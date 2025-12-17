//! MASP Client
//!
//! The client coordinates between:
//! - Local key/note storage
//! - Note commitment store (for membership proofs)
//! - Nullifier set (for double-spend prevention)
//! - Chain (for transaction submission)
//!
//! ## Identifier Scheme
//!
//! The client uses **commitment** as the primary identifier:
//! - commitment = H(note_plaintext)
//! - Client stores: (note, commitment, tx_sig)
//!
//! The backend may use a different identifier internally
//! (e.g., Light Protocol uses dataHash), but the client
//! only deals with commitments.

use crate::encryption::{EncryptedNote, NoteEncryption};
use crate::keys::{DiversifiedAddress, FullViewingKey, SpendingKey};
use crate::note::{compute_asset_id, Note};
use crate::nullifier::compute_nullifier;
use crate::proofs::MembershipWitness;
use crate::traits::{
    Chain, ChainError, Indexer, IndexerError, OutputCiphertext, ProofBytes, ShieldRequest,
    ShieldResult, StoreError, TransferRequest, TransferResult, UnshieldResult,
};
use crate::types::{Anchor, Commitment, Fr, Nullifier, TokenAddress};
use ark_ff::UniformRand;
use rand::rngs::OsRng;
use std::sync::Arc;
use thiserror::Error;

/// An owned note with its metadata
#[derive(Debug, Clone)]
pub struct OwnedNote {
    /// The note plaintext
    pub note: Note,

    /// Commitment = H(note) = identifier
    pub commitment: Commitment,

    /// Transaction that created this note
    pub tx_sig: String,

    /// Whether this note has been spent
    pub spent: bool,
}

/// Errors from client operations
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    #[error("Indexer error: {0}")]
    Indexer(#[from] IndexerError),

    #[error("Chain error: {0}")]
    Chain(#[from] ChainError),

    #[error("Note not found")]
    NoteNotFound,

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Note already spent")]
    AlreadySpent,

    #[error("Commitment not found on chain")]
    CommitmentNotFound,

    #[error("Proof error: {0}")]
    ProofError(#[from] crate::traits::ProofSystemError),
}

/// MASP client - manages keys, notes, and builds transactions
///
/// `I` and `C` are allowed to be dynamically sized (`dyn Indexer`, `dyn Chain`)
/// so tests (and eventually production) can swap backend implementations at
/// runtime via `Arc<dyn Indexer>` / `Arc<dyn Chain>`.
pub struct MaspClient<I: ?Sized, C: ?Sized>
where
    I: Indexer,
    C: Chain,
{
    /// User's spending key
    #[allow(dead_code)]
    spending_key: SpendingKey,

    /// Full viewing key
    fvk: FullViewingKey,

    /// Owned notes
    notes: Vec<OwnedNote>,

    /// Indexer (note commitment store + ciphertext scanning)
    indexer: Arc<I>,

    /// Chain (transaction submission)
    chain: Arc<C>,

    /// Spend prover backend (off-chain)
    prover: Arc<dyn crate::traits::SpendProver>,
}

impl<I: ?Sized, C: ?Sized> MaspClient<I, C>
where
    I: Indexer,
    C: Chain,
{
    /// Create a new client with the given spending key
    pub fn new(
        spending_key: SpendingKey,
        indexer: Arc<I>,
        chain: Arc<C>,
        prover: Arc<dyn crate::traits::SpendProver>,
    ) -> Self {
        let fvk = spending_key.to_full_viewing_key();
        Self {
            spending_key,
            fvk,
            notes: Vec::new(),
            indexer,
            chain,
            prover,
        }
    }

    /// Get the full viewing key
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Wait until the configured indexer has observed recent chain updates.
    ///
    /// This is primarily a **test/UX helper** to model real-world indexing latency.
    /// In production it may be a no-op (indexer is external).
    pub async fn wait_for_indexer_update(
        &self,
        tx_sig: Option<&str>,
    ) -> Result<(), crate::traits::IndexerError> {
        self.indexer.wait_for_update(tx_sig).await
    }

    /// Get a diversified address for receiving
    pub fn get_address(&self, diversifier_index: u64) -> Fr {
        self.fvk.diversified_address(diversifier_index).to_field()
    }

    /// Get balance for a specific asset
    pub fn balance(&self, asset_id: Fr) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.spent && n.note.asset_id == asset_id)
            .map(|n| n.note.amount)
            .sum()
    }

    /// Get all unspent notes for an asset
    pub fn unspent_notes(&self, asset_id: Fr) -> Vec<&OwnedNote> {
        self.notes
            .iter()
            .filter(|n| !n.spent && n.note.asset_id == asset_id)
            .collect()
    }

    /// Find note by commitment
    pub fn find_note(&self, commitment: Commitment) -> Option<&OwnedNote> {
        self.notes.iter().find(|n| n.commitment == commitment)
    }

    /// Add a note (after receiving or shielding)
    pub fn add_note(&mut self, note: Note, tx_sig: String) {
        let commitment = note.commitment();
        self.notes.push(OwnedNote {
            note,
            commitment,
            tx_sig,
            spent: false,
        });
    }

    /// Import note from OOB message
    ///
    /// Verifies the commitment exists on-chain before adding.
    pub async fn import_note(&mut self, note: Note, tx_sig: String) -> Result<(), ClientError> {
        let commitment = note.commitment();

        // Verify commitment exists
        if !self.indexer.exists(commitment).await? {
            return Err(ClientError::CommitmentNotFound);
        }

        self.add_note(note, tx_sig);
        Ok(())
    }

    /// Mark a note as spent
    pub fn mark_spent(&mut self, commitment: Commitment) {
        if let Some(note) = self.notes.iter_mut().find(|n| n.commitment == commitment) {
            note.spent = true;
        }
    }

    /// Prepare to spend a note: get witness and compute nullifier
    pub async fn prepare_spend(
        &self,
        commitment: Commitment,
    ) -> Result<(OwnedNote, MembershipWitness, Nullifier), ClientError> {
        let owned = self
            .notes
            .iter()
            .find(|n| n.commitment == commitment)
            .ok_or(ClientError::NoteNotFound)?
            .clone();

        if owned.spent {
            return Err(ClientError::AlreadySpent);
        }

        // Get membership witness
        let witness = self.indexer.get_witness(commitment).await?;

        // Compute nullifier
        let nk = self.fvk.nk_field();
        let nullifier = compute_nullifier(nk, owned.note.nullifier_nonce);

        Ok((owned, witness, nullifier))
    }

    /// Build a shield request (without ciphertext - add separately)
    pub fn build_shield(&self, token_address: &TokenAddress, amount: u64) -> (Note, ShieldRequest) {
        let asset_id = compute_asset_id(token_address);
        let recipient = self.get_address(0);

        let note = Note::new(&mut OsRng, asset_id, amount, recipient);
        let commitment = note.commitment();

        // Build shield proof (mock/real depending on configured prover backend).
        let public = crate::traits::ShieldPublicInputs {
            new_commitment: commitment,
            public_asset_id: asset_id,
            public_amount: amount,
        };
        let private = crate::traits::SpendPrivateInputs {
            note_asset_id: note.asset_id,
            note_amount: note.amount,
            note_recipient: note.recipient,
            note_nullifier_nonce: note.nullifier_nonce,
            note_randomness: note.note_randomness,
            nk: Fr::from(0u64),
            membership_witness: crate::proofs::MembershipWitness::merkle_path(
                vec![],
                vec![],
                Fr::from(0u64),
            ),
            output_notes: vec![],
        };
        let shield_proof = self
            .prover
            .prove(&crate::traits::ProofPublicInputs::Shield(public), &private)
            .expect("shield prover should succeed (scaffold)")
            .into_bytes();

        (
            note,
            ShieldRequest {
                token_address: *token_address,
                amount,
                commitment,
                shield_proof,
                // Ciphertext should be added by caller if needed for scanning
                ciphertext: None,
                ephemeral_key: None,
            },
        )
    }

    /// Build a transfer (shielded to shielded)
    pub async fn build_transfer(
        &self,
        spend_commitment: Commitment,
        recipient: Fr,
        amount: u64,
    ) -> Result<TransferData, ClientError> {
        let (owned, witness, nullifier) = self.prepare_spend(spend_commitment).await?;

        if owned.note.amount < amount {
            return Err(ClientError::InsufficientBalance {
                have: owned.note.amount,
                need: amount,
            });
        }

        // Create output note
        let output_nonce = Note::derive_nullifier_nonce(owned.commitment, 0);
        let output = Note::with_values(
            owned.note.asset_id,
            amount,
            recipient,
            output_nonce,
            Fr::rand(&mut OsRng),
        );

        // Create change note if needed
        let change = if owned.note.amount > amount {
            let change_nonce = Note::derive_nullifier_nonce(owned.commitment, 1);
            Some(Note::with_values(
                owned.note.asset_id,
                owned.note.amount - amount,
                self.get_address(0),
                change_nonce,
                Fr::rand(&mut OsRng),
            ))
        } else {
            None
        };

        Ok(TransferData {
            anchor: witness.root(),
            input_commitment: spend_commitment,
            membership_witness: witness,
            nullifier,
            spend_note: owned.note,
            output,
            change,
        })
    }

    /// Get current anchor from chain
    pub async fn current_anchor(&self) -> Result<Anchor, ClientError> {
        Ok(self.chain.get_current_anchor().await?)
    }

    // =========================================================================
    // High-Level User Operations
    // =========================================================================
    //
    // These are the primary methods for user flows. They handle:
    // - Note creation and encryption
    // - Chain submission
    // - Local state updates
    //
    // Use these for reference implementations and user-facing code.
    // The lower-level build_* methods are available for advanced use cases.

    /// Shield tokens into the pool
    ///
    /// Complete flow: create note → encrypt → submit to chain → update local state
    ///
    /// # Arguments
    /// * `encryption` - Encryption scheme (use `ChaChaPolyEncryption::new()`)
    /// * `token_address` - Token to deposit
    /// * `amount` - Amount to deposit
    ///
    /// # Returns
    /// The created note and transaction signature
    pub async fn shield<E: NoteEncryption>(
        &mut self,
        encryption: &E,
        token_address: &TokenAddress,
        amount: u64,
    ) -> Result<(Note, ShieldResult), ClientError> {
        // 1. Create note
        let (note, mut request) = self.build_shield(token_address, amount);

        // 2. Encrypt for self-scanning
        let addr = self.fvk.diversified_address(0);
        let encrypted = encryption.encrypt(&mut OsRng, &note, &addr);
        request.ciphertext = Some(encrypted.to_bytes());
        request.ephemeral_key = Some(encrypted.ephemeral_key);

        // 3. Submit to chain
        let result = self.chain.shield(request).await?;

        // 4. Update local state
        self.add_note(note.clone(), result.tx_sig.clone());

        Ok((note, result))
    }

    /// Transfer to another user
    ///
    /// Complete flow: build transfer → encrypt for recipient → submit → update state
    ///
    /// # Arguments
    /// * `encryption` - Encryption scheme
    /// * `recipient` - Recipient's diversified address
    /// * `amount` - Amount to send
    ///
    /// # Returns
    /// Transfer result with tx_sig (share this with recipient via OOB)
    pub async fn transfer_to<E: NoteEncryption>(
        &mut self,
        encryption: &E,
        recipient: &DiversifiedAddress,
        amount: u64,
        asset_id: Fr,
    ) -> Result<TransferResult, ClientError> {
        // 1. Find a note to spend
        let notes = self.unspent_notes(asset_id);
        let spend_note = notes.iter().find(|n| n.note.amount >= amount).ok_or(
            ClientError::InsufficientBalance {
                have: self.balance(asset_id),
                need: amount,
            },
        )?;
        let spend_commitment = spend_note.commitment;

        // 2. Build transfer
        let transfer_data = self
            .build_transfer(spend_commitment, recipient.to_field(), amount)
            .await?;

        // 3. Encrypt outputs for recipients
        use crate::traits::TransferOutput;

        let output_encrypted = encryption.encrypt(&mut OsRng, &transfer_data.output, recipient);
        let mut outputs = vec![TransferOutput::with_ciphertext(
            transfer_data.output.commitment(),
            output_encrypted.to_bytes(),
            output_encrypted.ephemeral_key,
        )];

        // Encrypt change for self
        if let Some(ref change_note) = transfer_data.change {
            let self_addr = self.fvk.diversified_address(0);
            let change_encrypted = encryption.encrypt(&mut OsRng, change_note, &self_addr);
            outputs.push(TransferOutput::with_ciphertext(
                change_note.commitment(),
                change_encrypted.to_bytes(),
                change_encrypted.ephemeral_key,
            ));
        }

        // 4. Submit to chain
        let (public, private) = transfer_data.spend_proof_inputs(self.fvk.nk_field());
        let spend_proof = self.prover.prove(
            &crate::traits::ProofPublicInputs::Transfer(public),
            &private,
        )?;

        let request = transfer_data.to_request_with_outputs(spend_proof, outputs);
        let result = self.chain.transfer(request).await?;

        // 5. Update local state
        self.mark_spent(spend_commitment);
        if let Some(change_note) = transfer_data.change {
            self.add_note(change_note, result.tx_sig.clone());
        }

        Ok(result)
    }

    /// Unshield (withdraw) tokens from the pool
    ///
    /// Complete flow: find note → build unshield → submit → update state
    ///
    /// # Arguments
    /// * `recipient` - Public address to receive tokens (32 bytes)
    /// * `amount` - Amount to withdraw
    /// * `token_address` - Token to withdraw
    ///
    /// # Returns
    /// Unshield result with tx_sig
    pub async fn unshield(
        &mut self,
        recipient: [u8; 32],
        amount: u64,
        token_address: TokenAddress,
    ) -> Result<UnshieldResult, ClientError> {
        use crate::traits::UnshieldRequest;

        let asset_id = compute_asset_id(&token_address);

        // 1. Find a note to spend
        let notes = self.unspent_notes(asset_id);
        let spend_note = notes.iter().find(|n| n.note.amount >= amount).ok_or(
            ClientError::InsufficientBalance {
                have: self.balance(asset_id),
                need: amount,
            },
        )?;
        let spend_commitment = spend_note.commitment;

        // 2. Prepare spend (get witness and nullifier)
        let (owned, witness, nullifier) = self.prepare_spend(spend_commitment).await?;

        // 3. Verify amount matches (unshield must be exact - no change in public withdrawal)
        if owned.note.amount != amount {
            return Err(ClientError::InsufficientBalance {
                have: owned.note.amount,
                need: amount,
            });
        }

        // 4. Prove unshield (real ZK when prover backend supports it)
        use ark_ff::PrimeField;
        let public = crate::traits::UnshieldPublicInputs {
            anchor: witness.root(),
            input_commitment: spend_commitment,
            nullifier,
            public_amount: amount,
            // Stage-0: interpret the 32-byte recipient as a field element mod p.
            // In production this must match the circuit/program recipient encoding decision.
            public_recipient: Fr::from_be_bytes_mod_order(&recipient),
            public_asset_id: asset_id,
        };
        let private = crate::traits::SpendPrivateInputs {
            note_asset_id: owned.note.asset_id,
            note_amount: owned.note.amount,
            note_recipient: owned.note.recipient,
            note_nullifier_nonce: owned.note.nullifier_nonce,
            note_randomness: owned.note.note_randomness,
            nk: self.fvk.nk_field(),
            membership_witness: witness.clone(),
            output_notes: vec![],
        };
        let spend_proof = self
            .prover
            .prove(
                &crate::traits::ProofPublicInputs::Unshield(public),
                &private,
            )?
            .into_bytes();

        // 5. Build unshield request
        let request = UnshieldRequest {
            anchor: witness.root(),
            input_commitment: spend_commitment,
            membership_witness: witness,
            nullifier,
            spend_proof,
            recipient,
            amount,
            token_address,
        };

        // 6. Submit to chain
        let result = self.chain.unshield(request).await?;

        // 7. Update local state
        self.mark_spent(spend_commitment);

        Ok(result)
    }

    /// Recover wallet from seed
    ///
    /// Scans all chain outputs, decrypts notes belonging to us,
    /// filters out already-spent notes.
    ///
    /// Call this after creating a new client from seed.
    pub async fn recover<E: NoteEncryption + ?Sized>(
        &mut self,
        encryption: &E,
    ) -> Result<SyncResult, ClientError> {
        self.sync_from_chain(encryption, 0).await
    }

    /// Receive payment via OOB notification
    ///
    /// When someone sends you a payment, they share the tx_sig via OOB.
    /// This method fetches and decrypts notes from that transaction.
    pub async fn receive_payment<E: NoteEncryption + ?Sized>(
        &mut self,
        encryption: &E,
        tx_sig: &str,
    ) -> Result<Vec<Note>, ClientError> {
        self.sync_from_tx(encryption, tx_sig, 0).await
    }

    // =========================================================================
    // Shielded Sync - Recovery Methods
    // =========================================================================

    /// Full shielded sync: scan all outputs and filter spent notes
    ///
    /// This is the complete wallet recovery flow:
    /// 1. Scan all outputs from indexer
    /// 2. Trial decrypt each with ivk to find received notes
    /// 3. Batch check nullifiers to filter already-spent notes
    ///
    /// # Arguments
    /// * `encryption` - The encryption scheme for trial decryption
    /// * `diversifier_index` - Which diversified address to check (usually 0)
    pub async fn sync_from_chain<E: NoteEncryption + ?Sized>(
        &mut self,
        encryption: &E,
        diversifier_index: u64,
    ) -> Result<SyncResult, ClientError> {
        let mut result = SyncResult::default();

        // 1. Scan all outputs from indexer
        let outputs = self.indexer.scan_outputs_since(None).await?;
        result.outputs_scanned = outputs.len();

        // 2. Trial decrypt each output to find our notes
        let mut found_notes = Vec::new();

        for output in &outputs {
            // Try to decrypt as recipient (ivk)
            if let Some(note) = self.try_decrypt_output(encryption, output, diversifier_index) {
                found_notes.push((note, output.commitment, output.tx_sig.clone()));
                result.received_found += 1;
            }
        }

        // 3. Batch check which notes are already spent
        if !found_notes.is_empty() {
            let nullifiers: Vec<Nullifier> = found_notes
                .iter()
                .map(|(note, _, _)| compute_nullifier(self.fvk.nk_field(), note.nullifier_nonce))
                .collect();

            let spent_flags = self.chain.batch_check_nullifiers(&nullifiers).await?;

            // 4. Add unspent notes to client
            for ((note, commitment, tx_sig), is_spent) in
                found_notes.into_iter().zip(spent_flags.iter())
            {
                if *is_spent {
                    result.already_spent += 1;
                } else {
                    self.notes.push(OwnedNote {
                        note,
                        commitment,
                        tx_sig,
                        spent: false,
                    });
                    result.notes_added += 1;
                }
            }
        }

        Ok(result)
    }

    /// Incremental sync: scan only new outputs since last sync
    pub async fn sync_incremental<E: NoteEncryption + ?Sized>(
        &mut self,
        encryption: &E,
        diversifier_index: u64,
        since_tx: Option<&str>,
    ) -> Result<SyncResult, ClientError> {
        let mut result = SyncResult::default();

        let outputs = self.indexer.scan_outputs_since(since_tx).await?;
        result.outputs_scanned = outputs.len();

        let mut found_notes = Vec::new();

        for output in &outputs {
            if let Some(note) = self.try_decrypt_output(encryption, output, diversifier_index) {
                found_notes.push((note, output.commitment, output.tx_sig.clone()));
                result.received_found += 1;
            }
        }

        // Batch check nullifiers
        if !found_notes.is_empty() {
            let nullifiers: Vec<_> = found_notes
                .iter()
                .map(|(note, _, _)| compute_nullifier(self.fvk.nk_field(), note.nullifier_nonce))
                .collect();

            let spent_flags = self.chain.batch_check_nullifiers(&nullifiers).await?;

            for ((note, commitment, tx_sig), is_spent) in
                found_notes.into_iter().zip(spent_flags.iter())
            {
                if !is_spent {
                    self.notes.push(OwnedNote {
                        note,
                        commitment,
                        tx_sig,
                        spent: false,
                    });
                    result.notes_added += 1;
                } else {
                    result.already_spent += 1;
                }
            }
        }

        Ok(result)
    }

    /// Try to decrypt an output ciphertext with our ivk
    fn try_decrypt_output<E: NoteEncryption + ?Sized>(
        &self,
        encryption: &E,
        output: &OutputCiphertext,
        diversifier_index: u64,
    ) -> Option<Note> {
        // Convert to our EncryptedNote format
        let encrypted = EncryptedNote::from_bytes(&output.ciphertext).ok()?;
        encryption
            .try_decrypt(&encrypted, &self.fvk, diversifier_index)
            .ok()
    }

    /// Scan for notes in a specific transaction (for OOB fast-path)
    ///
    /// This is the fast path when someone tells you "you were paid in tx X".
    /// Instead of scanning all outputs, just scan that transaction.
    pub async fn sync_from_tx<E: NoteEncryption + ?Sized>(
        &mut self,
        encryption: &E,
        tx_sig: &str,
        diversifier_index: u64,
    ) -> Result<Vec<Note>, ClientError> {
        let outputs = self.indexer.get_outputs_for_tx(tx_sig).await?;

        let mut found = Vec::new();
        for output in outputs {
            if let Some(note) = self.try_decrypt_output(encryption, &output, diversifier_index) {
                let commitment = note.commitment();
                found.push(note.clone());

                // Check if already owned
                if self.find_note(commitment).is_none() {
                    // Check if spent
                    let nullifier = compute_nullifier(self.fvk.nk_field(), note.nullifier_nonce);
                    let is_spent = self.chain.is_nullifier_spent(&nullifier).await?;

                    if !is_spent {
                        self.add_note(note, tx_sig.to_string());
                    }
                }
            }
        }

        Ok(found)
    }

    /// Update spent status for all notes by checking nullifiers
    pub async fn refresh_spent_status(&mut self) -> Result<usize, ClientError> {
        if self.notes.is_empty() {
            return Ok(0);
        }

        let nullifiers: Vec<_> = self
            .notes
            .iter()
            .map(|owned| compute_nullifier(self.fvk.nk_field(), owned.note.nullifier_nonce))
            .collect();

        let spent_flags = self.chain.batch_check_nullifiers(&nullifiers).await?;

        let mut newly_spent = 0;
        for (owned, is_spent) in self.notes.iter_mut().zip(spent_flags.iter()) {
            if *is_spent && !owned.spent {
                owned.spent = true;
                newly_spent += 1;
            }
        }

        Ok(newly_spent)
    }
}

/// Result of a sync operation
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Number of outputs scanned
    pub outputs_scanned: usize,
    /// Number of received notes found
    pub received_found: usize,
    /// Number of notes that were already spent
    pub already_spent: usize,
    /// Number of notes added to client
    pub notes_added: usize,
}

/// Data for a transfer transaction
#[derive(Debug)]
pub struct TransferData {
    pub anchor: Anchor,
    pub input_commitment: Commitment,
    pub membership_witness: MembershipWitness,
    pub nullifier: Nullifier,
    pub spend_note: Note,
    pub output: Note,
    pub change: Option<Note>,
}

impl TransferData {
    /// Build spend proof inputs for this transfer (reference implementation).
    ///
    /// Today we use a placeholder `tx_binding = 0`. When circuits are integrated,
    /// this should be replaced with a real transaction binding hash.
    pub fn spend_proof_inputs(
        &self,
        nk: Fr,
    ) -> (
        crate::traits::SpendPublicInputs,
        crate::traits::SpendPrivateInputs,
    ) {
        use crate::traits::{SpendPrivateInputs, SpendPublicInputs};

        let output_commitments = {
            let mut v = vec![self.output.commitment()];
            if let Some(change) = &self.change {
                v.push(change.commitment());
            }
            v
        };

        let public = SpendPublicInputs {
            anchor: self.anchor,
            input_commitment: self.input_commitment,
            nullifier: self.nullifier,
            output_commitments,
            tx_binding: Fr::from(0u64),
        };

        let note = &self.spend_note;
        let private = SpendPrivateInputs {
            note_asset_id: note.asset_id,
            note_amount: note.amount,
            note_recipient: note.recipient,
            note_nullifier_nonce: note.nullifier_nonce,
            note_randomness: note.note_randomness,
            nk,
            membership_witness: self.membership_witness.clone(),
            output_notes: {
                let mut v = vec![self.output.clone()];
                if let Some(change) = &self.change {
                    v.push(change.clone());
                }
                v
            },
        };

        (public, private)
    }

    /// Convert to transfer request for submission (without ciphertexts)
    ///
    /// For full ciphertext support, use `to_request_with_outputs()` instead.
    pub fn to_request(&self, spend_proof: ProofBytes) -> TransferRequest {
        use crate::traits::TransferOutput;

        let mut outputs = vec![TransferOutput::commitment_only(self.output.commitment())];

        if let Some(change) = &self.change {
            outputs.push(TransferOutput::commitment_only(change.commitment()));
        }

        TransferRequest {
            anchor: self.anchor,
            input_commitment: self.input_commitment,
            membership_witness: self.membership_witness.clone(),
            nullifier: self.nullifier,
            spend_proof: spend_proof.into_bytes(),
            outputs,
        }
    }

    /// Convert to transfer request with full output data (including ciphertexts)
    pub fn to_request_with_outputs(
        &self,
        spend_proof: ProofBytes,
        outputs: Vec<crate::traits::TransferOutput>,
    ) -> TransferRequest {
        TransferRequest {
            anchor: self.anchor,
            input_commitment: self.input_commitment,
            membership_witness: self.membership_witness.clone(),
            nullifier: self.nullifier,
            spend_proof: spend_proof.into_bytes(),
            outputs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockChain, MockNoteStore};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn setup() -> (
        MaspClient<MockNoteStore, MockChain>,
        Arc<MockNoteStore>,
        Arc<MockChain>,
    ) {
        let acc = Arc::new(MockNoteStore::new(8));
        let chain = Arc::new(MockChain::new(acc.clone(), 10));
        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let client = MaspClient::new(
            sk,
            acc.clone(),
            chain.clone(),
            Arc::new(crate::proofs::MockSpendProver),
        );
        (client, acc, chain)
    }

    #[tokio::test]
    async fn test_client_balance() {
        let (mut client, acc, _chain) = setup();

        let asset_id = Fr::from(1u64);
        let recipient = client.get_address(0);

        let mut rng = StdRng::seed_from_u64(12345);
        let note1 = Note::new(&mut rng, asset_id, 100, recipient);
        let cm1 = note1.commitment();
        acc.insert(cm1, "tx_1");
        client.add_note(note1, "tx_1".to_string());

        let note2 = Note::new(&mut rng, asset_id, 50, recipient);
        let cm2 = note2.commitment();
        acc.insert(cm2, "tx_2");
        client.add_note(note2, "tx_2".to_string());

        assert_eq!(client.balance(asset_id), 150);

        client.mark_spent(cm1);
        assert_eq!(client.balance(asset_id), 50);
    }

    #[tokio::test]
    async fn test_prepare_spend() {
        let (mut client, acc, _chain) = setup();

        let asset_id = Fr::from(1u64);
        let recipient = client.get_address(0);

        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, asset_id, 100, recipient);
        let cm = note.commitment();
        acc.insert(cm, "tx_1");
        client.add_note(note, "tx_1".to_string());

        let (owned, witness, nullifier) = client.prepare_spend(cm).await.unwrap();

        assert_eq!(owned.note.amount, 100);
        assert!(witness.verify_local(cm));
        assert_ne!(nullifier, Fr::from(0u64));
    }

    #[tokio::test]
    async fn test_build_transfer() {
        let (mut client, acc, _chain) = setup();

        let asset_id = Fr::from(1u64);
        let recipient = client.get_address(0);

        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, asset_id, 100, recipient);
        let cm = note.commitment();
        acc.insert(cm, "tx_1");
        client.add_note(note, "tx_1".to_string());

        let other_recipient = Fr::from(999u64);
        let transfer = client
            .build_transfer(cm, other_recipient, 60)
            .await
            .unwrap();

        assert_eq!(transfer.output.amount, 60);
        assert_eq!(transfer.output.recipient, other_recipient);
        assert!(transfer.change.is_some());
        assert_eq!(transfer.change.unwrap().amount, 40);
    }

    #[tokio::test]
    async fn test_import_note_oob() {
        let (mut client, _acc, chain) = setup();

        let asset_id = Fr::from(1u64);
        let recipient = client.get_address(0);

        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, asset_id, 100, recipient);
        let cm = note.commitment();

        // Shield first
        let shield_result = chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
                shield_proof: b"true".to_vec(),
                ciphertext: None,
                ephemeral_key: None,
            })
            .await
            .unwrap();

        // OOB import
        let result = client.import_note(note.clone(), shield_result.tx_sig).await;
        assert!(result.is_ok());

        assert!(client.find_note(cm).is_some());
        assert_eq!(client.balance(asset_id), 100);
    }

    #[tokio::test]
    async fn test_import_nonexistent_note_fails() {
        let (mut client, _acc, _chain) = setup();

        let asset_id = Fr::from(1u64);
        let recipient = client.get_address(0);

        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, asset_id, 100, recipient);

        let result = client.import_note(note, "fake_tx".to_string()).await;
        assert!(matches!(result, Err(ClientError::CommitmentNotFound)));
    }
}

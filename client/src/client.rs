//! MASP Client
//!
//! The client coordinates between:
//! - Local key/note storage
//! - Commitment accumulator (for membership proofs)
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

use crate::keys::{FullViewingKey, SpendingKey};
use crate::note::{compute_asset_id, Note};
use crate::nullifier::compute_nullifier;
use crate::proofs::MembershipWitness;
use crate::traits::{
    Chain, ChainError, Indexer, IndexerError, ProofBytes, ShieldRequest, StoreError,
    TransferRequest,
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
}

/// MASP client - manages keys, notes, and builds transactions
pub struct MaspClient<I, C>
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
}

impl<I, C> MaspClient<I, C>
where
    I: Indexer,
    C: Chain,
{
    /// Create a new client with the given spending key
    pub fn new(spending_key: SpendingKey, indexer: Arc<I>, chain: Arc<C>) -> Self {
        let fvk = spending_key.to_full_viewing_key();
        Self {
            spending_key,
            fvk,
            notes: Vec::new(),
            indexer,
            chain,
        }
    }

    /// Get the full viewing key
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
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

    /// Build a shield request
    pub fn build_shield(
        &self,
        token_address: &TokenAddress,
        amount: u64,
    ) -> (Note, ShieldRequest) {
        let asset_id = compute_asset_id(token_address);
        let recipient = self.get_address(0);

        let note = Note::new(&mut OsRng, asset_id, amount, recipient);
        let commitment = note.commitment();

        (
            note,
            ShieldRequest {
                token_address: *token_address,
                amount,
                commitment,
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
    /// Convert to transfer request for submission
    pub fn to_request(&self, spend_proof: ProofBytes) -> TransferRequest {
        let mut output_commitments = vec![self.output.commitment()];
        let ciphertexts = vec![]; // TODO: encrypt notes

        if let Some(change) = &self.change {
            output_commitments.push(change.commitment());
        }

        TransferRequest {
            anchor: self.anchor,
            input_commitment: self.input_commitment,
            membership_witness: self.membership_witness.clone(),
            nullifier: self.nullifier,
            spend_proof: spend_proof.into_bytes(),
            output_commitments,
            ciphertexts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockAccumulator, MockChain};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn setup() -> (
        MaspClient<MockAccumulator, MockChain>,
        Arc<MockAccumulator>,
        Arc<MockChain>,
    ) {
        let acc = Arc::new(MockAccumulator::new(8));
        let chain = Arc::new(MockChain::new(acc.clone(), 10));
        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let client = MaspClient::new(sk, acc.clone(), chain.clone());
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
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
            })
            .await
            .unwrap();

        // OOB import
        let result = client
            .import_note(note.clone(), "mock_tx_1".to_string())
            .await;
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

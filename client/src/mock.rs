//! Mock implementations for testing
//!
//! These mocks use simple in-memory data structures:
//! - Merkle tree for note commitment store
//! - HashSet for nullifier set
//!
//! ## Architecture
//!
//! ```text
//! Client ─────────reads─────────▶ Indexer (MockNoteStore)
//!    │                               ▲
//!    │                               │ observes
//!    └────submits────▶ Chain ────────┘
//!                    (MockChain)
//! ```
//!
//! The client READS from the indexer but only WRITES through the chain.
//! When MockChain processes transactions, it updates MockNoteStore (the indexer).
//!
//! Identifier scheme: commitment directly (no extra hash layer)

use crate::backends::config::ProofVerificationMode;
use crate::hash::merkle_hash;
use crate::proofs::MembershipWitness;
use crate::proofs::MockProofVerifier;
use crate::traits::{
    Chain, ChainError, Indexer, IndexerError, InsertCommitmentResult, NoteCommitmentStore,
    NullifierError, NullifierSet, OutputCiphertext, ProofBytes, ProofVerifier, ShieldRequest,
    ShieldResult, SpendPublicInputs, StoreError, TransferRequest, TransferResult, UnshieldRequest,
    UnshieldResult,
};
use crate::types::{Anchor, Commitment, Fr, Nullifier};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

// ============================================================================
// Ciphertext Data (passed to chain operations)
// ============================================================================

/// Ciphertext data to be stored with an output commitment
///
/// This is what the client provides when submitting a transaction.
/// The chain stores it, and the indexer can read it for scanning.
#[derive(Debug, Clone)]
pub struct OutputCiphertextData {
    /// Encrypted note plaintext (C_enc)
    pub c_enc: Vec<u8>,
    /// Ephemeral public key (64 bytes: x || y)
    pub ephemeral_key: [u8; 64],
}

// ============================================================================
// Mock Note Store (Merkle Tree)
// ============================================================================

/// Mock note commitment store using in-memory Merkle tree
///
/// Identifier scheme: commitment directly (no hash layer)
pub struct MockNoteStore {
    inner: Arc<RwLock<MockNoteStoreInner>>,
}

struct MockNoteStoreInner {
    depth: usize,
    nodes: HashMap<(usize, u64), Fr>,
    commitments: HashMap<Commitment, u64>, // commitment -> leaf_index
    leaf_count: u64,
    empty_nodes: Vec<Fr>,
    ciphertexts: Vec<OutputCiphertext>,
    tx_log: HashMap<String, Vec<Commitment>>,
}

impl MockNoteStore {
    pub fn new(depth: usize) -> Self {
        let mut empty_nodes = vec![Fr::from(0u64)];
        for _ in 1..=depth {
            let prev = *empty_nodes.last().unwrap();
            empty_nodes.push(merkle_hash(prev, prev));
        }

        Self {
            inner: Arc::new(RwLock::new(MockNoteStoreInner {
                depth,
                nodes: HashMap::new(),
                commitments: HashMap::new(),
                leaf_count: 0,
                empty_nodes,
                ciphertexts: Vec::new(),
                tx_log: HashMap::new(),
            })),
        }
    }

    /// Insert a commitment
    pub fn insert(&self, commitment: Commitment, tx_sig: &str) -> u64 {
        let mut inner = self.inner.write().unwrap();
        let leaf_index = inner.leaf_count;

        // Insert into merkle tree
        inner.nodes.insert((0, leaf_index), commitment);

        // Update path to root
        let mut idx = leaf_index;
        for level in 0..inner.depth {
            let parent_idx = idx / 2;
            let left_idx = parent_idx * 2;
            let right_idx = parent_idx * 2 + 1;

            let left = inner.get_node(level, left_idx);
            let right = inner.get_node(level, right_idx);
            inner
                .nodes
                .insert((level + 1, parent_idx), merkle_hash(left, right));

            idx = parent_idx;
        }

        // Index by commitment (our identifier scheme)
        inner.commitments.insert(commitment, leaf_index);

        // Log transaction
        inner
            .tx_log
            .entry(tx_sig.to_string())
            .or_default()
            .push(commitment);

        inner.leaf_count += 1;
        leaf_index
    }

    /// Insert a commitment with optional ciphertext data
    ///
    /// This is the ONLY way to insert - called by MockChain operations.
    /// Clients should NOT call this directly; they submit to the chain.
    ///
    /// Stores data in two places:
    /// 1. Merkle tree + indexes - for membership proofs
    /// 2. Ciphertexts vector - for scanning/trial decryption (indexer reads this)
    pub(crate) fn insert_output(
        &self,
        commitment: Commitment,
        tx_sig: &str,
        ciphertext: Option<OutputCiphertextData>,
    ) -> u64 {
        // Insert into Merkle tree and indexes
        let leaf_index = self.insert(commitment, tx_sig);

        // Store ciphertext data for scanning (if provided)
        if let Some(ct_data) = ciphertext {
            let mut inner = self.inner.write().unwrap();
            inner.ciphertexts.push(OutputCiphertext {
                commitment,
                ciphertext: ct_data.c_enc,
                ephemeral_key: ct_data.ephemeral_key,
                tx_sig: tx_sig.to_string(),
            });
        }

        leaf_index
    }

    /// Get current root
    pub fn current_root(&self) -> Anchor {
        let inner = self.inner.read().unwrap();
        inner.get_node(inner.depth, 0)
    }

    /// Get leaf index for commitment
    pub fn get_leaf_index(&self, commitment: Commitment) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        inner.commitments.get(&commitment).copied()
    }
}

impl MockNoteStoreInner {
    fn get_node(&self, level: usize, index: u64) -> Fr {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.empty_nodes[level])
    }

    fn get_merkle_path(&self, leaf_index: u64) -> (Vec<Fr>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);

        let mut idx = leaf_index;
        for level in 0..self.depth {
            let is_right = (idx % 2) == 1;
            path_indices.push(is_right);

            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(self.get_node(level, sibling_idx));

            idx /= 2;
        }

        (siblings, path_indices)
    }
}

#[async_trait]
impl NoteCommitmentStore for MockNoteStore {
    async fn root(&self) -> Result<Anchor, StoreError> {
        Ok(self.current_root())
    }

    async fn exists(&self, commitment: Commitment) -> Result<bool, StoreError> {
        let inner = self.inner.read().unwrap();
        Ok(inner.commitments.contains_key(&commitment))
    }

    async fn get_witness(&self, commitment: Commitment) -> Result<MembershipWitness, StoreError> {
        let inner = self.inner.read().unwrap();

        let leaf_index = inner
            .commitments
            .get(&commitment)
            .ok_or(StoreError::NotFound)?;

        let (siblings, path_indices) = inner.get_merkle_path(*leaf_index);
        let root = inner.get_node(inner.depth, 0);

        Ok(MembershipWitness::merkle_path(siblings, path_indices, root))
    }
}

#[async_trait]
impl Indexer for MockNoteStore {
    async fn scan_outputs_since(
        &self,
        since_tx: Option<&str>,
    ) -> Result<Vec<OutputCiphertext>, IndexerError> {
        let inner = self.inner.read().unwrap();

        let outputs = if let Some(tx) = since_tx {
            let mut found = false;
            inner
                .ciphertexts
                .iter()
                .filter(|c| {
                    if found {
                        true
                    } else if c.tx_sig == tx {
                        found = true;
                        false
                    } else {
                        false
                    }
                })
                .cloned()
                .collect()
        } else {
            inner.ciphertexts.clone()
        };

        Ok(outputs)
    }

    async fn get_commitments_for_tx(&self, tx_sig: &str) -> Result<Vec<Commitment>, IndexerError> {
        let inner = self.inner.read().unwrap();

        inner
            .tx_log
            .get(tx_sig)
            .cloned()
            .ok_or(IndexerError::NotFound)
    }
}

// ============================================================================
// Mock Nullifier Set
// ============================================================================

/// Mock nullifier set using HashSet
pub struct MockNullifierSet {
    nullifiers: Arc<RwLock<HashSet<Nullifier>>>,
}

impl MockNullifierSet {
    pub fn new() -> Self {
        Self {
            nullifiers: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Insert a nullifier (returns error if exists)
    pub fn insert(&self, nullifier: Nullifier) -> Result<(), NullifierError> {
        let mut set = self.nullifiers.write().unwrap();
        if set.contains(&nullifier) {
            Err(NullifierError::AlreadySpent)
        } else {
            set.insert(nullifier);
            Ok(())
        }
    }
}

impl Default for MockNullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NullifierSet for MockNullifierSet {
    async fn is_spent(&self, nullifier: &Nullifier) -> Result<bool, NullifierError> {
        let set = self.nullifiers.read().unwrap();
        Ok(set.contains(nullifier))
    }
}

// ============================================================================
// Mock Chain
// ============================================================================

/// Mock chain combining note store and nullifier set
pub struct MockChain {
    note_store: Arc<MockNoteStore>,
    nullifier_set: MockNullifierSet,
    anchor_history: Arc<RwLock<Vec<Anchor>>>,
    max_anchors: usize,
    tx_counter: Arc<RwLock<u64>>,
    verifier: Arc<dyn ProofVerifier>,
    verify_mode: ProofVerificationMode,
}

/// Configuration for how `MockChain` verifies spend proofs.
///
/// Even in a mock chain, proof verification is conceptually always present.
/// We default to:
/// - `MockProofVerifier` (accepts everything)
/// - `Local` verification mode
pub struct MockChainOptions {
    pub verifier: Arc<dyn ProofVerifier>,
    pub verify_mode: ProofVerificationMode,
}

impl Default for MockChainOptions {
    fn default() -> Self {
        Self {
            verifier: Arc::new(MockProofVerifier),
            verify_mode: ProofVerificationMode::Local,
        }
    }
}

impl MockChain {
    pub fn new(note_store: Arc<MockNoteStore>, max_anchors: usize) -> Self {
        Self::new_with_options(note_store, max_anchors, MockChainOptions::default())
    }

    pub fn new_with_options(
        note_store: Arc<MockNoteStore>,
        max_anchors: usize,
        options: MockChainOptions,
    ) -> Self {
        let initial_root = note_store.current_root();
        Self {
            note_store,
            nullifier_set: MockNullifierSet::new(),
            anchor_history: Arc::new(RwLock::new(vec![initial_root])),
            max_anchors,
            tx_counter: Arc::new(RwLock::new(0)),
            verifier: options.verifier,
            verify_mode: options.verify_mode,
        }
    }

    /// Get the note store (for tests)
    pub fn note_store(&self) -> &MockNoteStore {
        &self.note_store
    }

    fn next_tx_sig(&self) -> String {
        let mut counter = self.tx_counter.write().unwrap();
        *counter += 1;
        format!("mock_tx_{}", *counter)
    }

    fn update_anchor_history(&self) {
        let root = self.note_store.current_root();
        let mut history = self.anchor_history.write().unwrap();

        if history.last() != Some(&root) {
            history.push(root);
            if history.len() > self.max_anchors {
                history.remove(0);
            }
        }
    }
}

#[async_trait]
impl NullifierSet for MockChain {
    async fn is_spent(&self, nullifier: &Nullifier) -> Result<bool, NullifierError> {
        self.nullifier_set.is_spent(nullifier).await
    }
}

#[async_trait]
impl Chain for MockChain {
    // ===== Low-level operations =====

    async fn insert_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<InsertCommitmentResult, ChainError> {
        let tx_sig = self.next_tx_sig();
        self.note_store.insert(commitment, &tx_sig);
        self.update_anchor_history();

        Ok(InsertCommitmentResult { tx_sig, commitment })
    }

    async fn insert_nullifier(&self, nullifier: Nullifier) -> Result<String, ChainError> {
        self.nullifier_set
            .insert(nullifier)
            .map_err(|_| ChainError::DoubleSpend)?;

        Ok(self.next_tx_sig())
    }

    async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
        Ok(self.note_store.current_root())
    }

    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError> {
        let history = self.anchor_history.read().unwrap();
        let current = self.note_store.current_root();
        Ok(*anchor == current || history.contains(anchor))
    }

    async fn is_nullifier_spent(&self, nullifier: &Nullifier) -> Result<bool, ChainError> {
        self.nullifier_set
            .is_spent(nullifier)
            .await
            .map_err(|e| ChainError::ConnectionError(e.to_string()))
    }

    // ===== High-level operations =====
    // Note: shield() uses default implementation (just calls insert_commitment)

    /// Shield: deposit tokens + insert commitment
    ///
    /// Chain stores the commitment and ciphertext (indexer can read it).
    async fn shield(&self, request: ShieldRequest) -> Result<ShieldResult, ChainError> {
        let tx_sig = self.next_tx_sig();

        // Build ciphertext data if provided
        let ct_data = match (&request.ciphertext, &request.ephemeral_key) {
            (Some(ct), Some(epk)) => Some(OutputCiphertextData {
                c_enc: ct.clone(),
                ephemeral_key: *epk,
            }),
            _ => None,
        };

        // MOCK ONLY: we write directly into `MockNoteStore` here so tests can scan/witness
        // immediately without running a real indexer.
        //
        // PRODUCTION: the chain does NOT "update the indexer". Ciphertexts/commitments live
        // in ledger space, and an external indexer (Helius/Light-backed) observes the chain
        // and builds its own DB / witness service asynchronously.
        self.note_store
            .insert_output(request.commitment, &tx_sig, ct_data);
        self.update_anchor_history();

        Ok(ShieldResult {
            tx_sig,
            commitment: request.commitment,
        })
    }

    async fn transfer(&self, request: TransferRequest) -> Result<TransferResult, ChainError> {
        // Validate anchor
        if !self.is_valid_anchor(&request.anchor).await? {
            return Err(ChainError::InvalidAnchor);
        }

        // Verify input commitment exists
        if !self
            .note_store
            .exists(request.input_commitment)
            .await
            .unwrap_or(false)
        {
            return Err(ChainError::InvalidProof);
        }

        // Verify membership witness locally (for mock)
        if !request
            .membership_witness
            .verify_local(request.input_commitment)
        {
            return Err(ChainError::InvalidProof);
        }

        // Verify spend proof (scaffold: verifier may be mock or real local verifier)
        let public_inputs = SpendPublicInputs {
            anchor: request.anchor,
            nullifier: request.nullifier,
            output_commitments: request.output_commitments(),
            tx_binding: Fr::from(0u64),
        };
        let proof = ProofBytes::new(request.spend_proof.clone());
        let ok = match self.verify_mode {
            crate::backends::config::ProofVerificationMode::Local => self
                .verifier
                .verify_local(&public_inputs, &proof)
                .await
                .map_err(|e| ChainError::TransactionFailed(e.to_string()))?,
            crate::backends::config::ProofVerificationMode::OnChain => self
                .verifier
                .verify_on_chain(&public_inputs, &proof)
                .await
                .map_err(|e| ChainError::TransactionFailed(e.to_string()))?,
        };
        if !ok {
            return Err(ChainError::InvalidProof);
        }

        // Insert nullifier (fails if double-spend)
        self.insert_nullifier(request.nullifier).await?;

        // Insert output commitments with ciphertexts (all in same "transaction")
        let tx_sig = self.next_tx_sig();
        for output in &request.outputs {
            let ct_data = match (&output.ciphertext, &output.ephemeral_key) {
                (Some(ct), Some(epk)) => Some(OutputCiphertextData {
                    c_enc: ct.clone(),
                    ephemeral_key: *epk,
                }),
                _ => None,
            };

            // MOCK ONLY: direct write into the "indexer" store; see note in `shield()`.
            self.note_store
                .insert_output(output.commitment, &tx_sig, ct_data);
        }
        self.update_anchor_history();

        Ok(TransferResult {
            tx_sig,
            output_commitments: request.output_commitments(),
        })
    }

    /// Batch check multiple nullifiers at once (efficient for shielded sync)
    async fn batch_check_nullifiers(
        &self,
        nullifiers: &[Nullifier],
    ) -> Result<Vec<bool>, ChainError> {
        // For mock, we can check all at once since everything is in memory
        let set = self.nullifier_set.nullifiers.read().unwrap();
        Ok(nullifiers.iter().map(|nf| set.contains(nf)).collect())
    }

    async fn unshield(&self, request: UnshieldRequest) -> Result<UnshieldResult, ChainError> {
        // Validate anchor
        if !self.is_valid_anchor(&request.anchor).await? {
            return Err(ChainError::InvalidAnchor);
        }

        // Verify input commitment exists
        if !self
            .note_store
            .exists(request.input_commitment)
            .await
            .unwrap_or(false)
        {
            return Err(ChainError::InvalidProof);
        }

        // Verify membership witness
        if !request
            .membership_witness
            .verify_local(request.input_commitment)
        {
            return Err(ChainError::InvalidProof);
        }

        // Verify spend proof (scaffold)
        let public_inputs = SpendPublicInputs {
            anchor: request.anchor,
            nullifier: request.nullifier,
            output_commitments: vec![],
            tx_binding: Fr::from(0u64),
        };
        let proof = ProofBytes::new(request.spend_proof.clone());
        let ok = match self.verify_mode {
            crate::backends::config::ProofVerificationMode::Local => self
                .verifier
                .verify_local(&public_inputs, &proof)
                .await
                .map_err(|e| ChainError::TransactionFailed(e.to_string()))?,
            crate::backends::config::ProofVerificationMode::OnChain => self
                .verifier
                .verify_on_chain(&public_inputs, &proof)
                .await
                .map_err(|e| ChainError::TransactionFailed(e.to_string()))?,
        };
        if !ok {
            return Err(ChainError::InvalidProof);
        }

        // Insert nullifier (fails if double-spend)
        let tx_sig = self.insert_nullifier(request.nullifier).await?;

        // In production: transfer tokens to recipient

        Ok(UnshieldResult { tx_sig })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ShieldRequest;

    #[tokio::test]
    async fn test_note_store_insert_and_witness() {
        let acc = MockNoteStore::new(4);

        let cm = Fr::from(42u64);
        acc.insert(cm, "tx_1");

        assert!(acc.exists(cm).await.unwrap());

        let witness = acc.get_witness(cm).await.unwrap();
        assert!(witness.verify_local(cm));
    }

    #[tokio::test]
    async fn test_store_not_found() {
        let acc = MockNoteStore::new(4);

        let cm = Fr::from(42u64);
        let result = acc.get_witness(cm).await;
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn test_nullifier_set() {
        let set = MockNullifierSet::new();
        let nf = Fr::from(123u64);

        assert!(!set.is_spent(&nf).await.unwrap());

        set.insert(nf).unwrap();
        assert!(set.is_spent(&nf).await.unwrap());

        // Double insert fails
        let result = set.insert(nf);
        assert!(matches!(result, Err(NullifierError::AlreadySpent)));
    }

    #[tokio::test]
    async fn test_chain_shield() {
        let acc = Arc::new(MockNoteStore::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        let cm = Fr::from(42u64);
        let result = chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
                ciphertext: None,
                ephemeral_key: None,
            })
            .await
            .unwrap();

        assert_eq!(result.commitment, cm);
        assert!(acc.exists(cm).await.unwrap());
    }

    #[tokio::test]
    async fn test_chain_transfer() {
        let acc = Arc::new(MockNoteStore::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        // Shield first
        let cm1 = Fr::from(42u64);
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm1,
                ciphertext: None,
                ephemeral_key: None,
            })
            .await
            .unwrap();

        // Get witness
        let witness = acc.get_witness(cm1).await.unwrap();

        // Transfer
        let nf = Fr::from(12345u64);
        let cm2 = Fr::from(100u64);

        use crate::traits::TransferOutput;

        let result = chain
            .transfer(TransferRequest {
                anchor: chain.get_current_anchor().await.unwrap(),
                input_commitment: cm1,
                membership_witness: witness,
                nullifier: nf,
                spend_proof: vec![],
                outputs: vec![TransferOutput::commitment_only(cm2)],
            })
            .await
            .unwrap();

        assert_eq!(result.output_commitments, vec![cm2]);
        assert!(chain.is_nullifier_spent(&nf).await.unwrap());
    }

    #[tokio::test]
    async fn test_double_spend_prevented() {
        use crate::traits::TransferOutput;

        let acc = Arc::new(MockNoteStore::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        // Shield
        let cm = Fr::from(42u64);
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
                ciphertext: None,
                ephemeral_key: None,
            })
            .await
            .unwrap();

        let witness = acc.get_witness(cm).await.unwrap();
        let nf = Fr::from(12345u64);

        // First transfer succeeds
        chain
            .transfer(TransferRequest {
                anchor: chain.get_current_anchor().await.unwrap(),
                input_commitment: cm,
                membership_witness: witness.clone(),
                nullifier: nf,
                spend_proof: vec![],
                outputs: vec![TransferOutput::commitment_only(Fr::from(100u64))],
            })
            .await
            .unwrap();

        // Second transfer with same nullifier fails
        let result = chain
            .transfer(TransferRequest {
                anchor: chain.get_current_anchor().await.unwrap(),
                input_commitment: cm,
                membership_witness: witness,
                nullifier: nf,
                spend_proof: vec![],
                outputs: vec![TransferOutput::commitment_only(Fr::from(200u64))],
            })
            .await;

        assert!(matches!(result, Err(ChainError::DoubleSpend)));
    }

    #[tokio::test]
    async fn test_indexer_scan() {
        let acc = Arc::new(MockNoteStore::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        let cm1 = Fr::from(1u64);
        let cm2 = Fr::from(2u64);

        // Use chain to insert (proper flow - chain updates indexer)
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm1,
                ciphertext: Some(vec![1, 2, 3]),
                ephemeral_key: Some([0u8; 64]),
            })
            .await
            .unwrap();

        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm2,
                ciphertext: Some(vec![4, 5, 6]),
                ephemeral_key: Some([0u8; 64]),
            })
            .await
            .unwrap();

        // Scan all
        let outputs = acc.scan_outputs_since(None).await.unwrap();
        assert_eq!(outputs.len(), 2);

        // Get the first tx_sig
        let first_tx = outputs[0].tx_sig.clone();

        // Scan since first tx
        let outputs = acc.scan_outputs_since(Some(&first_tx)).await.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].commitment, cm2);
    }

    #[tokio::test]
    async fn test_indexer_get_commitments_for_tx() {
        use crate::traits::TransferOutput;

        let acc = Arc::new(MockNoteStore::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        let cm1 = Fr::from(1u64);

        // Shield first note
        let shield_result = chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm1,
                ciphertext: None,
                ephemeral_key: None,
            })
            .await
            .unwrap();

        let witness = acc.get_witness(cm1).await.unwrap();
        let nf = Fr::from(999u64);
        let cm2 = Fr::from(2u64);
        let cm3 = Fr::from(3u64);

        // Transfer creates two outputs in same tx
        let transfer_result = chain
            .transfer(TransferRequest {
                anchor: chain.get_current_anchor().await.unwrap(),
                input_commitment: cm1,
                membership_witness: witness,
                nullifier: nf,
                spend_proof: vec![],
                outputs: vec![
                    TransferOutput::commitment_only(cm2),
                    TransferOutput::commitment_only(cm3),
                ],
            })
            .await
            .unwrap();

        // Get commitments for the transfer tx
        let cms = acc
            .get_commitments_for_tx(&transfer_result.tx_sig)
            .await
            .unwrap();
        assert_eq!(cms.len(), 2);
        assert!(cms.contains(&cm2));
        assert!(cms.contains(&cm3));

        // Shield tx should have only one commitment
        let cms = acc
            .get_commitments_for_tx(&shield_result.tx_sig)
            .await
            .unwrap();
        assert_eq!(cms, vec![cm1]);
    }
}

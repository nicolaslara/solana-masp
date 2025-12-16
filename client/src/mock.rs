//! Mock implementations for testing
//!
//! These mocks use simple in-memory data structures:
//! - Merkle tree for commitment accumulator
//! - HashSet for nullifier set
//!
//! Identifier scheme: commitment directly (no extra hash layer)

use crate::hash::merkle_hash;
use crate::proofs::MembershipWitness;
use crate::traits::{
    Chain, ChainError, Indexer, IndexerError, InsertCommitmentResult, NoteCommitmentStore,
    NullifierError, NullifierSet, OutputCiphertext, StoreError, TransferRequest, TransferResult,
    UnshieldRequest, UnshieldResult,
};
use crate::types::{Anchor, Commitment, Fr, Nullifier};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

// ============================================================================
// Mock Accumulator (Merkle Tree)
// ============================================================================

/// Mock commitment accumulator using in-memory Merkle tree
///
/// Identifier scheme: commitment directly (no hash layer)
pub struct MockAccumulator {
    inner: Arc<RwLock<MockAccumulatorInner>>,
}

struct MockAccumulatorInner {
    depth: usize,
    nodes: HashMap<(usize, u64), Fr>,
    commitments: HashMap<Commitment, u64>, // commitment -> leaf_index
    leaf_count: u64,
    empty_nodes: Vec<Fr>,
    ciphertexts: Vec<OutputCiphertext>,
    tx_log: HashMap<String, Vec<Commitment>>,
}

impl MockAccumulator {
    pub fn new(depth: usize) -> Self {
        let mut empty_nodes = vec![Fr::from(0u64)];
        for _ in 1..=depth {
            let prev = *empty_nodes.last().unwrap();
            empty_nodes.push(merkle_hash(prev, prev));
        }

        Self {
            inner: Arc::new(RwLock::new(MockAccumulatorInner {
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

    /// Insert with ciphertext
    pub fn insert_with_ciphertext(
        &self,
        commitment: Commitment,
        tx_sig: &str,
        ciphertext: Vec<u8>,
        ephemeral_key: [u8; 32],
    ) -> u64 {
        let leaf_index = self.insert(commitment, tx_sig);

        let mut inner = self.inner.write().unwrap();
        inner.ciphertexts.push(OutputCiphertext {
            commitment,
            ciphertext,
            ephemeral_key,
            tx_sig: tx_sig.to_string(),
        });

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

impl MockAccumulatorInner {
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
impl NoteCommitmentStore for MockAccumulator {
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
impl Indexer for MockAccumulator {
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

/// Mock chain combining accumulator and nullifier set
pub struct MockChain {
    accumulator: Arc<MockAccumulator>,
    nullifier_set: MockNullifierSet,
    anchor_history: Arc<RwLock<Vec<Anchor>>>,
    max_anchors: usize,
    tx_counter: Arc<RwLock<u64>>,
}

impl MockChain {
    pub fn new(accumulator: Arc<MockAccumulator>, max_anchors: usize) -> Self {
        let initial_root = accumulator.current_root();
        Self {
            accumulator,
            nullifier_set: MockNullifierSet::new(),
            anchor_history: Arc::new(RwLock::new(vec![initial_root])),
            max_anchors,
            tx_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the accumulator (for tests)
    pub fn accumulator(&self) -> &MockAccumulator {
        &self.accumulator
    }

    fn next_tx_sig(&self) -> String {
        let mut counter = self.tx_counter.write().unwrap();
        *counter += 1;
        format!("mock_tx_{}", *counter)
    }

    fn update_anchor_history(&self) {
        let root = self.accumulator.current_root();
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
        self.accumulator.insert(commitment, &tx_sig);
        self.update_anchor_history();

        Ok(InsertCommitmentResult {
            tx_sig,
            commitment,
        })
    }

    async fn insert_nullifier(&self, nullifier: Nullifier) -> Result<String, ChainError> {
        self.nullifier_set
            .insert(nullifier)
            .map_err(|_| ChainError::DoubleSpend)?;

        Ok(self.next_tx_sig())
    }

    async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
        Ok(self.accumulator.current_root())
    }

    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError> {
        let history = self.anchor_history.read().unwrap();
        let current = self.accumulator.current_root();
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

    async fn transfer(&self, request: TransferRequest) -> Result<TransferResult, ChainError> {
        // Validate anchor
        if !self.is_valid_anchor(&request.anchor).await? {
            return Err(ChainError::InvalidAnchor);
        }

        // Verify input commitment exists
        if !self
            .accumulator
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

        // Insert nullifier (fails if double-spend)
        self.insert_nullifier(request.nullifier).await?;

        // Insert output commitments
        let mut output_tx_sigs = Vec::new();
        for (i, cm) in request.output_commitments.iter().enumerate() {
            let result = if let Some(ct) = request.ciphertexts.get(i) {
                let tx_sig = self.next_tx_sig();
                self.accumulator
                    .insert_with_ciphertext(*cm, &tx_sig, ct.clone(), [0u8; 32]);
                self.update_anchor_history();
                tx_sig
            } else {
                self.insert_commitment(*cm).await?.tx_sig
            };
            output_tx_sigs.push(result);
        }

        Ok(TransferResult {
            tx_sig: output_tx_sigs.first().cloned().unwrap_or_default(),
            output_commitments: request.output_commitments,
        })
    }

    async fn unshield(&self, request: UnshieldRequest) -> Result<UnshieldResult, ChainError> {
        // Validate anchor
        if !self.is_valid_anchor(&request.anchor).await? {
            return Err(ChainError::InvalidAnchor);
        }

        // Verify input commitment exists
        if !self
            .accumulator
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
    async fn test_accumulator_insert_and_witness() {
        let acc = MockAccumulator::new(4);

        let cm = Fr::from(42u64);
        acc.insert(cm, "tx_1");

        assert!(acc.exists(cm).await.unwrap());

        let witness = acc.get_witness(cm).await.unwrap();
        assert!(witness.verify_local(cm));
    }

    #[tokio::test]
    async fn test_store_not_found() {
        let acc = MockAccumulator::new(4);

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
        let acc = Arc::new(MockAccumulator::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        let cm = Fr::from(42u64);
        let result = chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
            })
            .await
            .unwrap();

        assert_eq!(result.commitment, cm);
        assert!(acc.exists(cm).await.unwrap());
    }

    #[tokio::test]
    async fn test_chain_transfer() {
        let acc = Arc::new(MockAccumulator::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        // Shield first
        let cm1 = Fr::from(42u64);
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm1,
            })
            .await
            .unwrap();

        // Get witness
        let witness = acc.get_witness(cm1).await.unwrap();

        // Transfer
        let nf = Fr::from(12345u64);
        let cm2 = Fr::from(100u64);

        let result = chain
            .transfer(TransferRequest {
                anchor: chain.get_current_anchor().await.unwrap(),
                input_commitment: cm1,
                membership_witness: witness,
                nullifier: nf,
                spend_proof: vec![],
                output_commitments: vec![cm2],
                ciphertexts: vec![],
            })
            .await
            .unwrap();

        assert_eq!(result.output_commitments, vec![cm2]);
        assert!(chain.is_nullifier_spent(&nf).await.unwrap());
    }

    #[tokio::test]
    async fn test_double_spend_prevented() {
        let acc = Arc::new(MockAccumulator::new(4));
        let chain = MockChain::new(acc.clone(), 10);

        // Shield
        let cm = Fr::from(42u64);
        chain
            .shield(ShieldRequest {
                token_address: [0u8; 32],
                amount: 100,
                commitment: cm,
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
                output_commitments: vec![Fr::from(100u64)],
                ciphertexts: vec![],
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
                output_commitments: vec![Fr::from(200u64)],
                ciphertexts: vec![],
            })
            .await;

        assert!(matches!(result, Err(ChainError::DoubleSpend)));
    }

    #[tokio::test]
    async fn test_indexer_scan() {
        let acc = MockAccumulator::new(4);

        let cm1 = Fr::from(1u64);
        let cm2 = Fr::from(2u64);

        acc.insert_with_ciphertext(cm1, "tx_1", vec![1, 2, 3], [0u8; 32]);
        acc.insert_with_ciphertext(cm2, "tx_2", vec![4, 5, 6], [0u8; 32]);

        // Scan all
        let outputs = acc.scan_outputs_since(None).await.unwrap();
        assert_eq!(outputs.len(), 2);

        // Scan since tx_1
        let outputs = acc.scan_outputs_since(Some("tx_1")).await.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].commitment, cm2);
    }

    #[tokio::test]
    async fn test_indexer_get_commitments_for_tx() {
        let acc = MockAccumulator::new(4);

        let cm1 = Fr::from(1u64);
        let cm2 = Fr::from(2u64);

        acc.insert(cm1, "tx_1");
        acc.insert(cm2, "tx_1");

        let cms = acc.get_commitments_for_tx("tx_1").await.unwrap();
        assert_eq!(cms, vec![cm1, cm2]);
    }
}


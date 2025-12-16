//! Trait definitions for external dependencies
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      MaspClient                              │
//! │  - Keys, notes, ZK proof generation                          │
//! └───────────────────┬───────────────────┬─────────────────────┘
//!                     │                   │
//!                     ▼                   ▼
//! ┌───────────────────────────┐   ┌─────────────────────────────┐
//! │    NoteCommitmentStore    │   │      NullifierSet           │
//! │  (stores note commitments)│   │  (tracks spent nullifiers)  │
//! │                           │   │                             │
//! │  Mock: Merkle tree        │   │  Mock: HashSet              │
//! │  Prod: Light Protocol     │   │  Prod: Light Protocol       │
//! └───────────────────────────┘   └─────────────────────────────┘
//! ```
//!
//! ## What We Prove
//!
//! 1. **Membership** - commitment exists in store
//!    - Mock: Merkle path verification
//!    - Light: Groth16 validity proof
//!
//! 2. **Non-membership** - nullifier NOT in set
//!    - Mock: HashSet.contains() == false
//!    - Light: Address insert succeeds
//!
//! 3. **Spend validity** - ZK proof of valid note
//!    - Current: UltraPlonk (via SpendProver trait)
//!    - Future: Could support other proving systems
//!
//! ## Feature-Based Configuration
//!
//! One crate, different features for different contexts:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Feature Flags                                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  prove         - SpendProver trait (client-side)            │
//! │  verify        - SpendVerifier trait (client + program)     │
//! │  backend-mock  - Mock implementations (testing)             │
//! │  backend-light - Light Protocol (production)                │
//! │  std           - Standard library (client)                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Key insight:** Write operations (insert commitment, insert nullifier)
//! aren't traits - they're instruction handlers. Traits are for:
//! - Read operations (both client and program)
//! - Proof generation (client only)
//! - Proof verification (both, but different implementations)

use crate::proofs::MembershipWitness;
use crate::types::{Anchor, Commitment, Fr, Nullifier, TokenAddress};
use async_trait::async_trait;
use thiserror::Error;

// ============================================================================
// Note Commitment Store
// ============================================================================

/// Errors from store operations
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Commitment not found")]
    NotFound,

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Trait for note commitment storage (membership proofs)
///
/// ## Mock Implementation
/// In-memory Merkle tree. Identifier = commitment.
/// Witness = Merkle path (siblings + indices).
///
/// ## Production Implementation (Light Protocol)
/// ZK Compression state tree with address = commitment.
/// Witness = Groth16 validity proof.
///
/// ## Crate Separation
/// - Read-only operations: `masp-traits` (no_std)
/// - Write operations: `masp-chain` (on-chain program)
#[async_trait]
pub trait NoteCommitmentStore: Send + Sync {
    /// Get the current root (anchor)
    async fn root(&self) -> Result<Anchor, StoreError>;

    /// Check if a commitment exists
    async fn exists(&self, commitment: Commitment) -> Result<bool, StoreError>;

    /// Get a membership witness for a commitment
    ///
    /// Returns the appropriate witness type for this backend:
    /// - Mock: MerkleWitness::MerklePath
    /// - Light: MerkleWitness::LightValidityProof
    async fn get_witness(&self, commitment: Commitment) -> Result<MembershipWitness, StoreError>;

    /// Get witnesses for multiple commitments (batched)
    ///
    /// Light Protocol can batch these into a single validity proof.
    async fn get_witnesses(
        &self,
        commitments: &[Commitment],
    ) -> Result<Vec<MembershipWitness>, StoreError> {
        // Default: sequential (override for batching)
        let mut witnesses = Vec::with_capacity(commitments.len());
        for cm in commitments {
            witnesses.push(self.get_witness(*cm).await?);
        }
        Ok(witnesses)
    }
}

// ============================================================================
// Nullifier Set
// ============================================================================

/// Errors from nullifier set operations
#[derive(Debug, Error)]
pub enum NullifierError {
    #[error("Nullifier already spent")]
    AlreadySpent,

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Trait for nullifier set (double-spend prevention)
///
/// ## Mock Implementation
/// In-memory HashSet. Insert fails if exists.
///
/// ## Production Implementation (Light Protocol)
/// Address tree with uniqueness enforcement.
/// Insert = create_address. Fails if address exists.
///
/// Note: Insertion is done via Chain trait (requires transaction).
#[async_trait]
pub trait NullifierSet: Send + Sync {
    /// Check if a nullifier has been spent
    async fn is_spent(&self, nullifier: &Nullifier) -> Result<bool, NullifierError>;
}

// ============================================================================
// ZK Proof System (Prove/Verify)
// ============================================================================

/// Errors from proof operations
#[derive(Debug, Error)]
pub enum ProofSystemError {
    #[error("Proof generation failed: {0}")]
    ProvingFailed(String),

    #[error("Proof verification failed")]
    VerificationFailed,

    #[error("Invalid public inputs")]
    InvalidPublicInputs,

    #[error("Circuit error: {0}")]
    CircuitError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Public inputs for spend proof
#[derive(Debug, Clone)]
pub struct SpendPublicInputs {
    /// Anchor (commitment tree root)
    pub anchor: Anchor,

    /// Nullifier being revealed
    pub nullifier: Nullifier,

    /// Output commitment(s)
    pub output_commitments: Vec<Commitment>,

    /// Transaction binding hash (prevents malleability)
    pub tx_binding: Fr,
}

/// Private inputs for spend proof
#[derive(Debug, Clone)]
pub struct SpendPrivateInputs {
    /// Note fields
    pub note_asset_id: Fr,
    pub note_amount: u64,
    pub note_recipient: Fr,
    pub note_nullifier_nonce: Fr,
    pub note_randomness: Fr,

    /// Nullifier key (from spending key)
    pub nk: Fr,

    /// Membership witness
    pub membership_witness: MembershipWitness,
}

/// Serialized proof bytes
#[derive(Debug, Clone)]
pub struct ProofBytes(pub Vec<u8>);

impl ProofBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Trait for spend proof generation (client-side)
///
/// ## Crate Separation
/// - `masp-prover` crate with `prove` feature
/// - Requires std (heavy computation)
///
/// ## Implementations
/// - `MockSpendProver` - Always returns valid mock proof
/// - `UltraPlonkProver` - Real Noir/UltraPlonk prover
pub trait SpendProver: Send + Sync {
    /// Generate a spend proof
    fn prove(
        &self,
        public_inputs: &SpendPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError>;

    /// Get the proving system name (for debugging)
    fn system_name(&self) -> &'static str;
}

/// Trait for spend proof verification (on-chain or client)
///
/// ## Crate Separation
/// - `masp-verifier` crate with `verify` feature
/// - Should be no_std compatible for on-chain use
///
/// ## Implementations
/// - `MockSpendVerifier` - Always returns true
/// - `UltraPlonkVerifier` - Real verification via BN254 syscalls
pub trait SpendVerifier: Send + Sync {
    /// Verify a spend proof
    fn verify(
        &self,
        public_inputs: &SpendPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError>;

    /// Get the verification system name (for debugging)
    fn system_name(&self) -> &'static str;
}

// ============================================================================
// Chain (transaction submission)
// ============================================================================

/// Errors from chain operations
#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Nullifier already spent")]
    DoubleSpend,

    #[error("Invalid anchor: not in history")]
    InvalidAnchor,

    #[error("Proof verification failed")]
    InvalidProof,

    #[error("Insufficient funds for deposit")]
    InsufficientFunds,

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Shield (deposit) request
#[derive(Debug, Clone)]
pub struct ShieldRequest {
    pub token_address: TokenAddress,
    pub amount: u64,
    pub commitment: Commitment,
}

/// Shield result
#[derive(Debug, Clone)]
pub struct ShieldResult {
    pub tx_sig: String,
    pub commitment: Commitment,
}

/// Transfer request
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Anchor for membership proof
    pub anchor: Anchor,

    /// Input commitment being spent
    pub input_commitment: Commitment,

    /// Membership witness (Merkle path or validity proof)
    pub membership_witness: MembershipWitness,

    /// Nullifier of spent note
    pub nullifier: Nullifier,

    /// ZK proof of valid spend (UltraPlonk)
    pub spend_proof: Vec<u8>,

    /// Output commitments
    pub output_commitments: Vec<Commitment>,

    /// Encrypted notes for recipients
    pub ciphertexts: Vec<Vec<u8>>,
}

/// Transfer result
#[derive(Debug, Clone)]
pub struct TransferResult {
    pub tx_sig: String,
    pub output_commitments: Vec<Commitment>,
}

/// Unshield (withdraw) request
#[derive(Debug, Clone)]
pub struct UnshieldRequest {
    pub anchor: Anchor,
    pub input_commitment: Commitment,
    pub membership_witness: MembershipWitness,
    pub nullifier: Nullifier,
    pub spend_proof: Vec<u8>,
    pub recipient: [u8; 32],
    pub amount: u64,
    pub token_address: TokenAddress,
}

/// Unshield result
#[derive(Debug, Clone)]
pub struct UnshieldResult {
    pub tx_sig: String,
}

/// Result of inserting a commitment
#[derive(Debug, Clone)]
pub struct InsertCommitmentResult {
    /// Transaction signature
    pub tx_sig: String,
    /// The commitment that was inserted
    pub commitment: Commitment,
}

/// Chain trait - state operations and transaction submission
///
/// ## Architecture
///
/// ```text
/// Low-level operations (building blocks):
///   - insert_commitment()     Insert note commitment into tree
///   - insert_nullifier()      Insert nullifier (fails if exists)
///   - get_current_anchor()    Get current tree root
///   - is_valid_anchor()       Check anchor in history
///   - is_nullifier_spent()    Check nullifier exists
///
/// High-level operations (use the building blocks):
///   - shield()                Deposit tokens + insert commitment
///   - transfer()              Spend + insert nullifier + insert outputs
///   - unshield()              Spend + insert nullifier + withdraw tokens
/// ```
///
/// ## Implementations
/// - `MockChain` - In-memory state
/// - `SurfpoolChain` - Local validator (future)
/// - `SolanaRpcChain` - Real Solana (future)
#[async_trait]
pub trait Chain: Send + Sync {
    // ===== Low-level state operations =====

    /// Insert a commitment into the note commitment tree
    ///
    /// This is the primitive operation - shield/transfer use this internally.
    async fn insert_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<InsertCommitmentResult, ChainError>;

    /// Insert a nullifier (fails if already exists)
    ///
    /// This is how double-spend prevention works.
    /// Returns Ok(tx_sig) on success, Err(DoubleSpend) if exists.
    async fn insert_nullifier(&self, nullifier: Nullifier) -> Result<String, ChainError>;

    /// Get the current anchor (tree root)
    async fn get_current_anchor(&self) -> Result<Anchor, ChainError>;

    /// Check if an anchor is valid (in root history)
    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError>;

    /// Check if a nullifier has been spent
    async fn is_nullifier_spent(&self, nullifier: &Nullifier) -> Result<bool, ChainError>;

    // ===== High-level operations =====

    /// Shield: deposit tokens + insert commitment
    ///
    /// Default implementation: just insert commitment.
    /// Real implementation: also transfers tokens to pool.
    async fn shield(&self, request: ShieldRequest) -> Result<ShieldResult, ChainError> {
        let result = self.insert_commitment(request.commitment).await?;
        Ok(ShieldResult {
            tx_sig: result.tx_sig,
            commitment: result.commitment,
        })
    }

    /// Transfer: spend note(s), create output(s)
    ///
    /// 1. Verify anchor is valid
    /// 2. Verify membership proof
    /// 3. Verify ZK spend proof
    /// 4. Insert nullifier (fails if double-spend)
    /// 5. Insert output commitments
    async fn transfer(&self, request: TransferRequest) -> Result<TransferResult, ChainError>;

    /// Unshield: spend note, withdraw tokens
    ///
    /// 1. Verify anchor is valid
    /// 2. Verify proofs
    /// 3. Insert nullifier
    /// 4. Transfer tokens to recipient
    async fn unshield(&self, request: UnshieldRequest) -> Result<UnshieldResult, ChainError>;
}

// ============================================================================
// Indexer (for scanning)
// ============================================================================

/// Errors from indexer operations
#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("Not found")]
    NotFound,

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Output ciphertext from chain (for scanning)
#[derive(Debug, Clone)]
pub struct OutputCiphertext {
    /// The commitment (note identifier)
    pub commitment: Commitment,

    /// Encrypted note plaintext
    pub ciphertext: Vec<u8>,

    /// Ephemeral public key for decryption
    pub ephemeral_key: [u8; 32],

    /// Transaction that created this output
    pub tx_sig: String,
}

/// Indexer trait - scans for notes, provides witnesses
///
/// Combines NoteCommitmentStore queries with ciphertext scanning.
///
/// ## Mock Implementation
/// Combined with mock store.
///
/// ## Production Implementation
/// Helius RPC for ZK Compression APIs.
#[async_trait]
pub trait Indexer: NoteCommitmentStore {
    /// Scan for output ciphertexts since a transaction
    async fn scan_outputs_since(
        &self,
        since_tx: Option<&str>,
    ) -> Result<Vec<OutputCiphertext>, IndexerError>;

    /// Get commitments created in a transaction (for OOB)
    async fn get_commitments_for_tx(&self, tx_sig: &str) -> Result<Vec<Commitment>, IndexerError>;
}

// ============================================================================
// Backward Compatibility
// ============================================================================

/// Legacy MerkleWitness type (use MembershipWitness instead)
#[derive(Debug, Clone)]
pub struct MerkleWitness {
    pub siblings: Vec<Fr>,
    pub path_indices: Vec<bool>,
    pub root: Anchor,
}

impl MerkleWitness {
    pub fn verify(&self, commitment: Commitment) -> bool {
        self.to_membership_witness().verify_local(commitment)
    }

    pub fn to_membership_witness(&self) -> MembershipWitness {
        MembershipWitness::merkle_path(self.siblings.clone(), self.path_indices.clone(), self.root)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_witness_verify() {
        use crate::hash::merkle_hash;

        let leaf = Fr::from(42u64);
        let sibling = Fr::from(100u64);
        let root = merkle_hash(leaf, sibling);

        let witness = MerkleWitness {
            siblings: vec![sibling],
            path_indices: vec![false],
            root,
        };

        assert!(witness.verify(leaf));
        assert!(!witness.verify(Fr::from(999u64)));
    }
}

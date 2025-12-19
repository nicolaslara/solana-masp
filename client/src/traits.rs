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
//! │  verify        - ProofVerifier trait (client + program)     │
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
use crate::types::{Anchor, CiphertextHash, Commitment, Fr, Nullifier, TokenAddress};
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

/// Maximum number of inputs in a transfer.
pub const MAX_INPUTS: usize = crate::tx_binding::MAX_INPUTS;

/// Maximum number of outputs in a transfer.
pub const MAX_OUTPUTS: usize = crate::tx_binding::MAX_OUTPUTS;

/// Public inputs for transfer proof.
///
/// Supports flexible N inputs and M outputs within fixed compile-time maxima.
/// Arrays are fixed-size and padded with zeros for disabled slots.
/// This includes the common 1→3 case (1 input, up to 3 outputs: payment + change + fee).
#[derive(Debug, Clone)]
pub struct TransferPublicInputs {
    /// Shared anchor (commitment tree root) for all inputs
    pub anchor: Anchor,

    /// Nullifiers being revealed (padded with 0 for disabled inputs)
    pub nullifiers: [Nullifier; MAX_INPUTS],

    /// Output commitments (padded with 0 for disabled outputs)
    pub output_commitments: [Commitment; MAX_OUTPUTS],

    /// Number of enabled inputs (1 ≤ input_count ≤ MAX_INPUTS)
    pub input_count: u32,

    /// Number of enabled outputs (1 ≤ output_count ≤ MAX_OUTPUTS)
    pub output_count: u32,

    /// Ciphertext hashes for output binding (padded with 0 for disabled outputs)
    ///
    /// Each enabled output `j` has `ct_hashes[j] = H(DOM_CIPHERTEXT, ciphertext_bytes[j])`.
    /// This binds the proof to the ciphertext bytes published in Tx A (Option 1A baseline).
    /// See `docs/design-decisions/ciphertext-da-and-binding.md`.
    pub ct_hashes: [CiphertextHash; MAX_OUTPUTS],

    /// Transaction binding hash (prevents malleability)
    ///
    /// Includes anchor, counts, nullifiers, and ct_hashes (see `tx_binding.rs`).
    pub tx_binding: Fr,
}

impl TransferPublicInputs {
    /// Get the enabled nullifiers (non-zero values based on input_count).
    pub fn enabled_nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers[..self.input_count as usize]
    }

    /// Get the enabled output commitments (non-zero values based on output_count).
    pub fn enabled_output_commitments(&self) -> &[Commitment] {
        &self.output_commitments[..self.output_count as usize]
    }

    /// Create placeholder ct_hashes for testing.
    ///
    /// In production, ct_hashes should be computed from actual ciphertext bytes.
    /// This helper creates non-zero placeholders for enabled outputs (0..output_count)
    /// and zero for disabled outputs.
    pub fn placeholder_ct_hashes(output_count: u32) -> [CiphertextHash; MAX_OUTPUTS] {
        let mut ct_hashes = [Fr::from(0u64); MAX_OUTPUTS];
        for i in 0..(output_count as usize).min(MAX_OUTPUTS) {
            // Use a unique non-zero value for each enabled output
            ct_hashes[i] = Fr::from((i + 1) as u64);
        }
        ct_hashes
    }

    /// Get the enabled ciphertext hashes (non-zero values based on output_count).
    pub fn enabled_ct_hashes(&self) -> &[CiphertextHash] {
        &self.ct_hashes[..self.output_count as usize]
    }
}

/// Private inputs for a single input slot in a transfer.
#[derive(Debug, Clone)]
pub struct InputSlot {
    /// Whether this input is enabled
    pub enabled: bool,

    /// Note fields (only meaningful if enabled)
    pub note_asset_id: Fr,
    pub note_amount: u64,
    pub note_recipient: Fr,
    pub note_diversifier_index: u64,
    pub note_nullifier_nonce: Fr,
    pub note_randomness: Fr,

    /// Nullifier key for this input
    pub nk: Fr,

    /// Spending key as field element
    pub spending_key: Fr,

    /// Membership witness for this input
    pub membership_witness: MembershipWitness,
}

impl Default for InputSlot {
    fn default() -> Self {
        Self {
            enabled: false,
            note_asset_id: Fr::from(0u64),
            note_amount: 0,
            note_recipient: Fr::from(0u64),
            note_diversifier_index: 0,
            note_nullifier_nonce: Fr::from(0u64),
            note_randomness: Fr::from(0u64),
            nk: Fr::from(0u64),
            spending_key: Fr::from(0u64),
            membership_witness: MembershipWitness::merkle_path(vec![], vec![], Fr::from(0u64)),
        }
    }
}

/// Private inputs for a single output slot in a transfer.
#[derive(Debug, Clone)]
pub struct OutputSlot {
    /// Whether this output is enabled
    pub enabled: bool,

    /// The output note (only meaningful if enabled)
    pub note: crate::note::Note,
}

impl Default for OutputSlot {
    fn default() -> Self {
        Self {
            enabled: false,
            note: crate::note::Note::with_values(
                Fr::from(0u64),
                0,
                Fr::from(0u64),
                0,
                Fr::from(0u64),
                Fr::from(0u64),
            ),
        }
    }
}

/// Private inputs for transfer proof.
#[derive(Debug, Clone)]
pub struct TransferPrivateInputs {
    /// Input slots (fixed size, use `enabled` flag)
    pub inputs: [InputSlot; MAX_INPUTS],

    /// Output slots (fixed size, use `enabled` flag)
    pub outputs: [OutputSlot; MAX_OUTPUTS],
}

impl Default for TransferPrivateInputs {
    fn default() -> Self {
        Self {
            inputs: std::array::from_fn(|_| InputSlot::default()),
            outputs: std::array::from_fn(|_| OutputSlot::default()),
        }
    }
}

impl TransferPrivateInputs {
    /// Count enabled inputs.
    pub fn input_count(&self) -> u32 {
        self.inputs.iter().filter(|s| s.enabled).count() as u32
    }

    /// Count enabled outputs.
    pub fn output_count(&self) -> u32 {
        self.outputs.iter().filter(|s| s.enabled).count() as u32
    }
}

/// Public inputs for unshield proof
///
/// This follows `docs/circuit-security-requirements.md` (Unshield Circuit public inputs).
#[derive(Debug, Clone)]
pub struct UnshieldPublicInputs {
    /// Anchor (commitment tree root)
    pub anchor: Anchor,

    /// Nullifier being revealed
    pub nullifier: Nullifier,

    /// Transaction binding hash (prevents malleability / binds intent)
    pub tx_binding: Fr,

    /// Amount being withdrawn (public)
    pub public_amount: u64,

    /// Transparent recipient address (public), encoded as 4×u64 limbs (little-endian).
    ///
    /// This is injective (no collisions) and avoids the unsafe many-to-one mapping of
    /// `pubkey_bytes -> Fr mod p`.
    pub public_recipient_limbs: [u64; 4],

    /// Asset id (public)
    pub public_asset_id: Fr,
}

/// Public inputs for shield proof
///
/// This follows `docs/circuit-security-requirements.md` (Shield Circuit public inputs).
#[derive(Debug, Clone)]
pub struct ShieldPublicInputs {
    /// Commitment being inserted
    pub new_commitment: Commitment,
    /// Asset id (public)
    pub public_asset_id: Fr,
    /// Amount (public)
    pub public_amount: u64,
    /// Ciphertext hash for the output note (Option 1A binding).
    ///
    /// `ct_hash = H(DOM_CIPHERTEXT, ciphertext_bytes)`.
    /// See `docs/design-decisions/ciphertext-da-and-binding.md`.
    pub ct_hash: CiphertextHash,
}

impl ShieldPublicInputs {
    /// Create placeholder ct_hash for testing.
    ///
    /// In production, ct_hash should be computed from actual ciphertext bytes.
    /// This helper creates a non-zero placeholder value.
    pub fn placeholder_ct_hash() -> CiphertextHash {
        Fr::from(1u64)
    }
}

/// Public inputs for MASP proofs (per-circuit).
#[derive(Debug, Clone)]
pub enum ProofPublicInputs {
    /// Shield (deposit transparent -> shielded)
    Shield(ShieldPublicInputs),

    /// Transfer (N inputs -> M outputs in single proof)
    /// Common case: 1 input, up to 3 outputs (payment + change + fee)
    Transfer(TransferPublicInputs),

    /// Unshield (shielded spend + public withdrawal)
    Unshield(UnshieldPublicInputs),
}

/// Private inputs for a shield proof.
#[derive(Debug, Clone)]
pub struct ShieldPrivateInputs {
    pub note_asset_id: Fr,
    pub note_amount: u64,
    pub note_recipient: Fr,
    pub note_diversifier_index: u64,
    pub note_nullifier_nonce: Fr,
    pub note_randomness: Fr,
}

/// Private inputs for an unshield proof (single input spend).
#[derive(Debug, Clone)]
pub struct UnshieldPrivateInputs {
    /// Spending key (root secret) as a field element.
    pub spending_key: Fr,

    /// Note fields
    pub note_asset_id: Fr,
    pub note_amount: u64,
    pub note_recipient: Fr,
    pub note_diversifier_index: u64,
    pub note_nullifier_nonce: Fr,
    pub note_randomness: Fr,

    /// Nullifier key (`nk.x` as a field element).
    pub nk: Fr,

    /// Membership witness for the spent note.
    pub membership_witness: MembershipWitness,
}

/// Private inputs for MASP proofs (per-circuit).
#[derive(Debug, Clone)]
pub enum ProofPrivateInputs {
    Shield(ShieldPrivateInputs),
    Transfer(TransferPrivateInputs),
    Unshield(UnshieldPrivateInputs),
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
///
pub trait SpendProver: Send + Sync {
    /// Generate a proof for the given public inputs and private witness.
    fn prove(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &ProofPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError>;

    /// Get the proving system name (for debugging)
    fn system_name(&self) -> &'static str;
}

/// Trait for ZK proof verification (locally or via on-chain program)
///
/// ## Crate Separation
/// - `masp-verifier` crate with `verify` feature
/// - Should be no_std compatible for on-chain use
///
/// ## Implementations
/// - `MockProofVerifier` - Always returns true
/// - `UltraPlonkVerifier` - Verification via BN254 syscalls / Solana program
///
/// Notes:
/// - We support *two* verification paths:
///   - `verify_local`: for fast local iteration (unit tests, mock chain)
///   - `verify_on_chain`: for Solana program verification (instruction/CPI)
/// - Most implementations can simply implement `verify_local` and inherit the
///   default `verify_on_chain` behavior (delegates to local) until a program
///   integration exists.
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    /// Verify a spend proof locally (off-chain)
    async fn verify_local(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError>;

    /// Verify a spend proof via the on-chain verifier (instruction/CPI).
    ///
    /// Default: fall back to local verification (useful for scaffolds).
    async fn verify_on_chain(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        self.verify_local(public_inputs, proof).await
    }

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
    /// ZK proof for shield (optional in early scaffolding; required in production).
    pub shield_proof: Vec<u8>,
    /// Encrypted note for self-scanning (stored in calldata)
    pub ciphertext: Option<Vec<u8>>,
    /// Ephemeral public key
    pub ephemeral_key: Option<[u8; 64]>,
    /// Ciphertext hash for output binding (Option 1A).
    ///
    /// If `ciphertext` and `ephemeral_key` are present, this SHOULD be set to
    /// `output_ciphertext_hash(ciphertext, ephemeral_key)`.
    /// Zero if not yet computed.
    pub ct_hash: CiphertextHash,
}

impl ShieldRequest {
    /// Get the ciphertext hash (returns zero if not set).
    pub fn ct_hash(&self) -> CiphertextHash {
        self.ct_hash
    }
}

/// Shield result
#[derive(Debug, Clone)]
pub struct ShieldResult {
    pub tx_sig: String,
    pub commitment: Commitment,
}

// ============================================================================
// Ciphertext Posting (Tx A) - Option 1A baseline
// ============================================================================

/// A single output ciphertext to be posted in Tx A.
///
/// In the Option 1A baseline, ciphertexts are posted in a separate transaction (Tx A)
/// before the MASP state transition (Tx B). This struct represents one output's ciphertext data.
#[derive(Debug, Clone)]
pub struct OutputCiphertextData {
    /// The encrypted note plaintext (C_enc)
    pub ciphertext: Vec<u8>,

    /// Ephemeral public key (64 bytes: x || y)
    pub ephemeral_key: [u8; 64],

    /// Precomputed ciphertext hash for binding.
    /// `ct_hash = H(DOM_CIPHERTEXT, ephemeral_key || ciphertext)`
    pub ct_hash: CiphertextHash,
}

impl OutputCiphertextData {
    /// Create from raw ciphertext bytes and ephemeral key, computing the ct_hash.
    pub fn new(ciphertext: Vec<u8>, ephemeral_key: [u8; 64]) -> Self {
        let ct_hash = crate::hash::ciphertext_hash(&[&ephemeral_key[..], &ciphertext[..]].concat());
        Self {
            ciphertext,
            ephemeral_key,
            ct_hash,
        }
    }

    /// Get the bytes that should be posted in Tx A (ephemeral_key || ciphertext).
    pub fn posting_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.ciphertext.len());
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
}

/// Request to post ciphertexts (Tx A) for later binding in Tx B.
///
/// This represents a "ciphertext posting transaction" in the Option 1A baseline.
/// The posted ciphertexts become ledger-historical artifacts (archive-retrievable).
#[derive(Debug, Clone)]
pub struct CiphertextPostingRequest {
    /// Ciphertexts to post (one per enabled output in the upcoming Tx B).
    pub outputs: Vec<OutputCiphertextData>,
}

/// Result of posting ciphertexts (Tx A).
#[derive(Debug, Clone)]
pub struct CiphertextPostingResult {
    /// Transaction signature of the ciphertext posting transaction.
    pub tx_sig: String,

    /// The ct_hashes for each posted output (in order).
    /// These should be used in the corresponding Tx B's public inputs.
    pub ct_hashes: Vec<CiphertextHash>,
}

// ============================================================================
// Transfer Output
// ============================================================================

/// Output data for a transfer (commitment + optional ciphertext)
#[derive(Debug, Clone)]
pub struct TransferOutput {
    /// The note commitment
    pub commitment: Commitment,

    /// Encrypted note plaintext (C_enc) - stored in transaction calldata
    pub ciphertext: Option<Vec<u8>>,

    /// Ephemeral public key (64 bytes: x || y)
    pub ephemeral_key: Option<[u8; 64]>,
}

impl TransferOutput {
    /// Create output with just a commitment (no ciphertext)
    pub fn commitment_only(commitment: Commitment) -> Self {
        Self {
            commitment,
            ciphertext: None,
            ephemeral_key: None,
        }
    }

    /// Create output with ciphertext data
    pub fn with_ciphertext(
        commitment: Commitment,
        ciphertext: Vec<u8>,
        ephemeral_key: [u8; 64],
    ) -> Self {
        Self {
            commitment,
            ciphertext: Some(ciphertext),
            ephemeral_key: Some(ephemeral_key),
        }
    }
}

/// Transfer request (N inputs -> M outputs).
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Shared anchor for all input membership proofs
    pub anchor: Anchor,

    /// Nullifiers being revealed (padded with 0 for disabled inputs)
    pub nullifiers: [Nullifier; MAX_INPUTS],

    /// Number of enabled inputs
    pub input_count: u32,

    /// Number of enabled outputs
    pub output_count: u32,

    /// Ciphertext hashes for output binding (padded with 0 for disabled outputs)
    ///
    /// Each enabled output `j` has `ct_hashes[j] = H(DOM_CIPHERTEXT, ciphertext_bytes[j])`.
    pub ct_hashes: [CiphertextHash; MAX_OUTPUTS],

    /// Transaction binding hash (public input to spend proof)
    pub tx_binding: Fr,

    /// ZK proof of valid spend (UltraPlonk)
    pub spend_proof: Vec<u8>,

    /// Output data (fixed size, disabled slots have zero commitment)
    pub outputs: [TransferOutput; MAX_OUTPUTS],
}

impl TransferRequest {
    /// Get the enabled nullifiers (non-zero values).
    pub fn enabled_nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers[..self.input_count as usize]
    }

    /// Get the enabled output commitments.
    pub fn enabled_output_commitments(&self) -> Vec<Commitment> {
        self.outputs[..self.output_count as usize]
            .iter()
            .map(|o| o.commitment)
            .collect()
    }

    /// Get the padded output commitment array.
    pub fn output_commitments_array(&self) -> [Commitment; MAX_OUTPUTS] {
        std::array::from_fn(|i| self.outputs[i].commitment)
    }
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
    pub nullifier: Nullifier,
    pub tx_binding: Fr,
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

    /// Batch check if nullifiers have been spent (for shielded sync)
    ///
    /// This is critical for efficient wallet recovery - instead of checking
    /// each nullifier individually (O(n) RPC calls), we check all at once.
    ///
    /// Returns a Vec of bools in the same order as input nullifiers.
    async fn batch_check_nullifiers(
        &self,
        nullifiers: &[Nullifier],
    ) -> Result<Vec<bool>, ChainError> {
        // Default: sequential checks (inefficient but correct)
        let mut results = Vec::with_capacity(nullifiers.len());
        for nf in nullifiers {
            results.push(self.is_nullifier_spent(nf).await?);
        }
        Ok(results)
    }

    // ===== Ciphertext posting (Tx A) =====

    /// Post ciphertexts for output notes (Tx A in Option 1A baseline).
    ///
    /// This submits ciphertext bytes to the ledger for later binding in Tx B.
    /// The ciphertexts become archive-retrievable historical artifacts.
    ///
    /// Returns the transaction signature and the ct_hashes for each output.
    async fn post_ciphertexts(
        &self,
        request: CiphertextPostingRequest,
    ) -> Result<CiphertextPostingResult, ChainError>;

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

    /// Transfer: spend note(s), create output(s).
    ///
    /// Supports N inputs and M outputs (including common 1→3 case).
    ///
    /// 1. Verify anchor is valid
    /// 2. Verify ZK spend proof
    /// 3. Insert each non-zero nullifier (fails if any is double-spend)
    /// 4. Insert each non-zero output commitment
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

    /// Encrypted note plaintext (C_enc) for recipient
    pub ciphertext: Vec<u8>,

    /// Ephemeral public key for decryption (64 bytes: x || y)
    pub ephemeral_key: [u8; 64],

    /// Transaction that created this output
    pub tx_sig: String,

    /// Ciphertext hash from the proof's public inputs.
    ///
    /// This is the `ct_hash` that was bound in Tx B's ZK proof.
    /// Wallets MUST verify: `ciphertext_hash(&ciphertext) == committed_ct_hash`
    /// before accepting the note.
    ///
    /// If None, the wallet should fetch ct_hash from the transaction's public inputs.
    pub committed_ct_hash: Option<CiphertextHash>,
}

/// Scan parameters for shielded sync
#[derive(Debug, Clone, Default)]
pub struct ScanParams {
    /// Start from this transaction (exclusive)
    pub since_tx: Option<String>,
    /// Limit number of outputs to return
    pub limit: Option<usize>,
}

/// Scan result with pagination info
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Outputs found
    pub outputs: Vec<OutputCiphertext>,
    /// Last tx_sig for pagination
    pub last_tx_sig: Option<String>,
    /// Whether there are more results
    pub has_more: bool,
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

    /// Wait until the indexer has observed recent chain updates.
    ///
    /// In production, indexers are external observers of the ledger (RPC/Helius/Light),
    /// so this is often a **no-op** from the protocol perspective.
    ///
    /// In tests, this can be used to model indexing latency between a transaction
    /// being submitted and becoming queryable via the indexer.
    ///
    /// Default: no-op.
    async fn wait_for_update(&self, _tx_sig: Option<&str>) -> Result<(), IndexerError> {
        Ok(())
    }

    /// Scan with pagination (for efficient shielded sync)
    async fn scan_outputs_paginated(&self, params: ScanParams) -> Result<ScanResult, IndexerError> {
        // Default: use non-paginated scan
        let outputs = self.scan_outputs_since(params.since_tx.as_deref()).await?;

        let (outputs, has_more) = if let Some(limit) = params.limit {
            if outputs.len() > limit {
                (outputs[..limit].to_vec(), true)
            } else {
                (outputs, false)
            }
        } else {
            (outputs, false)
        };

        let last_tx_sig = outputs.last().map(|o| o.tx_sig.clone());

        Ok(ScanResult {
            outputs,
            last_tx_sig,
            has_more,
        })
    }

    /// Get commitments created in a transaction (for OOB)
    async fn get_commitments_for_tx(&self, tx_sig: &str) -> Result<Vec<Commitment>, IndexerError>;

    /// Get output ciphertexts for a transaction (for OOB)
    async fn get_outputs_for_tx(
        &self,
        tx_sig: &str,
    ) -> Result<Vec<OutputCiphertext>, IndexerError> {
        // Default: scan all and filter
        let outputs = self.scan_outputs_since(None).await?;
        Ok(outputs.into_iter().filter(|o| o.tx_sig == tx_sig).collect())
    }

    // ===== Ciphertext retrieval (Option 1A baseline) =====

    /// Get ciphertext bytes by ct_hash.
    ///
    /// This is used by wallets to fetch ciphertext data posted in Tx A
    /// when they know the ct_hash (e.g., from Tx B's public inputs).
    ///
    /// Returns (tx_sig, output_index, ciphertext_bytes, ephemeral_key) if found.
    async fn get_ciphertext_by_hash(
        &self,
        ct_hash: &CiphertextHash,
    ) -> Result<Option<(String, u32, Vec<u8>, [u8; 64])>, IndexerError>;

    /// Get ciphertext for a specific output in a transaction.
    ///
    /// This is used when the wallet knows the tx_sig and output_index
    /// (e.g., from OOB notification).
    ///
    /// Returns (ciphertext_bytes, ephemeral_key, ct_hash) if found.
    async fn get_ciphertext_for_output(
        &self,
        tx_sig: &str,
        output_index: u32,
    ) -> Result<Option<(Vec<u8>, [u8; 64], CiphertextHash)>, IndexerError>;
}

// ============================================================================
// Arc Blanket Implementations
// ============================================================================

// These allow Arc<T> to be used where T is expected, enabling shared ownership
// of backend implementations across multiple clients.

use std::sync::Arc;

#[async_trait]
impl<T: NoteCommitmentStore + ?Sized> NoteCommitmentStore for Arc<T> {
    async fn root(&self) -> Result<Anchor, StoreError> {
        (**self).root().await
    }

    async fn exists(&self, commitment: Commitment) -> Result<bool, StoreError> {
        (**self).exists(commitment).await
    }

    async fn get_witness(&self, commitment: Commitment) -> Result<MembershipWitness, StoreError> {
        (**self).get_witness(commitment).await
    }

    async fn get_witnesses(
        &self,
        commitments: &[Commitment],
    ) -> Result<Vec<MembershipWitness>, StoreError> {
        (**self).get_witnesses(commitments).await
    }
}

#[async_trait]
impl<T: NullifierSet + ?Sized> NullifierSet for Arc<T> {
    async fn is_spent(&self, nullifier: &Nullifier) -> Result<bool, NullifierError> {
        (**self).is_spent(nullifier).await
    }
}

#[async_trait]
impl<T: Chain + ?Sized> Chain for Arc<T> {
    async fn insert_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<InsertCommitmentResult, ChainError> {
        (**self).insert_commitment(commitment).await
    }

    async fn insert_nullifier(&self, nullifier: Nullifier) -> Result<String, ChainError> {
        (**self).insert_nullifier(nullifier).await
    }

    async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
        (**self).get_current_anchor().await
    }

    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError> {
        (**self).is_valid_anchor(anchor).await
    }

    async fn is_nullifier_spent(&self, nullifier: &Nullifier) -> Result<bool, ChainError> {
        (**self).is_nullifier_spent(nullifier).await
    }

    async fn batch_check_nullifiers(
        &self,
        nullifiers: &[Nullifier],
    ) -> Result<Vec<bool>, ChainError> {
        (**self).batch_check_nullifiers(nullifiers).await
    }

    async fn post_ciphertexts(
        &self,
        request: CiphertextPostingRequest,
    ) -> Result<CiphertextPostingResult, ChainError> {
        (**self).post_ciphertexts(request).await
    }

    async fn shield(&self, request: ShieldRequest) -> Result<ShieldResult, ChainError> {
        (**self).shield(request).await
    }

    async fn transfer(&self, request: TransferRequest) -> Result<TransferResult, ChainError> {
        (**self).transfer(request).await
    }

    async fn unshield(&self, request: UnshieldRequest) -> Result<UnshieldResult, ChainError> {
        (**self).unshield(request).await
    }
}

#[async_trait]
impl<T: Indexer + ?Sized> Indexer for Arc<T> {
    async fn scan_outputs_since(
        &self,
        since_tx: Option<&str>,
    ) -> Result<Vec<OutputCiphertext>, IndexerError> {
        (**self).scan_outputs_since(since_tx).await
    }

    async fn wait_for_update(&self, tx_sig: Option<&str>) -> Result<(), IndexerError> {
        (**self).wait_for_update(tx_sig).await
    }

    async fn scan_outputs_paginated(&self, params: ScanParams) -> Result<ScanResult, IndexerError> {
        (**self).scan_outputs_paginated(params).await
    }

    async fn get_commitments_for_tx(&self, tx_sig: &str) -> Result<Vec<Commitment>, IndexerError> {
        (**self).get_commitments_for_tx(tx_sig).await
    }

    async fn get_outputs_for_tx(
        &self,
        tx_sig: &str,
    ) -> Result<Vec<OutputCiphertext>, IndexerError> {
        (**self).get_outputs_for_tx(tx_sig).await
    }

    async fn get_ciphertext_by_hash(
        &self,
        ct_hash: &CiphertextHash,
    ) -> Result<Option<(String, u32, Vec<u8>, [u8; 64])>, IndexerError> {
        (**self).get_ciphertext_by_hash(ct_hash).await
    }

    async fn get_ciphertext_for_output(
        &self,
        tx_sig: &str,
        output_index: u32,
    ) -> Result<Option<(Vec<u8>, [u8; 64], CiphertextHash)>, IndexerError> {
        (**self)
            .get_ciphertext_for_output(tx_sig, output_index)
            .await
    }
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

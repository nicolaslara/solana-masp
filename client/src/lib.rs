//! MASP Client Library
//!
//! Multi-Asset Shielded Pool client for Solana.
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                      MaspClient                             │
//! │  - Keys, notes, proof generation                            │
//! └──────────────────┬─────────────────┬───────────────────────┘
//!                    │                 │
//!                    ▼                 ▼
//! ┌────────────────────────┐   ┌──────────────────────────────┐
//! │  Indexer               │   │  Chain                        │
//! │  (witness + scan)      │   │  (submit transactions)        │
//! │                        │   │                               │
//! │  Mock: MockNoteStore   │   │  Mock: MockChain              │
//! │  Prod: Helius RPC      │   │  Prod: Solana + Light Proto   │
//! └────────────────────────┘   └──────────────────────────────┘
//! ```
//!
//! ## Proofs
//!
//! Three types of proofs:
//! 1. **Membership** - commitment in note store (Merkle path or validity proof)
//! 2. **Non-membership** - nullifier not spent (set check or insert-or-fail)
//! 3. **Spend validity** - ZK proof of valid note (always UltraPlonk)

// ============================================================================
// Constants
// ============================================================================

/// Merkle tree depth for commitment accumulator.
/// Must match circuits/masp/common/src/constants.nr::MERKLE_DEPTH
pub const MERKLE_DEPTH: usize = 32;

/// Maximum number of inputs per transfer.
/// Must match circuits/masp/common/src/constants.nr::MAX_INPUTS
pub const MAX_INPUTS: usize = 3;

/// Maximum number of outputs per transfer.
/// Must match circuits/masp/common/src/constants.nr::MAX_OUTPUTS
pub const MAX_OUTPUTS: usize = 3;

// Core cryptographic primitives
pub mod domain;
pub mod encryption;
pub mod hash;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod oob;
pub mod tx_binding;
pub mod types;

// Proof abstractions
pub mod proofs;

// Backend traits
pub mod traits;

// Backend implementations
pub mod backends;
pub mod mock;

// Client
pub mod client;

// Re-exports
pub use backends::config::ProofVerificationMode;
pub use backends::LightIndexer;
pub use backends::ProofSystemBackend;
pub use backends::{BackendConfig, ChainBackend, EncryptionBackend, IndexerBackend};

#[cfg(feature = "solana-backend")]
pub use backends::SolanaChain;
pub use client::{MaspClient, OwnedNote, SyncResult};
pub use encryption::{
    encrypt_note, trial_decrypt, try_decrypt_note, verify_decrypted_note, verify_note_commitment,
    verify_note_ownership, ChaChaPolyEncryption, EncryptedNote, EncryptionError, MockEncryption,
    NoteEncryption, NoteVerification,
};
pub use hash::ciphertext_hash;
pub use keys::{DiversifiedAddress, FullViewingKey, SpendingKey};
pub use note::Note;
pub use oob::{
    MockOobChannel, OobChannel, OobError, OobNotificationBuilder, PaymentDetails,
    PaymentNotification,
};
pub use proofs::{MembershipWitness, StoreId};
#[cfg(feature = "onchain-mock")]
pub use proofs::{OnChainMockProofVerifier, OnChainMockSpendProver};
pub use traits::{
    Chain, ChainError, CiphertextPostingRequest, CiphertextPostingResult, Indexer, IndexerError,
    InputSlot, InsertCommitmentResult, NoteCommitmentStore, NullifierError, NullifierSet,
    OutputCiphertext, OutputCiphertextData, OutputSlot, ProofBytes, ProofPrivateInputs,
    ProofPublicInputs, ProofSystemError, ProofVerifier, ScanParams, ScanResult,
    ShieldPrivateInputs, ShieldPublicInputs, ShieldRequest, ShieldResult, SpendProver, StoreError,
    TransferOutput, TransferPrivateInputs, TransferPublicInputs, TransferRequest, TransferResult,
    UnshieldPrivateInputs, UnshieldRequest, UnshieldResult,
};
pub use types::{Anchor, CiphertextHash, Commitment, Fr, Nullifier, TokenAddress};

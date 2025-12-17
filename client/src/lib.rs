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

// Core cryptographic primitives
pub mod domain;
pub mod encryption;
pub mod hash;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod oob;
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
pub use backends::ProofSystemBackend;
pub use backends::{BackendConfig, ChainBackend, EncryptionBackend, IndexerBackend};
pub use backends::{LightIndexer, SolanaChain};
pub use client::{MaspClient, OwnedNote, SyncResult};
pub use encryption::{
    encrypt_note, trial_decrypt, try_decrypt_note, verify_decrypted_note, verify_note_commitment,
    verify_note_ownership, ChaChaPolyEncryption, EncryptedNote, EncryptionError, MockEncryption,
    NoteEncryption, NoteVerification,
};
pub use keys::{DiversifiedAddress, FullViewingKey, SpendingKey};
pub use note::Note;
pub use oob::{
    MockOobChannel, OobChannel, OobError, OobNotificationBuilder, PaymentDetails,
    PaymentNotification,
};
pub use proofs::{MembershipWitness, StoreId};
pub use traits::{
    Chain, ChainError, Indexer, IndexerError, InsertCommitmentResult, NoteCommitmentStore,
    NullifierError, NullifierSet, OutputCiphertext, ProofBytes, ProofPublicInputs,
    ProofSystemError, ProofVerifier, ScanParams, ScanResult, ShieldPublicInputs, ShieldRequest,
    ShieldResult, SpendPrivateInputs, SpendProver, SpendPublicInputs, StoreError, TransferOutput,
    TransferRequest, TransferResult, UnshieldRequest, UnshieldResult,
};
pub use types::{Anchor, Commitment, Fr, Nullifier, TokenAddress};

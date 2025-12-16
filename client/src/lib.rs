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
//! │  Mock: MockAccumulator │   │  Mock: MockChain              │
//! │  Prod: Helius RPC      │   │  Prod: Solana + Light Proto   │
//! └────────────────────────┘   └──────────────────────────────┘
//! ```
//!
//! ## Proofs
//!
//! Three types of proofs:
//! 1. **Membership** - commitment in accumulator (Merkle path or validity proof)
//! 2. **Non-membership** - nullifier not spent (set check or insert-or-fail)
//! 3. **Spend validity** - ZK proof of valid note (always UltraPlonk)

// Core cryptographic primitives
pub mod domain;
pub mod hash;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod types;

// Proof abstractions
pub mod proofs;

// Backend traits
pub mod traits;

// Mock implementations
pub mod mock;

// Client
pub mod client;

// Re-exports
pub use client::MaspClient;
pub use keys::{DiversifiedAddress, FullViewingKey, SpendingKey};
pub use note::Note;
pub use proofs::{MembershipWitness, StoreId};
pub use traits::{
    Chain, ChainError, Indexer, IndexerError, InsertCommitmentResult, NoteCommitmentStore,
    NullifierError, NullifierSet, ProofBytes, ProofSystemError, ShieldRequest, ShieldResult,
    SpendPrivateInputs, SpendProver, SpendPublicInputs, SpendVerifier, StoreError, TransferRequest,
    TransferResult, UnshieldRequest, UnshieldResult,
};
pub use types::{Anchor, Commitment, Fr, Nullifier, TokenAddress};

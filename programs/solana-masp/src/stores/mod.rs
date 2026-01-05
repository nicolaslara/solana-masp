//! External store abstractions for MASP
//!
//! This module defines the interfaces for external state stores:
//! - **NullifierStore** - Tracks spent nullifiers (double-spend prevention)
//! - **CommitmentStore** - Tracks note commitments (Merkle tree)
//!
//! ## Implementations
//!
//! ### Simple On-Chain Store (`simple-onchain-store` feature)
//! Uses CPI to an external program for nullifiers and commitments.
//! The program ID is hardcoded and validated at runtime.
//! Used for testing before Light Protocol integration.
//!
//! ### Direct Store (default, no feature)
//! MASP handles nullifiers directly with PDAs.
//! Commitments are just logged for indexer to process.
//!
//! ### Light Protocol (`light-protocol` feature)
//! Production implementation using Light Protocol's compressed accounts.
//! Uses validity proofs to prevent double-spending without PDAs.

pub mod commitment_store;
pub mod nullifier_store;

#[cfg(feature = "simple-onchain-store")]
pub mod mock;

#[cfg(feature = "light-protocol")]
pub mod light_nullifier;

//! MASP program errors

use solana_program::program_error::ProgramError;
use thiserror::Error;

/// MASP-specific errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MaspError {
    /// Nullifier has already been spent (double-spend attempt)
    #[error("Nullifier already spent")]
    NullifierAlreadySpent,

    /// Anchor (Merkle root) is not in valid root history
    #[error("Invalid anchor: not in recent root history")]
    InvalidAnchor,

    /// ZK proof verification failed
    #[error("Proof verification failed")]
    ProofVerificationFailed,

    /// Invalid proof data (wrong size, malformed)
    #[error("Invalid proof data")]
    InvalidProofData,

    /// Invalid public inputs
    #[error("Invalid public inputs")]
    InvalidPublicInputs,

    /// Commitment tree is full
    #[error("Commitment tree is full")]
    TreeFull,

    /// Invalid account owner
    #[error("Invalid account owner")]
    InvalidOwner,

    /// Account not initialized
    #[error("Account not initialized")]
    NotInitialized,

    /// Account already initialized
    #[error("Account already initialized")]
    AlreadyInitialized,

    /// Invalid instruction discriminator
    #[error("Invalid instruction")]
    InvalidInstruction,

    /// Arithmetic overflow
    #[error("Arithmetic overflow")]
    Overflow,

    /// Invalid VK (verification key parsing failed)
    #[error("Invalid verification key")]
    InvalidVk,

    /// Buffer incomplete (proof not fully uploaded)
    #[error("Proof buffer incomplete")]
    BufferIncomplete,

    /// Invalid account data (deserialization failed)
    #[error("Invalid account data")]
    InvalidAccountData,

    /// Authority mismatch
    #[error("Invalid authority")]
    InvalidAuthority,

    /// State inconsistency (e.g., leaf count mismatch)
    #[error("State inconsistency detected")]
    StateInconsistency,
}

impl From<MaspError> for ProgramError {
    fn from(e: MaspError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

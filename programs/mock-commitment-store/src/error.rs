//! Mock Commitment Store errors

use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Mock Commitment Store errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum StoreError {
    /// Nullifier has already been spent
    #[error("Nullifier already spent")]
    NullifierAlreadySpent,

    /// Commitment tree is full
    #[error("Tree is full")]
    TreeFull,

    /// Invalid anchor (not in recent history)
    #[error("Invalid anchor")]
    InvalidAnchor,

    /// Account not initialized
    #[error("Account not initialized")]
    NotInitialized,

    /// Account already initialized
    #[error("Account already initialized")]
    AlreadyInitialized,

    /// Invalid account data
    #[error("Invalid account data")]
    InvalidAccountData,

    /// Invalid authority
    #[error("Invalid authority")]
    InvalidAuthority,
}

impl From<StoreError> for ProgramError {
    fn from(e: StoreError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

//! Commitment Store abstraction
//!
//! Provides a unified interface for note commitment storage (Merkle tree),
//! with different implementations selected at compile time via feature flags.

use solana_program::{account_info::AccountInfo, msg, program_error::ProgramError};

/// Insert a commitment into the store
#[cfg(feature = "simple-onchain-store")]
pub fn insert<'info>(
    store_program: &AccountInfo<'info>,
    store_state: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    commitment: [u8; 32],
) -> Result<(), ProgramError> {
    use crate::stores::mock::{self, MOCK_STORE_PROGRAM_ID};

    // Validate store program matches hardcoded ID
    if store_program.key != &MOCK_STORE_PROGRAM_ID {
        msg!(
            "Invalid store program: expected {}, got {}",
            MOCK_STORE_PROGRAM_ID,
            store_program.key
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    mock::insert_commitment(store_program, authority, store_state, commitment)
}

/// No-op version when simple-onchain-store is disabled
#[cfg(not(feature = "simple-onchain-store"))]
pub fn insert(_authority: &AccountInfo, commitment: [u8; 32]) -> Result<(), ProgramError> {
    msg!("CommitmentStore: Commitment logged: {:?}", commitment);
    Ok(())
}

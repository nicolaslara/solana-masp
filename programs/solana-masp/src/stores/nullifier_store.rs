//! Nullifier Store abstraction
//!
//! Provides a unified interface for nullifier tracking, with different
//! implementations selected at compile time via feature flags.

use solana_program::{account_info::AccountInfo, msg, program_error::ProgramError, pubkey::Pubkey};

/// Derive the nullifier PDA address (for mock store)
#[cfg(feature = "simple-onchain-store")]
pub fn derive_pda(nullifier: &[u8; 32]) -> (Pubkey, u8) {
    use crate::stores::mock::MOCK_STORE_PROGRAM_ID;
    Pubkey::find_program_address(&[b"nullifier", nullifier], &MOCK_STORE_PROGRAM_ID)
}

/// Derive the nullifier PDA address (for direct/MASP)
#[cfg(not(feature = "simple-onchain-store"))]
pub fn derive_pda(nullifier: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier], program_id)
}

/// Insert a nullifier via CPI to mock store
#[cfg(feature = "simple-onchain-store")]
pub fn insert<'info>(
    store_program: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    nullifier_pda: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    nullifier: [u8; 32],
) -> Result<(), ProgramError> {
    use crate::stores::mock::{self, MOCK_STORE_PROGRAM_ID};

    // Verify PDA is derived from the store's program ID
    let (expected_pda, _) = derive_pda(&nullifier);
    if nullifier_pda.key != &expected_pda {
        msg!("Invalid nullifier PDA (expected mock store PDA)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate store program matches hardcoded ID
    if store_program.key != &MOCK_STORE_PROGRAM_ID {
        msg!(
            "Invalid store program: expected {}, got {}",
            MOCK_STORE_PROGRAM_ID,
            store_program.key
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    mock::insert_nullifier(
        store_program,
        authority,
        nullifier_pda,
        system_program,
        nullifier,
    )
}

/// Insert a nullifier directly (MASP handles PDAs)
#[cfg(not(feature = "simple-onchain-store"))]
pub fn insert<'info>(
    authority: &AccountInfo<'info>,
    nullifier_pda: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    nullifier: [u8; 32],
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    use crate::state::NullifierAccount;
    use borsh::BorshSerialize;
    use solana_program::{program::invoke_signed, rent::Rent, sysvar::Sysvar};

    msg!("NullifierStore: Creating nullifier PDA directly");

    // Verify PDA
    let seeds: &[&[u8]] = &[b"nullifier", &nullifier];
    let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);

    if nullifier_pda.key != &expected_pda {
        msg!("Invalid nullifier PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check if already spent
    if !nullifier_pda.data_is_empty() {
        msg!("Nullifier already spent");
        return Err(crate::error::MaspError::NullifierAlreadySpent.into());
    }

    // Create nullifier account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(NullifierAccount::SIZE);
    let seeds_with_bump: &[&[u8]] = &[b"nullifier", &nullifier, &[bump]];

    invoke_signed(
        &crate::instructions::create_account_instruction(
            authority.key,
            nullifier_pda.key,
            lamports,
            NullifierAccount::SIZE as u64,
            program_id,
        ),
        &[
            authority.clone(),
            nullifier_pda.clone(),
            system_program.clone(),
        ],
        &[seeds_with_bump],
    )?;

    // Initialize nullifier account
    let nf_account = NullifierAccount::new(nullifier, 0);
    nf_account.serialize(&mut *nullifier_pda.try_borrow_mut_data()?)?;

    Ok(())
}

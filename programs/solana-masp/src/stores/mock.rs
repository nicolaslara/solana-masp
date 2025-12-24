//! Mock commitment store implementation
//!
//! CPI helpers for calling the simple-onchain-store program.
//! This is used for local testing before integrating with Light Protocol.

#![cfg(feature = "simple-onchain-store")]

use solana_program::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// Mock commitment store program ID (generated with fixed keypair)
/// Deploy with: `solana program deploy --program-id programs/simple-onchain-store/mock-store-keypair.json`
pub const MOCK_STORE_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("9QnviXVA1YyeaL9raJU7AaP2i6hkXvgB7vw5j9KvrxZc");

/// System program ID
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]);

/// Instruction discriminators (must match simple-onchain-store program)
mod discriminators {
    pub const INSERT_COMMITMENT: u8 = 1;
    pub const INSERT_NULLIFIER: u8 = 2;
}

/// Get the store state PDA
pub fn get_store_state_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"mock_store", b"state"], &MOCK_STORE_PROGRAM_ID)
}

/// Get a nullifier PDA
pub fn get_nullifier_pda(nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier], &MOCK_STORE_PROGRAM_ID)
}

/// CPI to insert a commitment into the mock store
pub fn insert_commitment<'a>(
    store_program: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    store_state: &AccountInfo<'a>,
    commitment: [u8; 32],
) -> Result<(), ProgramError> {
    msg!("MockStore CPI: InsertCommitment {:?}...", &commitment[..4]);

    let mut data = Vec::with_capacity(33);
    data.push(discriminators::INSERT_COMMITMENT);
    data.extend_from_slice(&commitment);

    let instruction = Instruction {
        program_id: *store_program.key,
        accounts: vec![
            AccountMeta::new(*authority.key, true),
            AccountMeta::new(*store_state.key, false),
        ],
        data,
    };

    invoke(
        &instruction,
        &[
            authority.clone(),
            store_state.clone(),
            store_program.clone(),
        ],
    )?;

    msg!("MockStore CPI: InsertCommitment success");
    Ok(())
}

/// CPI to insert a nullifier into the mock store (mark as spent)
///
/// Fails if nullifier already exists (double-spend prevention).
pub fn insert_nullifier<'a>(
    store_program: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    nullifier_pda: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    nullifier: [u8; 32],
) -> Result<(), ProgramError> {
    msg!("MockStore CPI: InsertNullifier {:?}...", &nullifier[..4]);

    let mut data = Vec::with_capacity(33);
    data.push(discriminators::INSERT_NULLIFIER);
    data.extend_from_slice(&nullifier);

    let instruction = Instruction {
        program_id: *store_program.key,
        accounts: vec![
            AccountMeta::new(*authority.key, true),
            AccountMeta::new(*nullifier_pda.key, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    };

    invoke(
        &instruction,
        &[
            authority.clone(),
            nullifier_pda.clone(),
            system_program.clone(),
            store_program.clone(),
        ],
    )?;

    msg!("MockStore CPI: InsertNullifier success");
    Ok(())
}

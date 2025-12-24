//! Mock Commitment Store instruction handlers
//!
//! ⚠️ **FOR LOCAL TESTING ONLY**
//!
//! These instructions mirror the Light Protocol CPI interface, allowing
//! MASP to swap between this mock and Light Protocol.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

use crate::error::StoreError;
use crate::state::{NullifierAccount, StoreState};

// =============================================================================
// Instruction Discriminators
// =============================================================================

pub const IX_INITIALIZE: u8 = 0;
pub const IX_INSERT_COMMITMENT: u8 = 1;
pub const IX_INSERT_NULLIFIER: u8 = 2;

// =============================================================================
// System Program Helper
// =============================================================================

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]);

fn create_account_instruction(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> solana_program::instruction::Instruction {
    solana_program::instruction::Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            solana_program::instruction::AccountMeta::new(*from_pubkey, true),
            solana_program::instruction::AccountMeta::new(*to_pubkey, true),
        ],
        data: {
            let mut data = vec![0u8; 4 + 8 + 8 + 32];
            data[0..4].copy_from_slice(&0u32.to_le_bytes());
            data[4..12].copy_from_slice(&lamports.to_le_bytes());
            data[12..20].copy_from_slice(&space.to_le_bytes());
            data[20..52].copy_from_slice(owner.as_ref());
            data
        },
    }
}

// =============================================================================
// Initialize
// =============================================================================

/// Initialize the mock commitment store
///
/// Accounts:
/// 0. [signer] Authority (pays for account creation)
/// 1. [writable] Store state PDA (to be created)
/// 2. [] System program
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let store_state_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive store state PDA
    let (expected_pda, bump) = Pubkey::find_program_address(StoreState::SEEDS, program_id);

    if store_state_account.key != &expected_pda {
        msg!("Invalid store state PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check if already initialized
    if !store_state_account.data_is_empty() {
        return Err(StoreError::AlreadyInitialized.into());
    }

    // Create store state account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(StoreState::SIZE);
    let seeds_with_bump: &[&[u8]] = &[b"mock_store", b"state", &[bump]];

    invoke_signed(
        &create_account_instruction(
            authority.key,
            store_state_account.key,
            lamports,
            StoreState::SIZE as u64,
            program_id,
        ),
        &[
            authority.clone(),
            store_state_account.clone(),
            system_program.clone(),
        ],
        &[seeds_with_bump],
    )?;

    // Initialize store state
    let store_state = StoreState::new(*authority.key);
    store_state.serialize(&mut *store_state_account.try_borrow_mut_data()?)?;

    msg!(
        "MockCommitmentStore: Initialized with authority {}",
        authority.key
    );
    Ok(())
}

// =============================================================================
// Insert Commitment
// =============================================================================

/// Insert commitment instruction data
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct InsertCommitmentData {
    /// The commitment to insert
    pub commitment: [u8; 32],
}

/// Insert a commitment into the tree
///
/// ⚠️ NAIVE IMPLEMENTATION: Just updates root without real Merkle tree.
/// For testing, we trust the caller to provide correct roots.
/// In production, Light Protocol computes roots correctly.
///
/// Accounts:
/// 0. [signer] Authority
/// 1. [writable] Store state PDA
pub fn process_insert_commitment(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let store_state_account = next_account_info(accounts_iter)?;

    // Parse instruction data
    let insert_data = InsertCommitmentData::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify store state PDA
    let (expected_pda, _bump) = Pubkey::find_program_address(StoreState::SEEDS, program_id);

    if store_state_account.key != &expected_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Load store state
    let mut store_state = StoreState::try_from_slice(&store_state_account.data.borrow())
        .map_err(|_| StoreError::InvalidAccountData)?;

    // Check if full
    if store_state.is_full() {
        return Err(StoreError::TreeFull.into());
    }

    // NAIVE: Compute new root as hash of old root + commitment
    // In a real implementation, we'd update the Merkle tree properly.
    // For testing, this is sufficient to simulate root changes.
    let mut new_root = [0u8; 32];
    for i in 0..32 {
        new_root[i] = store_state.current_root[i] ^ insert_data.commitment[i];
    }

    // Update state
    store_state.update_root(new_root);
    store_state.leaf_count += 1;

    // Save
    store_state.serialize(&mut *store_state_account.try_borrow_mut_data()?)?;

    msg!(
        "MockCommitmentStore: Inserted commitment. Leaf count: {}",
        store_state.leaf_count
    );
    Ok(())
}

// =============================================================================
// Insert Nullifier
// =============================================================================

/// Insert nullifier instruction data
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct InsertNullifierData {
    /// The nullifier to mark as spent
    pub nullifier: [u8; 32],
}

/// Insert a nullifier (mark as spent)
///
/// Fails if nullifier already exists (double-spend prevention).
///
/// Accounts:
/// 0. [signer] Authority (pays for account creation)
/// 1. [writable] Nullifier PDA (to be created)
/// 2. [] System program
pub fn process_insert_nullifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let nullifier_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Parse instruction data
    let insert_data = InsertNullifierData::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive nullifier PDA
    let nullifier = &insert_data.nullifier;
    let seeds: &[&[u8]] = &[b"nullifier", nullifier];
    let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);

    if nullifier_account.key != &expected_pda {
        msg!("Invalid nullifier PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check if already spent
    if !nullifier_account.data_is_empty() {
        return Err(StoreError::NullifierAlreadySpent.into());
    }

    // Create nullifier account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(NullifierAccount::SIZE);
    let seeds_with_bump: &[&[u8]] = &[b"nullifier", nullifier, &[bump]];

    invoke_signed(
        &create_account_instruction(
            authority.key,
            nullifier_account.key,
            lamports,
            NullifierAccount::SIZE as u64,
            program_id,
        ),
        &[
            authority.clone(),
            nullifier_account.clone(),
            system_program.clone(),
        ],
        &[seeds_with_bump],
    )?;

    // Initialize nullifier account
    let nf_account = NullifierAccount::new(*nullifier, 0);
    nf_account.serialize(&mut *nullifier_account.try_borrow_mut_data()?)?;

    msg!("MockCommitmentStore: Nullifier inserted");
    Ok(())
}

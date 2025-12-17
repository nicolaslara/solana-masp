//! Solana MASP (Multi-Asset Shielded Pool) - SCAFFOLDING
//!
//! This is placeholder scaffolding. Architecture and design TBD.
//!
//! ## Instructions (Placeholder)
//!
//! 1. Shield - Deposit into shielded pool
//! 2. Transfer - Move value between shielded notes  
//! 3. Unshield - Withdraw to transparent address

// Solana's `entrypoint!` macro expands to cfg checks that trigger `unexpected_cfgs`
// warnings on newer Rust toolchains when building in a non-Solana context (e.g. `cargo test`).
// This is scaffolding code; we silence these warnings to keep test output clean.
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

// Instruction discriminators
const IX_SHIELD: u8 = 0;
const IX_TRANSFER: u8 = 1;
const IX_UNSHIELD: u8 = 2;

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        msg!("Error: Empty instruction data");
        return Err(ProgramError::InvalidInstructionData);
    }

    let discriminator = instruction_data[0];

    match discriminator {
        IX_SHIELD => {
            msg!("MASP: Shield (stub)");
            Ok(())
        }
        IX_TRANSFER => {
            msg!("MASP: Transfer (stub)");
            Ok(())
        }
        IX_UNSHIELD => {
            msg!("MASP: Unshield (stub)");
            Ok(())
        }
        _ => {
            msg!("Error: Unknown instruction: {}", discriminator);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

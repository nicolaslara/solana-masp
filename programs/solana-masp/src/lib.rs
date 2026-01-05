//! Solana MASP (Multi-Asset Shielded Pool)
//!
//! A privacy-preserving token pool using UltraPlonk ZK proofs.
//!
//! ## Overview
//!
//! The MASP allows users to:
//! - **Shield**: Deposit tokens into the shielded pool
//! - **Transfer**: Move value between shielded notes (private)
//! - **Unshield**: Withdraw tokens to a public address
//!
//! ## Architecture
//!
//! - **Circuits**: Shield, Transfer (N→M), Unshield (Noir + UltraPlonk)
//! - **State**: Commitment tree (Merkle accumulator) + nullifier set (PDAs)
//! - **Verification**: On-chain UltraPlonk verification via `ultraplonk-core`
//!
//! ## Instructions
//!
//! 0. Initialize - Create tree state
//! 1. InitProofBuffer - Create buffer for proof upload
//! 2. UploadChunk - Upload proof data in chunks
//! 3. Shield - Deposit with proof
//! 4. Transfer - Shielded transfer with proof
//! 5. Unshield - Withdraw with proof
//! 6. UpdateRoot - Update commitment tree root (LOCAL TESTING ONLY, feature-gated)
//!
//! ## Security Model
//!
//! See `docs/protocol-soundness.md` for the full security analysis.
//!
//! **Circuit proves (in ZK):**
//! - Commitment integrity (note hashes to public commitment)
//! - Nullifier derivation (from owner's secret key)
//! - Merkle membership (note is in the commitment tree)
//! - Balance conservation (inputs = outputs)
//!
//! **Chain enforces (on-chain):**
//! - Anchor validity (Merkle root in recent history)
//! - Nullifier uniqueness (no double-spends)
//! - Proof verification
//! - Token transfers (SPL)
//!
//! ## Proof System Configuration
//!
//! The program supports multiple proof systems, selected at compile time:
//!
//! ```toml
//! # UltraPlonk (default): ~2KB proofs, ~500K-1M CU, no trusted setup
//! cargo build-sbf --features ultraplonk
//!
//! # Groth16: ~192B proofs, ~81K CU, requires trusted setup
//! cargo build-sbf --features groth16
//! ```
//!
//! See `verify.rs` for proof system implementation details.

// Silence cfg warnings from solana-program entrypoint macro
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

pub mod error;
pub mod inputs;
pub mod instructions;
pub mod state;
pub mod stores;
pub mod verify;

use instructions::*;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Program entrypoint
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        msg!("Error: Empty instruction data");
        return Err(ProgramError::InvalidInstructionData);
    }

    let discriminator = instruction_data[0];
    let data = &instruction_data[1..];

    match discriminator {
        IX_INITIALIZE => {
            msg!("MASP: Initialize");
            process_initialize(program_id, accounts, data)
        }
        IX_INIT_PROOF_BUFFER => {
            msg!("MASP: InitProofBuffer");
            process_init_proof_buffer(program_id, accounts, data)
        }
        IX_UPLOAD_CHUNK => {
            msg!("MASP: UploadChunk");
            process_upload_chunk(accounts, data)
        }
        IX_SHIELD => {
            msg!("MASP: Shield");
            process_shield(program_id, accounts, data)
        }
        IX_TRANSFER => {
            msg!("MASP: Transfer");
            process_transfer(program_id, accounts, data)
        }
        IX_UNSHIELD => {
            msg!("MASP: Unshield");
            process_unshield(program_id, accounts, data)
        }
        #[cfg(feature = "local-testing")]
        IX_UPDATE_ROOT => {
            msg!("MASP[local-testing]: UpdateRoot");
            process_update_root(program_id, accounts, data)
        }
        IX_POST_CIPHERTEXTS => {
            // Note: No msg! here to save CUs - this is a high-frequency data carrier
            process_post_ciphertexts(data)
        }
        _ => {
            msg!("Error: Unknown instruction: {}", discriminator);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

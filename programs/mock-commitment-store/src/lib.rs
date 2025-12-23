//! Mock State Stores (Commitment Store + Nullifier Set)
//!
//! ⚠️ **FOR LOCAL TESTING ONLY - NOT PRODUCTION SAFE**
//!
//! This program provides simple on-chain state storage for MASP testing.
//! In production, use Light Protocol instead (200x cheaper).
//!
//! ## Two Logical Stores in One Program
//!
//! For testing simplicity, this program implements BOTH:
//!
//! 1. **NoteCommitmentStore** - Stores note commitments
//!    - `insert_commitment()` - Add to Merkle tree
//!    - `get_root()` - Get current root
//!    - `is_valid_anchor()` - Check if anchor is in history
//!    - Mock: Naive on-chain tree
//!    - Production: Light Protocol with validity proofs
//!
//! 2. **NullifierSet** - Stores spent nullifiers
//!    - `insert_nullifier()` - Mark as spent (fails if exists)
//!    - `is_nullifier_spent()` - Check if spent
//!    - Mock: PDA per nullifier (existence = spent)
//!    - Production: Light Protocol with **non-membership proofs**
//!
//! ```text
//!                     ┌─────────────────────────────────────┐
//!                     │     Mock State Stores Program       │
//!                     │  (testing only - combines both)     │
//!                     └───────────────┬─────────────────────┘
//!                                     │
//!              ┌──────────────────────┼──────────────────────┐
//!              ▼                                             ▼
//!   ┌────────────────────┐                       ┌────────────────────┐
//!   │ NoteCommitmentStore│                       │   NullifierSet     │
//!   │ - Merkle tree      │                       │ - PDAs (existence) │
//!   │ - Anchor history   │                       │                    │
//!   └────────────────────┘                       └────────────────────┘
//! ```
//!
//! ## ⚠️ Ciphertexts are NOT in this store!
//!
//! Ciphertexts are stored as **transaction calldata** (ledger history), NOT in
//! external stores like Light Protocol:
//!
//! ```text
//! Tx A: shield/transfer instruction includes ciphertext in calldata
//!       → permanently stored in ledger history (archives)
//!       → ct_hash binds proof to this calldata
//!
//! Indexer: Observes ledger, indexes ciphertexts for efficient lookup
//!          → get_ciphertext_by_hash(), get_ciphertext_for_output()
//! ```
//!
//! This ensures:
//! 1. **Wallet recovery** - Replay ledger to find all ciphertexts (no indexer needed)
//! 2. **Censorship resistance** - Ciphertexts are in permanent ledger history
//! 3. **Auditability** - All data needed to verify state is on-chain
//!
//! ## Why Separate in Production?
//!
//! In production (Light Protocol), commitment/nullifier stores are separate because:
//! - **Different proof types**: Membership vs non-membership proofs
//! - **Different tree structures**: May use different compressed account trees
//! - **Independent scaling**: Nullifier set grows faster than commitment tree
//!
//! ## Limitations (vs Light Protocol)
//!
//! - **Cost**: ~100x more expensive per operation
//! - **Scalability**: Limited by account size constraints
//! - **No real proofs**: Uses PDA existence, not ZK proofs
//!
//! ## Instructions
//!
//! 0. Initialize - Create store state
//! 1. InsertCommitment - Add commitment to tree (NoteCommitmentStore)
//! 2. InsertNullifier - Mark nullifier as spent (NullifierSet)

// Silence cfg warnings from solana-program entrypoint macro
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

pub mod error;
pub mod instructions;
pub mod state;

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
            msg!("MockCommitmentStore: Initialize");
            process_initialize(program_id, accounts, data)
        }
        IX_INSERT_COMMITMENT => {
            msg!("MockCommitmentStore: InsertCommitment");
            process_insert_commitment(program_id, accounts, data)
        }
        IX_INSERT_NULLIFIER => {
            msg!("MockCommitmentStore: InsertNullifier");
            process_insert_nullifier(program_id, accounts, data)
        }
        // Note: No store_ciphertext instruction - ciphertexts are stored as
        // transaction calldata in the MASP program's shield/transfer instructions,
        // not in external stores. The indexer observes the ledger to index them.
        _ => {
            msg!("Error: Unknown instruction: {}", discriminator);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

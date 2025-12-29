//! MASP Protocol Types and Constants
//!
//! This crate provides the shared protocol-level types used by both the
//! on-chain Solana program and the off-chain client. It is `no_std` compatible
//! for BPF deployment.
//!
//! ## Contents
//!
//! - **Domain tags**: Unique constants for hash domain separation
//! - **Instruction data**: Borsh-serializable structs for Shield/Transfer/Unshield
//! - **Public input layouts**: Constants defining PI counts and field ordering

#![cfg_attr(not(feature = "std"), no_std)]

mod domain;
mod instructions;
mod public_inputs;

pub use domain::DomainTag;
pub use instructions::{ShieldData, TransferData, UnshieldData};
pub use public_inputs::{
    ShieldPublicInputs, TransferPublicInputs, UnshieldPublicInputs, MAX_INPUTS, MAX_OUTPUTS,
};

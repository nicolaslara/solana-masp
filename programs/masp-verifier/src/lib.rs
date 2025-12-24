//! UltraPlonk Verifier for MASP Circuits
//!
//! This program verifies UltraPlonk proofs for MASP (Shield, Transfer, Unshield).
//!
//! ## Instructions
//!
//! 0. InitProofBuffer - Create account to store proof  
//! 1. UploadChunk - Upload proof data in chunks
//! 2. Verify - Verify the proof and create receipt PDA
//!
//! ## Receipt PDAs
//!
//! After successful verification, creates a receipt PDA:
//! `["receipt", circuit_type, keccak(public_inputs)]`
//!
//! Other programs (like MASP) can check this PDA exists to confirm
//! a proof was verified without re-running verification.
//!
//! ## Circuits
//!
//! - 0: Shield (4 public inputs)
//! - 1: Transfer (13 public inputs)  
//! - 2: Unshield (8 public inputs)

extern crate alloc;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

// Entry point
entrypoint!(process_instruction);

// ============================================================================
// Embedded VKs - Pre-converted to Solidity format at compile time
// ============================================================================

/// Shield circuit VK (4 public inputs)
const VK_SHIELD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_shield.bin"));
/// Transfer circuit VK (13 public inputs)
const VK_TRANSFER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_transfer.bin"));
/// Unshield circuit VK (8 public inputs)
const VK_UNSHIELD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_unshield.bin"));

/// Circuit types
pub const CIRCUIT_SHIELD: u8 = 0;
pub const CIRCUIT_TRANSFER: u8 = 1;
pub const CIRCUIT_UNSHIELD: u8 = 2;

/// Get VK bytes for circuit type
fn get_vk_for_circuit(circuit_type: u8) -> Option<&'static [u8]> {
    match circuit_type {
        CIRCUIT_SHIELD => Some(VK_SHIELD),
        CIRCUIT_TRANSFER => Some(VK_TRANSFER),
        CIRCUIT_UNSHIELD => Some(VK_UNSHIELD),
        _ => None,
    }
}

// ============================================================================
// Constants
// ============================================================================

/// UltraPlonk proof size
pub const PROOF_SIZE: usize = 2144;

/// Maximum chunk size for uploads (to fit in tx)
pub const MAX_CHUNK_SIZE: usize = 900;

/// Header size in proof buffer: status (1) + circuit_type (1) + proof_len (2) + pi_count (1)
pub const BUFFER_HEADER_SIZE: usize = 5;

/// Maximum number of public inputs supported
pub const MAX_PUBLIC_INPUTS: usize = 32;

/// Receipt PDA seed
pub const RECEIPT_SEED: &[u8] = b"receipt";

// ============================================================================
// Instruction Discriminators
// ============================================================================

/// Initialize proof buffer account
const IX_INIT_BUFFER: u8 = 0;
/// Upload a chunk of proof data
const IX_UPLOAD_CHUNK: u8 = 1;
/// Verify the proof from buffer
const IX_VERIFY: u8 = 2;

// ============================================================================
// Entry Point
// ============================================================================

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
        IX_INIT_BUFFER => process_init_buffer(program_id, accounts, data),
        IX_UPLOAD_CHUNK => process_upload_chunk(accounts, data),
        IX_VERIFY => process_verify(accounts, data),
        _ => {
            msg!("Error: Unknown instruction: {}", discriminator);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

// ============================================================================
// Init Buffer Instruction
// ============================================================================

/// Initialize a proof buffer account
///
/// Accounts:
/// 0. [signer] Payer
/// 1. [writable] Buffer account (must be created by System program)
///
/// Data:
/// - [0]: Circuit type (0=Shield, 1=Transfer, 2=Unshield)
/// - [1]: Number of public inputs (u8)
fn process_init_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let _payer = next_account_info(accounts_iter)?;
    let buffer = next_account_info(accounts_iter)?;

    // Verify buffer is owned by this program
    if buffer.owner != program_id {
        msg!("Error: Buffer not owned by program");
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 2 {
        msg!("Error: Missing circuit_type or pi_count");
        return Err(ProgramError::InvalidInstructionData);
    }

    let circuit_type = data[0];
    let pi_count = data[1];

    // Validate circuit type
    if get_vk_for_circuit(circuit_type).is_none() {
        msg!("Error: Invalid circuit type: {}", circuit_type);
        return Err(ProgramError::InvalidInstructionData);
    }

    if pi_count as usize > MAX_PUBLIC_INPUTS {
        msg!(
            "Error: Too many public inputs: {} > {}",
            pi_count,
            MAX_PUBLIC_INPUTS
        );
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut buffer_data = buffer.try_borrow_mut_data()?;

    // Initialize header: status=0, circuit_type, proof_len=0, pi_count
    buffer_data[0] = 0; // status: incomplete
    buffer_data[1] = circuit_type;
    buffer_data[2] = 0; // proof_len low byte
    buffer_data[3] = 0; // proof_len high byte
    buffer_data[4] = pi_count;

    msg!("Buffer initialized: circuit={}, pi_count={}", circuit_type, pi_count);
    Ok(())
}

// ============================================================================
// Upload Chunk Instruction
// ============================================================================

/// Upload a chunk of proof data
///
/// Accounts:
/// 0. [writable] Buffer account
///
/// Data:
/// - [0..2]: Offset (u16, little-endian)
/// - [2..]: Chunk data
fn process_upload_chunk(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let buffer = next_account_info(accounts_iter)?;

    if data.len() < 2 {
        msg!("Error: Missing offset");
        return Err(ProgramError::InvalidInstructionData);
    }

    let offset = u16::from_le_bytes([data[0], data[1]]) as usize;
    let chunk = &data[2..];

    if chunk.len() > MAX_CHUNK_SIZE {
        msg!(
            "Error: Chunk too large: {} > {}",
            chunk.len(),
            MAX_CHUNK_SIZE
        );
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut buffer_data = buffer.try_borrow_mut_data()?;

    // Data starts after header
    let data_start = BUFFER_HEADER_SIZE + offset;
    let data_end = data_start + chunk.len();

    if data_end > buffer_data.len() {
        msg!("Error: Chunk would overflow buffer");
        return Err(ProgramError::InvalidInstructionData);
    }

    // Copy chunk
    buffer_data[data_start..data_end].copy_from_slice(chunk);

    // Update proof length (at bytes 2-3, after status and circuit_type)
    let new_len = offset + chunk.len();
    buffer_data[2] = (new_len & 0xff) as u8;
    buffer_data[3] = ((new_len >> 8) & 0xff) as u8;

    msg!("Uploaded {} bytes at offset {}", chunk.len(), offset);
    Ok(())
}

// ============================================================================
// Verify Instruction
// ============================================================================

/// Verify the proof from the buffer and create receipt PDA
///
/// Accounts:
/// 0. [signer] Payer (for receipt creation)
/// 1. [readable] Buffer account with proof
/// 2. [writable] Receipt PDA (derived from circuit_type + keccak(public_inputs))
/// 3. [] System program
///
/// Data:
/// - (empty) All data is read from the buffer
fn process_verify(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    use alloc::boxed::Box;
    use ultraplonk_core::field::FrLimbs;
    use ultraplonk_core::widgets::ProofEvaluationsLimbs;
    use ultraplonk_core::{
        verify, verify_with_public_inputs_limbs, verify_with_public_inputs_limbs_and_evals, Fr,
        Proof, VerificationKey,
    };

    let accounts_iter = &mut accounts.iter();
    // For now, just buffer is required. Receipt creation can be added later.
    let payer = next_account_info(accounts_iter)?;
    let buffer = next_account_info(accounts_iter)?;
    // Optional accounts for receipt (not used yet)
    let receipt = accounts_iter.next();
    let system_program = accounts_iter.next();

    msg!("MASP Verifier: Starting");

    let buffer_data = buffer.try_borrow_data()?;

    // Read header (new format with circuit_type)
    let circuit_type = buffer_data[1];
    let proof_len = u16::from_le_bytes([buffer_data[2], buffer_data[3]]) as usize;
    let pi_count = buffer_data[4] as usize;

    msg!("Proof buffer data size: {} bytes", proof_len);
    msg!("Public inputs: {}", pi_count);

    // Validate
    if pi_count > MAX_PUBLIC_INPUTS {
        msg!("Error: Too many public inputs");
        return Err(ProgramError::InvalidInstructionData);
    }
    // IMPORTANT: Do NOT pass public inputs via instruction data. With 32 public inputs this would
    // exceed the Solana legacy tx size limit (1232 bytes). Instead, we store:
    //   buffer = [header][public_inputs (32*pi_count)][proof (PROOF_SIZE)]
    // and parse both from the buffer.
    let pi_bytes = pi_count * 32;
    if proof_len < pi_bytes + PROOF_SIZE {
        msg!("Error: Buffer missing PI prefix and/or proof bytes");
        return Err(ProgramError::InvalidInstructionData);
    }

    // Parse public inputs (canonical big-endian) into fixed-size array.
    // Use stack array instead of Vec to avoid heap allocation.
    let mut public_inputs: [Fr; MAX_PUBLIC_INPUTS] = [[0u8; 32]; MAX_PUBLIC_INPUTS];
    for i in 0..pi_count {
        let start = BUFFER_HEADER_SIZE + i * 32;
        public_inputs[i].copy_from_slice(&buffer_data[start..start + 32]);
    }

    // Proof body is always fixed-size (2144 bytes). The buffer may optionally include extra bytes
    // after the proof body:
    // - PI Montgomery limbs (32 * pi_count)
    // - Evals Montgomery limbs (41 * 32)
    let proof_start = BUFFER_HEADER_SIZE + pi_bytes;
    let proof_end = proof_start + PROOF_SIZE;
    if proof_end > buffer_data.len() {
        msg!("Error: Proof extends beyond buffer");
        return Err(ProgramError::InvalidInstructionData);
    }
    let proof_data = &buffer_data[proof_start..proof_end];

    // Get VK for circuit type
    let vk_bytes = get_vk_for_circuit(circuit_type).ok_or_else(|| {
        msg!("Error: Invalid circuit type: {}", circuit_type);
        ProgramError::InvalidInstructionData
    })?;

    // Parse VK from pre-converted Solidity format (zero-copy)
    let vk = VerificationKey::from_onchain_bytes(vk_bytes).map_err(|e| {
        msg!("Error parsing VK: {:?}", e);
        ProgramError::InvalidAccountData
    })?;

    // Parse proof (zero-copy)
    let proof = Proof::from_bytes(proof_data).map_err(|e| {
        msg!("Error parsing proof: {:?}", e);
        ProgramError::InvalidAccountData
    })?;

    // Optional optimization: if the buffer includes PI limbs and eval limbs in Montgomery form,
    // use them to avoid on-chain Montgomery conversions.
    let eval_bytes = 41 * 32;
    let has_pi_limbs = proof_len >= (pi_bytes + PROOF_SIZE + pi_bytes);
    let has_eval_limbs = proof_len >= (pi_bytes + PROOF_SIZE + pi_bytes + eval_bytes);

    let pi_limbs_box: Option<Box<[FrLimbs; MAX_PUBLIC_INPUTS]>> = if has_pi_limbs && pi_count > 0 {
        let pi_mont_start = proof_end;
        let pi_mont_end = pi_mont_start + pi_bytes;
        if pi_mont_end > buffer_data.len() {
            msg!("Error: PI limbs extend beyond buffer");
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut out = Box::new([FrLimbs::ZERO; MAX_PUBLIC_INPUTS]);
        for i in 0..pi_count {
            let mut raw = [0u8; 32];
            let start = pi_mont_start + i * 32;
            raw.copy_from_slice(&buffer_data[start..start + 32]);
            out[i] = FrLimbs::from_raw_bytes(&raw);
        }
        Some(out)
    } else {
        None
    };

    let evals_box: Option<Box<ProofEvaluationsLimbs>> = if has_eval_limbs {
        let evals_start = proof_end + pi_bytes;
        let evals_end = evals_start + eval_bytes;
        if evals_end > buffer_data.len() {
            msg!("Error: Evals limbs extend beyond buffer");
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut all = Box::new([FrLimbs::ZERO; 41]);
        for i in 0..41 {
            let mut raw = [0u8; 32];
            let start = evals_start + i * 32;
            raw.copy_from_slice(&buffer_data[start..start + 32]);
            all[i] = FrLimbs::from_raw_bytes(&raw);
        }
        Some(Box::new(ProofEvaluationsLimbs::from_all_evaluations(&*all)))
    } else {
        None
    };

    // Verify - pass slice of actual public inputs
    msg!("Running verification...");
    let result = if let (Some(pi_limbs), Some(evals)) = (pi_limbs_box.as_ref(), evals_box.as_ref())
    {
        verify_with_public_inputs_limbs_and_evals(
            &vk,
            &proof,
            &public_inputs[..pi_count],
            &pi_limbs[..pi_count],
            evals,
        )
        .map_err(|e| {
            msg!("Verification error: {:?}", e);
            ProgramError::InvalidAccountData
        })?
    } else if let Some(pi_limbs) = pi_limbs_box.as_ref() {
        verify_with_public_inputs_limbs(
            &vk,
            &proof,
            &public_inputs[..pi_count],
            &pi_limbs[..pi_count],
        )
        .map_err(|e| {
            msg!("Verification error: {:?}", e);
            ProgramError::InvalidAccountData
        })?
    } else {
        verify(&vk, &proof, &public_inputs[..pi_count]).map_err(|e| {
            msg!("Verification error: {:?}", e);
            ProgramError::InvalidAccountData
        })?
    };

    if result {
        msg!("✓ Proof verified! circuit={}", circuit_type);
        
        // TODO: Create receipt PDA for MASP to check
        // For now, just return success. MASP will call this via CPI
        // and check the return value.
        let _ = (payer, receipt, system_program); // silence unused warnings
        
        Ok(())
    } else {
        msg!("✗ Proof verification failed");
        Err(ProgramError::InvalidAccountData)
    }
}

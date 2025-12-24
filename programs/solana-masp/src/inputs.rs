//! Circuit input extraction
//!
//! This module provides unified extraction of public inputs from either:
//! - **Buffer** (UltraPlonk): PIs are read directly from the proof buffer
//! - **Instruction data** (Mock/Groth16): PIs are read from instruction data
//!
//! The key insight is that for buffer mode, we read the PIs from the buffer
//! and use them for BOTH state updates and verification. This eliminates
//! redundant validation since we're using the same bytes for everything.
//!
//! ## Security Model
//!
//! - **Buffer mode**: The buffer contains PIs that were used to generate the proof.
//!   If an attacker modifies the PIs, the proof will fail to verify.
//!   We use the buffer PIs for state updates, ensuring consistency.
//!
//! - **Inline mode**: Instruction data is the source of truth. The client must
//!   ensure the proof was generated with matching PIs.

use solana_program::{account_info::AccountInfo, program_error::ProgramError};

use crate::instructions::{ShieldData, TransferData, UnshieldData};
use crate::verify::ProofSystem;
use crate::verify::CURRENT_PROOF_SYSTEM;

/// Buffer header size (verifier format)
/// [status(1), circuit_type(1), proof_len(2), pi_count(1)]
const BUFFER_HEADER_SIZE: usize = 5;

// =============================================================================
// Shield Inputs
// =============================================================================

/// Extracted public inputs for Shield circuit
#[derive(Debug, Clone)]
pub struct ShieldInputs {
    /// Note commitment
    pub commitment: [u8; 32],
    /// Asset identifier
    pub asset_id: [u8; 32],
    /// Amount (extracted from 32-byte field)
    pub amount: u64,
    /// Ciphertext hash
    pub ct_hash: [u8; 32],
}

impl ShieldInputs {
    /// Number of public inputs for Shield circuit
    pub const PI_COUNT: usize = 4;

    /// Extract shield inputs from either buffer or instruction data
    /// based on the current proof system.
    pub fn extract(
        proof_buffer: &AccountInfo,
        shield_data: &ShieldData,
    ) -> Result<Self, ProgramError> {
        match CURRENT_PROOF_SYSTEM {
            ProofSystem::UltraPlonk => Self::from_buffer(proof_buffer),
            _ => Self::from_data(shield_data),
        }
    }

    /// Extract from proof buffer's public inputs section
    fn from_buffer(proof_buffer: &AccountInfo) -> Result<Self, ProgramError> {
        let data = proof_buffer.try_borrow_data()?;

        // Validate we have enough data
        let expected_size = BUFFER_HEADER_SIZE + Self::PI_COUNT * 32;
        if data.len() < expected_size {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse PIs from buffer
        let mut offset = BUFFER_HEADER_SIZE;

        let commitment: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        let asset_id: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        // Amount is stored as 32-byte big-endian field, value in last 8 bytes
        let amount_bytes: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let amount = u64::from_be_bytes(
            amount_bytes[24..32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        offset += 32;

        let ct_hash: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        Ok(Self {
            commitment,
            asset_id,
            amount,
            ct_hash,
        })
    }

    /// Extract from instruction data
    fn from_data(shield_data: &ShieldData) -> Result<Self, ProgramError> {
        Ok(Self {
            commitment: shield_data.commitment,
            asset_id: shield_data.asset_id,
            amount: shield_data.amount,
            ct_hash: shield_data.ct_hash,
        })
    }

    /// Convert to public inputs array for inline verification
    pub fn to_public_inputs(&self) -> [[u8; 32]; 4] {
        let mut amount_bytes = [0u8; 32];
        amount_bytes[24..32].copy_from_slice(&self.amount.to_be_bytes());

        [self.commitment, self.asset_id, amount_bytes, self.ct_hash]
    }
}

// =============================================================================
// Transfer Inputs
// =============================================================================

/// Extracted public inputs for Transfer circuit
#[derive(Debug, Clone)]
pub struct TransferInputs {
    /// Merkle root anchor
    pub anchor: [u8; 32],
    /// Nullifiers for spent notes
    pub nullifiers: [[u8; 32]; 3],
    /// Output commitments
    pub output_commitments: [[u8; 32]; 3],
    /// Number of input notes (1-3)
    pub input_count: u32,
    /// Number of output notes (1-3)
    pub output_count: u32,
    /// Ciphertext hashes for outputs
    pub ct_hashes: [[u8; 32]; 3],
    /// Transaction binding
    pub tx_binding: [u8; 32],
}

impl TransferInputs {
    /// Number of public inputs for Transfer circuit
    /// anchor(1) + nullifiers(3) + output_commitments(3) + input_count(1) +
    /// output_count(1) + ct_hashes(3) + tx_binding(1) = 13
    pub const PI_COUNT: usize = 13;

    /// Extract transfer inputs from either buffer or instruction data
    pub fn extract(
        proof_buffer: &AccountInfo,
        transfer_data: &TransferData,
    ) -> Result<Self, ProgramError> {
        match CURRENT_PROOF_SYSTEM {
            ProofSystem::UltraPlonk => Self::from_buffer(proof_buffer),
            _ => Self::from_data(transfer_data),
        }
    }

    /// Extract from proof buffer's public inputs section
    fn from_buffer(proof_buffer: &AccountInfo) -> Result<Self, ProgramError> {
        let data = proof_buffer.try_borrow_data()?;

        let expected_size = BUFFER_HEADER_SIZE + Self::PI_COUNT * 32;
        if data.len() < expected_size {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = BUFFER_HEADER_SIZE;

        // anchor
        let anchor: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        // nullifiers[3]
        let mut nullifiers = [[0u8; 32]; 3];
        for nf in &mut nullifiers {
            *nf = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            offset += 32;
        }

        // output_commitments[3]
        let mut output_commitments = [[0u8; 32]; 3];
        for oc in &mut output_commitments {
            *oc = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            offset += 32;
        }

        // input_count (32-byte field, value in last 4 bytes)
        let input_count_bytes: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let input_count = u32::from_be_bytes(
            input_count_bytes[28..32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        offset += 32;

        // output_count
        let output_count_bytes: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let output_count = u32::from_be_bytes(
            output_count_bytes[28..32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        offset += 32;

        // ct_hashes[3]
        let mut ct_hashes = [[0u8; 32]; 3];
        for ct in &mut ct_hashes {
            *ct = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            offset += 32;
        }

        // tx_binding
        let tx_binding: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        Ok(Self {
            anchor,
            nullifiers,
            output_commitments,
            input_count,
            output_count,
            ct_hashes,
            tx_binding,
        })
    }

    /// Extract from instruction data
    fn from_data(transfer_data: &TransferData) -> Result<Self, ProgramError> {
        Ok(Self {
            anchor: transfer_data.anchor,
            nullifiers: transfer_data.nullifiers,
            output_commitments: transfer_data.output_commitments,
            input_count: transfer_data.input_count,
            output_count: transfer_data.output_count,
            ct_hashes: transfer_data.ct_hashes,
            tx_binding: transfer_data.tx_binding,
        })
    }

    /// Convert to public inputs array for inline verification
    pub fn to_public_inputs(&self) -> [[u8; 32]; 13] {
        let mut pis = [[0u8; 32]; 13];
        let mut idx = 0;

        pis[idx] = self.anchor;
        idx += 1;

        for nf in &self.nullifiers {
            pis[idx] = *nf;
            idx += 1;
        }

        for oc in &self.output_commitments {
            pis[idx] = *oc;
            idx += 1;
        }

        // input_count as 32-byte field
        pis[idx][28..32].copy_from_slice(&self.input_count.to_be_bytes());
        idx += 1;

        // output_count as 32-byte field
        pis[idx][28..32].copy_from_slice(&self.output_count.to_be_bytes());
        idx += 1;

        for ct in &self.ct_hashes {
            pis[idx] = *ct;
            idx += 1;
        }

        pis[idx] = self.tx_binding;

        pis
    }
}

// =============================================================================
// Unshield Inputs
// =============================================================================

/// Extracted public inputs for Unshield circuit
#[derive(Debug, Clone)]
pub struct UnshieldInputs {
    /// Merkle root anchor
    pub anchor: [u8; 32],
    /// Nullifier for spent note
    pub nullifier: [u8; 32],
    /// Transaction binding
    pub tx_binding: [u8; 32],
    /// Amount to withdraw
    pub amount: u64,
    /// Recipient address as 4 u64 limbs
    pub recipient_limbs: [u64; 4],
    /// Asset identifier
    pub asset_id: [u8; 32],
}

impl UnshieldInputs {
    /// Number of public inputs for Unshield circuit
    /// anchor(1) + nullifier(1) + tx_binding(1) + amount(1) + recipient_limbs(4) + asset_id(1) = 9
    pub const PI_COUNT: usize = 9;

    /// Extract unshield inputs from either buffer or instruction data
    pub fn extract(
        proof_buffer: &AccountInfo,
        unshield_data: &UnshieldData,
    ) -> Result<Self, ProgramError> {
        match CURRENT_PROOF_SYSTEM {
            ProofSystem::UltraPlonk => Self::from_buffer(proof_buffer),
            _ => Self::from_data(unshield_data),
        }
    }

    /// Extract from proof buffer's public inputs section
    fn from_buffer(proof_buffer: &AccountInfo) -> Result<Self, ProgramError> {
        let data = proof_buffer.try_borrow_data()?;

        let expected_size = BUFFER_HEADER_SIZE + Self::PI_COUNT * 32;
        if data.len() < expected_size {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = BUFFER_HEADER_SIZE;

        // anchor
        let anchor: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        // nullifier
        let nullifier: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        // tx_binding
        let tx_binding: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += 32;

        // amount (32-byte field, value in last 8 bytes)
        let amount_bytes: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let amount = u64::from_be_bytes(
            amount_bytes[24..32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        offset += 32;

        // recipient_limbs[4] (each as 32-byte field, value in last 8 bytes)
        let mut recipient_limbs = [0u64; 4];
        for limb in &mut recipient_limbs {
            let limb_bytes: [u8; 32] = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            *limb = u64::from_be_bytes(
                limb_bytes[24..32]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?,
            );
            offset += 32;
        }

        // asset_id
        let asset_id: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        Ok(Self {
            anchor,
            nullifier,
            tx_binding,
            amount,
            recipient_limbs,
            asset_id,
        })
    }

    /// Extract from instruction data
    fn from_data(unshield_data: &UnshieldData) -> Result<Self, ProgramError> {
        Ok(Self {
            anchor: unshield_data.anchor,
            nullifier: unshield_data.nullifier,
            tx_binding: unshield_data.tx_binding,
            amount: unshield_data.amount,
            recipient_limbs: unshield_data.recipient_limbs,
            asset_id: unshield_data.asset_id,
        })
    }

    /// Convert to public inputs array for inline verification
    pub fn to_public_inputs(&self) -> [[u8; 32]; 9] {
        let mut pis = [[0u8; 32]; 9];

        pis[0] = self.anchor;
        pis[1] = self.nullifier;
        pis[2] = self.tx_binding;

        // amount as 32-byte field
        pis[3][24..32].copy_from_slice(&self.amount.to_be_bytes());

        // recipient_limbs as 32-byte fields
        for (i, limb) in self.recipient_limbs.iter().enumerate() {
            pis[4 + i][24..32].copy_from_slice(&limb.to_be_bytes());
        }

        pis[8] = self.asset_id;

        pis
    }

    /// Reconstruct recipient address from limbs (little-endian)
    pub fn recipient(&self) -> [u8; 32] {
        let mut recipient = [0u8; 32];
        for (i, limb) in self.recipient_limbs.iter().enumerate() {
            recipient[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        recipient
    }
}

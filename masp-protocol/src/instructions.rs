//! Instruction data structures for MASP operations
//!
//! These structs define the on-chain instruction format for Shield, Transfer, and Unshield.
//! They are Borsh-serializable and used by both the program (parsing) and client (encoding).

use borsh::{BorshDeserialize, BorshSerialize};

use crate::public_inputs::{MAX_INPUTS, MAX_OUTPUTS};

/// Shield instruction data
///
/// Deposits funds from a public SPL token account into the shielded pool.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ShieldData {
    /// New note commitment
    pub commitment: [u8; 32],
    /// Asset ID (H(token_address))
    pub asset_id: [u8; 32],
    /// Amount to shield (must match SPL transfer)
    pub amount: u64,
    /// Ciphertext hash for binding
    pub ct_hash: [u8; 32],
}

/// Transfer instruction data
///
/// Private transfer within the shielded pool.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransferData {
    /// Merkle root for membership proofs
    pub anchor: [u8; 32],
    /// Nullifiers for spent notes (padded with zeros for unused)
    pub nullifiers: [[u8; 32]; MAX_INPUTS],
    /// Output commitments (padded with zeros for unused)
    pub output_commitments: [[u8; 32]; MAX_OUTPUTS],
    /// Number of active inputs (1-3)
    pub input_count: u32,
    /// Number of active outputs (1-3)
    pub output_count: u32,
    /// Ciphertext hashes for outputs (padded with zeros for unused)
    pub ct_hashes: [[u8; 32]; MAX_OUTPUTS],
    /// Transaction binding hash
    pub tx_binding: [u8; 32],
}

/// Unshield instruction data
///
/// Withdraws funds from the shielded pool to a public SPL token account.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct UnshieldData {
    /// Merkle root for membership proof
    pub anchor: [u8; 32],
    /// Nullifier for spent note
    pub nullifier: [u8; 32],
    /// Transaction binding hash
    pub tx_binding: [u8; 32],
    /// Amount to withdraw
    pub amount: u64,
    /// Recipient address as 4 u64 limbs (little-endian reconstruction)
    pub recipient_limbs: [u64; 4],
    /// Asset ID being withdrawn
    pub asset_id: [u8; 32],
}

/// Ciphertext posting data (Tx A in two-tx model)
///
/// This instruction is a data carrier - it doesn't modify program state.
/// The ciphertext bytes are stored in ledger history for data availability.
/// Recipients discover these via the tx_sig shared out-of-band.
///
/// ## Format
///
/// The instruction data after the discriminator is:
/// - 1 byte: count (number of ciphertexts, 1-3)
/// - Variable: packed ciphertexts, each as:
///   - 2 bytes: length (u16 LE)
///   - N bytes: ciphertext data
///
/// The program does NOT parse the ciphertexts - it just accepts them.
/// The client computes `ct_hash` from the posted bytes.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCiphertextsData {
    /// Number of ciphertexts (1-3)
    pub count: u8,
    /// Raw ciphertext bytes (packed format: [len: u16 LE, data...] per ciphertext)
    pub packed_ciphertexts: Vec<u8>,
}

#[cfg(feature = "std")]
impl PostCiphertextsData {
    /// Encode the instruction data for on-chain submission
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + self.packed_ciphertexts.len());
        data.push(self.count);
        data.extend_from_slice(&self.packed_ciphertexts);
        data
    }

    /// Pack ciphertexts into the wire format
    pub fn pack_ciphertexts(ciphertexts: &[&[u8]]) -> Vec<u8> {
        let total_len: usize = ciphertexts.iter().map(|ct| 2 + ct.len()).sum();
        let mut packed = Vec::with_capacity(total_len);
        for ct in ciphertexts {
            let len = ct.len() as u16;
            packed.extend_from_slice(&len.to_le_bytes());
            packed.extend_from_slice(ct);
        }
        packed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shield_data_roundtrip() {
        let data = ShieldData {
            commitment: [1u8; 32],
            asset_id: [2u8; 32],
            amount: 1000,
            ct_hash: [3u8; 32],
        };
        let encoded = borsh::to_vec(&data).unwrap();
        let decoded: ShieldData = borsh::from_slice(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_transfer_data_roundtrip() {
        let data = TransferData {
            anchor: [1u8; 32],
            nullifiers: [[2u8; 32]; MAX_INPUTS],
            output_commitments: [[3u8; 32]; MAX_OUTPUTS],
            input_count: 2,
            output_count: 1,
            ct_hashes: [[4u8; 32]; MAX_OUTPUTS],
            tx_binding: [5u8; 32],
        };
        let encoded = borsh::to_vec(&data).unwrap();
        let decoded: TransferData = borsh::from_slice(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_unshield_data_roundtrip() {
        let data = UnshieldData {
            anchor: [1u8; 32],
            nullifier: [2u8; 32],
            tx_binding: [3u8; 32],
            amount: 500,
            recipient_limbs: [100, 200, 300, 400],
            asset_id: [4u8; 32],
        };
        let encoded = borsh::to_vec(&data).unwrap();
        let decoded: UnshieldData = borsh::from_slice(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
}

//! Public input layouts for MASP circuits
//!
//! Defines the structure and ordering of public inputs for each circuit type.
//! Both the on-chain verifier and off-chain prover must agree on these layouts.

/// Maximum number of inputs per transfer
pub const MAX_INPUTS: usize = 3;

/// Maximum number of outputs per transfer
pub const MAX_OUTPUTS: usize = 3;

/// Shield circuit public inputs
///
/// Layout (4 fields, each 32 bytes):
/// 1. commitment (32 bytes)
/// 2. asset_id (32 bytes)
/// 3. amount (32 bytes, big-endian, value in last 8 bytes)
/// 4. ct_hash (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldPublicInputs;

impl ShieldPublicInputs {
    /// Number of public inputs
    pub const COUNT: usize = 4;

    /// Total byte size (COUNT * 32)
    pub const BYTE_SIZE: usize = Self::COUNT * 32;

    // Field indices
    pub const IDX_COMMITMENT: usize = 0;
    pub const IDX_ASSET_ID: usize = 1;
    pub const IDX_AMOUNT: usize = 2;
    pub const IDX_CT_HASH: usize = 3;
}

/// Transfer circuit public inputs
///
/// Layout (13 fields, each 32 bytes):
/// - \[0\]: anchor (32 bytes)
/// - \[1-3\]: nullifiers\[3\] (3 × 32 bytes)
/// - \[4-6\]: output_commitments\[3\] (3 × 32 bytes)
/// - \[7\]: input_count (32 bytes, big-endian, value in last 4 bytes)
/// - \[8\]: output_count (32 bytes, big-endian, value in last 4 bytes)
/// - \[9-11\]: ct_hashes\[3\] (3 × 32 bytes)
/// - \[12\]: tx_binding (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferPublicInputs;

impl TransferPublicInputs {
    /// Number of public inputs
    pub const COUNT: usize = 13;

    /// Total byte size (COUNT * 32)
    pub const BYTE_SIZE: usize = Self::COUNT * 32;

    // Field indices
    pub const IDX_ANCHOR: usize = 0;
    pub const IDX_NULLIFIERS_START: usize = 1;
    pub const IDX_NULLIFIERS_END: usize = 4; // exclusive
    pub const IDX_OUTPUT_COMMITMENTS_START: usize = 4;
    pub const IDX_OUTPUT_COMMITMENTS_END: usize = 7; // exclusive
    pub const IDX_INPUT_COUNT: usize = 7;
    pub const IDX_OUTPUT_COUNT: usize = 8;
    pub const IDX_CT_HASHES_START: usize = 9;
    pub const IDX_CT_HASHES_END: usize = 12; // exclusive
    pub const IDX_TX_BINDING: usize = 12;
}

/// Unshield circuit public inputs
///
/// Layout (9 fields, each 32 bytes):
/// - \[0\]: anchor (32 bytes)
/// - \[1\]: nullifier (32 bytes)
/// - \[2\]: tx_binding (32 bytes)
/// - \[3\]: amount (32 bytes, big-endian, value in last 8 bytes)
/// - \[4-7\]: recipient_limbs\[4\] (4 × 32 bytes, each big-endian, value in last 8 bytes)
/// - \[8\]: asset_id (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnshieldPublicInputs;

impl UnshieldPublicInputs {
    /// Number of public inputs
    pub const COUNT: usize = 9;

    /// Total byte size (COUNT * 32)
    pub const BYTE_SIZE: usize = Self::COUNT * 32;

    // Field indices
    pub const IDX_ANCHOR: usize = 0;
    pub const IDX_NULLIFIER: usize = 1;
    pub const IDX_TX_BINDING: usize = 2;
    pub const IDX_AMOUNT: usize = 3;
    pub const IDX_RECIPIENT_LIMBS_START: usize = 4;
    pub const IDX_RECIPIENT_LIMBS_END: usize = 8; // exclusive
    pub const IDX_ASSET_ID: usize = 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shield_layout() {
        assert_eq!(ShieldPublicInputs::COUNT, 4);
        assert_eq!(ShieldPublicInputs::BYTE_SIZE, 128);
    }

    #[test]
    fn test_transfer_layout() {
        assert_eq!(TransferPublicInputs::COUNT, 13);
        assert_eq!(TransferPublicInputs::BYTE_SIZE, 416);
        // Verify indices are consistent
        assert_eq!(
            TransferPublicInputs::IDX_NULLIFIERS_END - TransferPublicInputs::IDX_NULLIFIERS_START,
            MAX_INPUTS
        );
        assert_eq!(
            TransferPublicInputs::IDX_OUTPUT_COMMITMENTS_END
                - TransferPublicInputs::IDX_OUTPUT_COMMITMENTS_START,
            MAX_OUTPUTS
        );
        assert_eq!(
            TransferPublicInputs::IDX_CT_HASHES_END - TransferPublicInputs::IDX_CT_HASHES_START,
            MAX_OUTPUTS
        );
    }

    #[test]
    fn test_unshield_layout() {
        assert_eq!(UnshieldPublicInputs::COUNT, 9);
        assert_eq!(UnshieldPublicInputs::BYTE_SIZE, 288);
        assert_eq!(
            UnshieldPublicInputs::IDX_RECIPIENT_LIMBS_END
                - UnshieldPublicInputs::IDX_RECIPIENT_LIMBS_START,
            4
        );
    }
}

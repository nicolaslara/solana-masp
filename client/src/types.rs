//! Common types for MASP

use ark_bn254::Fr as BN254Fr;

/// Field element type (BN254 scalar field)
pub type Fr = BN254Fr;

/// Token address (SPL mint pubkey) - 32 bytes
pub type TokenAddress = [u8; 32];

/// Commitment (32 bytes when serialized)
pub type Commitment = Fr;

/// Nullifier (32 bytes when serialized)
pub type Nullifier = Fr;

/// Anchor (Merkle root)
pub type Anchor = Fr;

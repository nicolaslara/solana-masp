//! Poseidon hash functions using light-poseidon
//!
//! We use the light-poseidon crate which implements Poseidon for BN254.

use crate::domain::DomainTag;
use crate::types::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};

/// Hash multiple field elements using Poseidon
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    // Convert Fr elements to bytes for light-poseidon
    let bytes: Vec<[u8; 32]> = inputs
        .iter()
        .map(|f| {
            let mut bytes = [0u8; 32];
            let le_bytes = f.into_bigint().to_bytes_le();
            bytes[..le_bytes.len()].copy_from_slice(&le_bytes);
            bytes
        })
        .collect();

    let byte_slices: Vec<&[u8]> = bytes.iter().map(|b| b.as_slice()).collect();
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("valid input count");
    let result_bytes: [u8; 32] = hasher.hash_bytes_le(&byte_slices).expect("hash succeeds");

    // Convert result back to Fr
    Fr::from_le_bytes_mod_order(&result_bytes)
}

/// Compute Merkle node hash with domain separation
pub fn merkle_hash(left: Fr, right: Fr) -> Fr {
    poseidon_hash(&[DomainTag::MerkleNode.to_field(), left, right])
}

/// Convert field element to 32 big-endian bytes
pub fn field_to_bytes(f: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let le_bytes = f.into_bigint().to_bytes_le();
    for (i, b) in le_bytes.iter().enumerate() {
        if i < 32 {
            bytes[31 - i] = *b;
        }
    }
    bytes
}

/// Convert 32 big-endian bytes to field element
pub fn field_from_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_deterministic() {
        let h1 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
        let h2 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_inputs_different_hash() {
        let h1 = poseidon_hash(&[Fr::from(1u64)]);
        let h2 = poseidon_hash(&[Fr::from(2u64)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_field_bytes_roundtrip() {
        let original = Fr::from(123456789u64);
        let bytes = field_to_bytes(&original);
        let recovered = field_from_bytes(&bytes);
        assert_eq!(original, recovered);
    }
}

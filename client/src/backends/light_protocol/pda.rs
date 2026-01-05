//! Light Protocol PDA derivation helpers
//!
//! These functions derive addresses compatible with Light Protocol's
//! compressed account system.

use sha3::{Digest, Keccak256};

/// BN254 field modulus (big-endian bytes)
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_MODULUS_P: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Derive the seed for a nullifier address (Light Protocol style)
///
/// The seed is: keccak256("nullifr\0" || nullifier || pool_pubkey)
///
/// This matches Light Protocol's address derivation scheme for nullifier records.
/// The nullifier address is used to prove non-existence (validity proof) before
/// creating a new compressed account that marks the nullifier as spent.
///
/// # Arguments
/// * `nullifier` - The 32-byte nullifier to check
/// * `pool_pubkey` - The pool/program identifier (32 bytes)
///
/// # Returns
/// A 32-byte seed for use with `derive_address`
pub fn derive_nullifier_address_seed(nullifier: &[u8; 32], pool_pubkey: &[u8; 32]) -> [u8; 32] {
    let prefix = b"nullifr\0"; // 8 bytes - matches noir-main

    // Concatenate: prefix || nullifier || pool_pubkey
    let mut input = Vec::with_capacity(8 + 32 + 32);
    input.extend_from_slice(prefix);
    input.extend_from_slice(nullifier);
    input.extend_from_slice(pool_pubkey);

    // Hash with Keccak256
    let hash = Keccak256::digest(&input);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Check if bytes (big-endian) are less than the BN254 modulus
fn bytes_lt_modulus(x: &[u8; 32]) -> bool {
    for i in 0..32 {
        if x[i] < BN254_MODULUS_P[i] {
            return true;
        }
        if x[i] > BN254_MODULUS_P[i] {
            return false;
        }
    }
    false
}

/// Derive an address from a seed and address tree (Light Protocol style)
///
/// Uses Keccak256 hash with bump search to find a valid BN254 field element.
///
/// # Arguments
/// * `seed` - The 32-byte seed (from `derive_nullifier_address_seed`)
/// * `address_tree` - The Light Protocol address tree pubkey (32 bytes)
///
/// # Returns
/// A 32-byte address suitable for Light Protocol validity proofs
pub fn derive_address(seed: &[u8; 32], address_tree: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let mut base = [0u8; 64];
    base[..32].copy_from_slice(address_tree);
    base[32..].copy_from_slice(seed);

    for bump in (0u8..=255).rev() {
        let mut data = [0u8; 65];
        data[..64].copy_from_slice(&base);
        data[64] = bump;

        let hash = Keccak256::digest(&data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);

        // Clear MSB and check if result is valid field element
        out[0] = 0;
        if bytes_lt_modulus(&out) {
            return Ok(out);
        }
    }

    Err("DeriveAddressError: no valid bump found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_nullifier_address_seed() {
        let nullifier = [0x42u8; 32];
        let pool = [0x01u8; 32];

        let seed = derive_nullifier_address_seed(&nullifier, &pool);

        // Seed should be non-zero
        assert!(seed.iter().any(|&b| b != 0));

        // Same inputs should give same seed
        let seed2 = derive_nullifier_address_seed(&nullifier, &pool);
        assert_eq!(seed, seed2);

        // Different nullifier should give different seed
        let different_nullifier = [0x43u8; 32];
        let seed3 = derive_nullifier_address_seed(&different_nullifier, &pool);
        assert_ne!(seed, seed3);
    }

    #[test]
    fn test_derive_address() {
        let seed = [0x42u8; 32];
        let tree = [0x01u8; 32];

        let result = derive_address(&seed, &tree);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Address should have MSB cleared
        assert_eq!(address[0], 0);
        // Address should be non-zero (except first byte)
        assert!(address[1..].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_derive_address_deterministic() {
        let seed = [0x42u8; 32];
        let tree = [0x01u8; 32];

        let addr1 = derive_address(&seed, &tree).unwrap();
        let addr2 = derive_address(&seed, &tree).unwrap();
        assert_eq!(addr1, addr2);
    }
}

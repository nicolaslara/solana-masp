//! Poseidon hash functions using light-poseidon
//!
//! We use the light-poseidon crate which implements Poseidon for BN254.

use crate::domain::{DomainTag, DomainTagExt};
use crate::types::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use taceo_poseidon2::bn254::t4 as poseidon2_t4;

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

/// Hash an arbitrary ciphertext byte string into a field element, with domain separation.
///
/// This is used for **Option 1A** ciphertext binding.
///
/// In this model:
///
/// 1) Tx A publishes ciphertext bytes (outputs-only).
/// 2) Tx B binds to those bytes via `ct_hash`.
///
/// Important notes: this function is intentionally deterministic and cheap in Rust. It does **not**
/// attempt to be injective over bytes; we rely on hash collision resistance. When we move ciphertext
/// binding into real circuits, we must ensure the circuit uses an equivalent hash construction for
/// `ct_hash` (or explicitly document/bridge the difference).
pub fn ciphertext_hash(ciphertext_bytes: &[u8]) -> Fr {
    // We want Poseidon2 to match Noir stdlib, so we build a Field-vector and call
    // `poseidon2_hash_noir()`.
    //
    // To avoid accidental byte-packing collisions, we pack bytes into **31-byte little-endian**
    // chunks, which are guaranteed to fit into the BN254 scalar field without modular reduction.
    //
    // Input layout (all as Fields):
    //   [ DOM_CIPHERTEXT, len_bytes, chunk0, chunk1, ... ]
    let dom = DomainTag::Ciphertext.to_field();
    let len_f = Fr::from(ciphertext_bytes.len() as u64);

    let chunk_len = 31usize;
    let chunk_count = ciphertext_bytes.len().div_ceil(chunk_len);

    let mut inputs: Vec<Fr> = Vec::with_capacity(2 + chunk_count);
    inputs.push(dom);
    inputs.push(len_f);

    for i in 0..chunk_count {
        let start = i * chunk_len;
        let end = ((i + 1) * chunk_len).min(ciphertext_bytes.len());
        let mut le_bytes = [0u8; 32];
        le_bytes[..(end - start)].copy_from_slice(&ciphertext_bytes[start..end]);
        inputs.push(Fr::from_le_bytes_mod_order(&le_bytes));
    }

    poseidon2_hash_noir(&inputs, inputs.len() as u32)
}

/// Compute Merkle node hash with domain separation
pub fn merkle_hash(left: Fr, right: Fr) -> Fr {
    // Noir circuits use `std::hash::poseidon2::Poseidon2::hash([dom, left, right], 3)` for Merkle
    // nodes. This is a sponge built from a Poseidon2 permutation over a 4-element state with
    // RATE=3, and an IV of `(message_size << 64)` placed in the capacity element.
    //
    // Domain separation must match `DomainTag::MerkleNode` and Noir circuits (`DOM_MERKLE_NODE=7`).
    let dom = DomainTag::MerkleNode.to_field();
    poseidon2_hash_noir(&[dom, left, right], 3)
}

/// Poseidon2 hash matching Noir stdlib `std::hash::poseidon2::Poseidon2::hash(input, message_size)`.
///
/// Source of truth: Noir stdlib (`noir_stdlib/src/hash/poseidon2.nr`, noirc commit `ceaa198...`).
///
/// Key details:
///
/// - Sponge RATE = 3 over a 4-element state
/// - IV = (message_size as Field) * 2^64, stored in the capacity element (state[3])
/// - If `message_size != input.len()`, append `1` (variable-length domain separation)
///
/// This is the function to use whenever Rust must match Noir stdlib Poseidon2 exactly.
pub fn poseidon2_hash_noir(inputs: &[Fr], message_size: u32) -> Fr {
    const RATE: usize = 3;
    const TWO_POW_64: u128 = 1u128 << 64;

    let in_len = message_size as usize;
    assert!(in_len <= inputs.len());

    let iv = Fr::from((message_size as u128) * TWO_POW_64);
    let mut state = [Fr::zero(); 4];
    state[RATE] = iv;

    // Cache up to RATE elements before permuting.
    let mut cache = [Fr::zero(); RATE];
    let mut cache_size: usize = 0;

    let perform_duplex = |state: &mut [Fr; 4], cache: &[Fr; RATE], cache_size: usize| {
        for i in 0..RATE {
            if i < cache_size {
                state[i] += cache[i];
            }
        }
        *state = poseidon2_t4::permutation(state);
    };

    // Absorb exactly `message_size` elements (even if inputs has extra capacity).
    for &x in inputs.iter().take(in_len) {
        if cache_size == RATE {
            perform_duplex(&mut state, &cache, cache_size);
            cache[0] = x;
            cache_size = 1;
        } else {
            cache[cache_size] = x;
            cache_size += 1;
        }
    }

    // Variable-length distinction: append 1 if message_size != N.
    if (message_size as usize) != inputs.len() {
        let x = Fr::from(1u64);
        if cache_size == RATE {
            perform_duplex(&mut state, &cache, cache_size);
            cache[0] = x;
            cache_size = 1;
        } else {
            cache[cache_size] = x;
            cache_size += 1;
        }
    }

    // Squeeze once.
    perform_duplex(&mut state, &cache, cache_size);
    state[0]
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
    use std::str::FromStr;

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

    #[test]
    fn test_poseidon2_matches_noir_kat() {
        // Generated via:
        // `cd circuits/poseidon2_kat && nargo execute`
        // for `Poseidon2::hash([0,1,2], 3)`.
        let expected = Fr::from_str(
            "4352841499683633384359722549333820364941934475207346704605191617958607370700",
        )
        .expect("valid Fr");
        let got = poseidon2_hash_noir(&[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)], 3);
        assert_eq!(got, expected);
    }
}

//! Transaction binding hash (anti-malleability / intent binding).
//!
//! In a real ZK system, the proof is verified *against* public inputs, so the proof is already
//! bound to those inputs. The role of `tx_binding` is to additionally bind the proof to a
//! well-defined transaction "intent" object, so that higher-level data cannot be modified
//! without invalidating the proof.
//!
//! ## Transfer Binding (current)
//!
//! For N→M transfers, the binding hash includes:
//! - `anchor_root` (shared anchor for all inputs)
//! - `input_count`, `output_count` (explicit counts)
//! - `h_nf = H(nullifiers[0..MAX_INPUTS])` (hash of padded nullifier array)
//!
//! ### What is NOT in `tx_binding` (and why)
//!
//! - **Output commitments:** already explicit public inputs, bound by proof verification.
//! - **Ciphertext hashes (`ct_hashes`):** also explicit public inputs, bound by proof verification.
//!
//! We intentionally do NOT include output commitments or ct_hashes in `tx_binding` to avoid
//! circular dependencies: output nonces are derived from `tx_binding`, so anything that depends
//! on output note contents (which include nonces) cannot be included in `tx_binding`.
//!
//! ### Ciphertext binding (Option 1A baseline)
//!
//! Per `docs/design-decisions/ciphertext-da-and-binding.md`:
//! - `ct_hashes[MAX_OUTPUTS]` are explicit public inputs (not inside `tx_binding`).
//! - The circuit binds to these values directly (verification "gets them for free").
//! - For disabled outputs, `ct_hashes[j] == 0`.

use crate::domain::DomainTag;
use crate::hash::poseidon2_hash_noir;
use crate::types::{Fr, Nullifier};

/// Maximum number of inputs in an N→M transfer (compile-time constant).
pub const MAX_INPUTS: usize = 3;

/// Maximum number of outputs in an N→M transfer (compile-time constant).
pub const MAX_OUTPUTS: usize = 3;

/// Compute the transaction binding hash for a **Transfer** spend proof (N inputs -> M outputs).
///
/// Layout:
/// `H(DOM_TX_BINDING, 2, anchor, input_count, output_count, h_nf)`
///
/// Where:
/// - `h_nf = H(nullifiers[0], nullifiers[1], ..., nullifiers[MAX_INPUTS-1])`
///
/// The nullifier array is padded with zeros for disabled slots.
pub fn tx_binding_transfer(
    anchor: Fr,
    nullifiers: &[Nullifier; MAX_INPUTS],
    input_count: u32,
    output_count: u32,
) -> Fr {
    // Hash the nullifier array with Noir-compatible Poseidon2.
    let h_nf = poseidon2_hash_noir(nullifiers, 3);

    // Final binding hash
    poseidon2_hash_noir(
        &[
            DomainTag::TransactionBinding.to_field(),
            Fr::from(2u64), // discriminator: transfer
            anchor,
            Fr::from(input_count as u64),
            Fr::from(output_count as u64),
            h_nf,
        ],
        6,
    )
}

/// Compute the transaction binding hash for an **Unshield** spend proof.
///
/// Layout:
/// `H(DOM_TX_BINDING, 3, anchor, nullifier, public_amount, public_recipient_limbs[4], public_asset_id)`
///
/// **Note:** `input_commitment` is intentionally NOT included. It is private (witness-only);
/// the proof already binds to it via preimage knowledge. Including it would create a value
/// the chain cannot recompute (chain only sees public inputs).
pub fn tx_binding_unshield(
    anchor: Fr,
    nullifier: Nullifier,
    public_amount: u64,
    public_recipient_limbs: [u64; 4],
    public_asset_id: Fr,
) -> Fr {
    // Must match Noir circuits (`Poseidon2::hash([..], 10)`).
    poseidon2_hash_noir(
        &[
            DomainTag::TransactionBinding.to_field(),
            Fr::from(3u64), // discriminator: unshield
            anchor,
            nullifier,
            Fr::from(public_amount),
            Fr::from(public_recipient_limbs[0]),
            Fr::from(public_recipient_limbs[1]),
            Fr::from(public_recipient_limbs[2]),
            Fr::from(public_recipient_limbs[3]),
            public_asset_id,
        ],
        10,
    )
}

/// Convert a 32-byte recipient (e.g. Solana pubkey) to 4×u64 limbs (little-endian).
///
/// This encoding is injective and avoids the many-to-one `bytes -> Field mod p` issue.
pub fn recipient_to_u64_limbs_le(recipient: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (out_limb, chunk) in out.iter_mut().zip(recipient.chunks_exact(8)) {
        *out_limb = u64::from_le_bytes(chunk.try_into().expect("len 8"));
    }
    out
}

/// Convert 4×u64 limbs (little-endian) back into the original 32-byte recipient.
pub fn recipient_from_u64_limbs_le(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (&limb, chunk) in limbs.iter().zip(out.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Derive the output nullifier nonce for an N→M transfer.
///
/// In N→M transfers, output nonces are derived from the tx_binding hash (not from
/// a single input commitment), which avoids ambiguity when there are multiple inputs.
///
/// Formula: `H(DOM_NULLIFIER_NONCE, tx_binding, output_index)`
pub fn derive_output_nonce_nm(tx_binding: Fr, output_index: u64) -> Fr {
    poseidon2_hash_noir(
        &[
            DomainTag::NullifierNonce.to_field(),
            tx_binding,
            Fr::from(output_index),
        ],
        3,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_binding_transfer_deterministic() {
        let anchor = Fr::from(1u64);
        let nullifiers = [Fr::from(10u64), Fr::from(20u64), Fr::from(0u64)];

        let binding1 = tx_binding_transfer(anchor, &nullifiers, 2, 2);
        let binding2 = tx_binding_transfer(anchor, &nullifiers, 2, 2);

        assert_eq!(binding1, binding2);
    }

    #[test]
    fn test_tx_binding_changes_with_counts() {
        let anchor = Fr::from(1u64);
        let nullifiers = [Fr::from(10u64), Fr::from(0u64), Fr::from(0u64)];

        let binding1 = tx_binding_transfer(anchor, &nullifiers, 1, 1);
        let binding2 = tx_binding_transfer(anchor, &nullifiers, 2, 1);

        // Different counts should produce different bindings
        assert_ne!(binding1, binding2);
    }

    #[test]
    fn test_derive_output_nonce_nm_unique_per_index() {
        let tx_binding = Fr::from(12345u64);

        let nonce0 = derive_output_nonce_nm(tx_binding, 0);
        let nonce1 = derive_output_nonce_nm(tx_binding, 1);
        let nonce2 = derive_output_nonce_nm(tx_binding, 2);

        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce0, nonce2);
    }
}

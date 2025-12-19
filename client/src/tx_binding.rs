//! Transaction binding hash (anti-malleability / intent binding).
//!
//! In a real ZK system, the proof is verified *against* public inputs, so the proof is already
//! bound to those inputs. The role of `tx_binding` is to additionally bind the proof to a
//! well-defined transaction "intent" object, so that higher-level data (and in future, additional
//! public inputs like ciphertext hashes) cannot be modified without invalidating the proof.
//!
//! ## Transfer Binding (current)
//!
//! For N→M transfers, the binding hash includes:
//! - `anchor_root` (shared anchor for all inputs)
//! - `input_count`, `output_count` (explicit counts)
//! - `h_nf = H(nullifiers[0..MAX_INPUTS])` (hash of padded nullifier array)
//!
//! Output commitments are already explicit public inputs to the transfer proof and therefore
//! are already bound by proof verification; we intentionally do not include them in `tx_binding`
//! so we can safely derive output nonces from `tx_binding` without circular dependency.

use crate::domain::DomainTag;
use crate::hash::poseidon2_hash_noir;
use crate::types::{Commitment, Fr, Nullifier};

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
/// `H(DOM_TX_BINDING, 3, anchor, input_commitment, nullifier, public_amount, public_recipient, public_asset_id)`
pub fn tx_binding_unshield(
    anchor: Fr,
    input_commitment: Commitment,
    nullifier: Nullifier,
    public_amount: u64,
    public_recipient: Fr,
    public_asset_id: Fr,
) -> Fr {
    // Unshield binding remains Poseidon (legacy) for now; it isn't wired to Noir yet.
    // We can migrate this to Poseidon2 once the unshield circuit starts enforcing the same layout.
    crate::hash::poseidon_hash(&[
        DomainTag::TransactionBinding.to_field(),
        Fr::from(3u64), // discriminator: unshield
        anchor,
        input_commitment,
        nullifier,
        Fr::from(public_amount),
        public_recipient,
        public_asset_id,
    ])
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

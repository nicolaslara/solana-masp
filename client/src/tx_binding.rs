//! Transaction binding hash (anti-malleability / intent binding).
//!
//! In a real ZK system, the proof is verified *against* public inputs, so the proof is already
//! bound to those inputs. The role of `tx_binding` is to additionally bind the proof to a
//! well-defined transaction "intent" object, so that higher-level data (and in future, additional
//! public inputs like ciphertext hashes) cannot be modified without invalidating the proof.
//!
//! v0: We define a concrete layout over the fields we already have today.

use crate::domain::DomainTag;
use crate::hash::poseidon_hash;
use crate::types::{Commitment, Fr, Nullifier};

/// Compute the transaction binding hash for a **Transfer** spend proof.
///
/// Layout (v0):
/// `H(DOM_TX_BINDING, 2, anchor, input_commitment, nullifier, len(outputs), outputs...)`
pub fn tx_binding_transfer(
    anchor: Fr,
    input_commitment: Commitment,
    nullifier: Nullifier,
    output_commitments: &[Commitment],
) -> Fr {
    let mut inputs = Vec::with_capacity(6 + output_commitments.len());
    inputs.push(DomainTag::TransactionBinding.to_field());
    inputs.push(Fr::from(2u64)); // discriminator: transfer
    inputs.push(anchor);
    inputs.push(input_commitment);
    inputs.push(nullifier);
    inputs.push(Fr::from(output_commitments.len() as u64));
    inputs.extend_from_slice(output_commitments);
    poseidon_hash(&inputs)
}

/// Compute the transaction binding hash for an **Unshield** spend proof.
///
/// Layout (v0):
/// `H(DOM_TX_BINDING, 3, anchor, input_commitment, nullifier, public_amount, public_recipient, public_asset_id)`
pub fn tx_binding_unshield(
    anchor: Fr,
    input_commitment: Commitment,
    nullifier: Nullifier,
    public_amount: u64,
    public_recipient: Fr,
    public_asset_id: Fr,
) -> Fr {
    poseidon_hash(&[
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



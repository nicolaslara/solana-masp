//! Nullifier derivation
//!
//! A nullifier is a unique identifier revealed when spending a note.
//! It prevents double-spending: same note = same nullifier = rejected.
//!
//! `nullifier = H(DOM_NULLIFIER, nullifier_key, nullifier_nonce)`
//!
//! Note: The nullifier SET is stored on-chain, not in the client.
//! The client only computes nullifiers for its own notes.

use crate::domain::DomainTag;
use crate::hash::poseidon_hash;
use crate::types::{Fr, Nullifier};

/// Compute a note's nullifier
///
/// `nullifier = H(DOM_NULLIFIER, nullifier_key, nullifier_nonce)`
///
/// Where:
/// - `nullifier_key` (nk): derived from the spending key, binds to owner
/// - `nullifier_nonce`: unique per note, committed in the note
pub fn compute_nullifier(nullifier_key: Fr, nullifier_nonce: Fr) -> Nullifier {
    poseidon_hash(&[
        DomainTag::Nullifier.to_field(),
        nullifier_key,
        nullifier_nonce,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let nk = Fr::from(12345u64);
        let nonce = Fr::from(67890u64);

        let nf1 = compute_nullifier(nk, nonce);
        let nf2 = compute_nullifier(nk, nonce);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_different_nonce_different_nullifier() {
        let nk = Fr::from(12345u64);
        let nf1 = compute_nullifier(nk, Fr::from(1u64));
        let nf2 = compute_nullifier(nk, Fr::from(2u64));
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_different_key_different_nullifier() {
        let nonce = Fr::from(67890u64);
        let nf1 = compute_nullifier(Fr::from(1u64), nonce);
        let nf2 = compute_nullifier(Fr::from(2u64), nonce);
        assert_ne!(nf1, nf2);
    }
}

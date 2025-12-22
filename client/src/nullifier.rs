//! Nullifier derivation
//!
//! A nullifier is a unique identifier revealed when spending a note.
//! It prevents double-spending: same note = same nullifier = rejected.
//!
//! **CRITICAL SECURITY PROPERTY:**
//! The nullifier MUST be derived from `nsk` (the nullifier SECRET), NOT from `nk.x` (public key).
//!
//! `nullifier = H(DOM_NULLIFIER, nsk, nullifier_nonce)`
//!
//! This ensures that only SpendingKey holders can compute nullifiers.
//! If we used `nk.x` (which is in the FullViewingKey), watch-only wallets could spend!
//!
//! Note: The nullifier SET is stored on-chain, not in the client.
//! The client only computes nullifiers for its own notes.

use crate::domain::DomainTag;
use crate::hash::poseidon2_hash_noir;
use crate::types::{Fr, Nullifier};

/// Compute a note's nullifier
///
/// `nullifier = H(DOM_NULLIFIER, nsk, nullifier_nonce)`
///
/// Where:
/// - `nsk`: the nullifier SECRET key (NOT the public key nk.x!)
///   - `nsk = H(DOM_NULLIFIER_SECRET, spending_key)`
///   - Only the SpendingKey holder knows this
/// - `nullifier_nonce`: unique per note, committed in the note
///
/// **SECURITY:** Using `nsk` (secret) instead of `nk.x` (public) ensures
/// that FullViewingKey holders CANNOT compute nullifiers or spend notes.
pub fn compute_nullifier(nsk: Fr, nullifier_nonce: Fr) -> Nullifier {
    // Must match Noir circuits (`Poseidon2::hash([DOM_NULLIFIER, nsk, nonce], 3)`).
    poseidon2_hash_noir(
        &[DomainTag::Nullifier.to_field(), nsk, nullifier_nonce],
        3,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        // nsk is the SECRET nullifier key (not the public nk.x!)
        let nsk = Fr::from(12345u64);
        let nonce = Fr::from(67890u64);

        let nf1 = compute_nullifier(nsk, nonce);
        let nf2 = compute_nullifier(nsk, nonce);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_different_nonce_different_nullifier() {
        let nsk = Fr::from(12345u64);
        let nf1 = compute_nullifier(nsk, Fr::from(1u64));
        let nf2 = compute_nullifier(nsk, Fr::from(2u64));
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_different_key_different_nullifier() {
        let nonce = Fr::from(67890u64);
        let nf1 = compute_nullifier(Fr::from(1u64), nonce);
        let nf2 = compute_nullifier(Fr::from(2u64), nonce);
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_uses_nsk_not_nk() {
        // This test documents the CRITICAL security property:
        // Nullifiers MUST use nsk (secret), not nk.x (public).
        use crate::keys::SpendingKey;

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let nsk = sk.nsk(); // SECRET - only SpendingKey holder knows this
        let nk_x = sk.to_full_viewing_key().nk_field(); // PUBLIC - in FullViewingKey

        // These MUST be different values
        assert_ne!(nsk, nk_x);

        let nonce = Fr::from(123u64);

        // The nullifier should use nsk, not nk_x
        let correct_nullifier = compute_nullifier(nsk, nonce);

        // A watch-only wallet using nk_x would get a different (WRONG) nullifier
        let wrong_nullifier = compute_nullifier(nk_x, nonce);
        assert_ne!(correct_nullifier, wrong_nullifier);
    }
}

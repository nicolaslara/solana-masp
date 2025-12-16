//! Note structure and commitment derivation
//!
//! A note represents a unit of shielded value with clear field naming:
//!
//! | Field              | Purpose                                    |
//! |--------------------|------------------------------------------- |
//! | `asset_id`         | Which token (derived from token_address)   |
//! | `amount`           | Value in the note                          |
//! | `recipient`        | Who can spend (owner's address)            |
//! | `nullifier_nonce`  | Unique per note, used in nullifier derivation |
//! | `note_randomness`  | Hides note contents in commitment          |

use crate::domain::DomainTag;
use crate::hash::{field_from_bytes, field_to_bytes, poseidon_hash};
use crate::types::{Commitment, Fr, TokenAddress};
use ark_ff::UniformRand;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A MASP note representing shielded value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Asset identifier: `H(DOM_ASSET, token_address)`
    /// Hides the actual token mint from observers
    pub asset_id: Fr,

    /// Note value (must fit in u64, range-checked in circuit)
    pub amount: u64,

    /// Recipient's address (pk_d.x from diversified address)
    /// Only the holder of the corresponding spending key can spend
    pub recipient: Fr,

    /// Unique per note - ensures unique nullifier
    /// For outputs: derived as `H(DOM, spent_commitment, output_index)`
    /// Without this, same owner + same nk = same nullifier = linkable
    pub nullifier_nonce: Fr,

    /// Randomness that hides note contents in the commitment
    /// Without this, identical notes would have identical commitments
    pub note_randomness: Fr,
}

/// Serializable note plaintext (for encryption/storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePlaintext {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 32],
    pub nullifier_nonce: [u8; 32],
    pub note_randomness: [u8; 32],
}

impl Note {
    /// Create a new note with random nonce and randomness
    pub fn new<R: Rng>(rng: &mut R, asset_id: Fr, amount: u64, recipient: Fr) -> Self {
        Self {
            asset_id,
            amount,
            recipient,
            nullifier_nonce: Fr::rand(rng),
            note_randomness: Fr::rand(rng),
        }
    }

    /// Create note with explicit values (for deterministic derivation)
    pub fn with_values(
        asset_id: Fr,
        amount: u64,
        recipient: Fr,
        nullifier_nonce: Fr,
        note_randomness: Fr,
    ) -> Self {
        Self {
            asset_id,
            amount,
            recipient,
            nullifier_nonce,
            note_randomness,
        }
    }

    /// Derive nullifier_nonce for an output note
    ///
    /// `nullifier_nonce = H(DOM, spent_commitment, output_index)`
    ///
    /// This ties the output to the transaction that created it,
    /// ensuring each output has a unique nonce.
    pub fn derive_nullifier_nonce(spent_commitment: Fr, output_index: u64) -> Fr {
        poseidon_hash(&[
            DomainTag::NullifierNonce.to_field(),
            spent_commitment,
            Fr::from(output_index),
        ])
    }

    /// Compute the note commitment
    ///
    /// `cm = H(DOM, asset_id, amount, recipient, nullifier_nonce, note_randomness)`
    ///
    /// This is stored in the on-chain Merkle tree.
    pub fn commitment(&self) -> Commitment {
        poseidon_hash(&[
            DomainTag::NoteCommitment.to_field(),
            self.asset_id,
            Fr::from(self.amount),
            self.recipient,
            self.nullifier_nonce,
            self.note_randomness,
        ])
    }

    /// Convert to plaintext for encryption/serialization
    pub fn to_plaintext(&self) -> NotePlaintext {
        NotePlaintext {
            asset_id: field_to_bytes(&self.asset_id),
            amount: self.amount,
            recipient: field_to_bytes(&self.recipient),
            nullifier_nonce: field_to_bytes(&self.nullifier_nonce),
            note_randomness: field_to_bytes(&self.note_randomness),
        }
    }

    /// Reconstruct note from plaintext
    pub fn from_plaintext(p: &NotePlaintext) -> Self {
        Self {
            asset_id: field_from_bytes(&p.asset_id),
            amount: p.amount,
            recipient: field_from_bytes(&p.recipient),
            nullifier_nonce: field_from_bytes(&p.nullifier_nonce),
            note_randomness: field_from_bytes(&p.note_randomness),
        }
    }
}

/// Compute asset_id from a token address (SPL mint pubkey)
///
/// `asset_id = H(DOM_ASSET, token_address)`
pub fn compute_asset_id(token_address: &TokenAddress) -> Fr {
    let addr_field = field_from_bytes(token_address);
    poseidon_hash(&[DomainTag::AssetId.to_field(), addr_field])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_commitment_deterministic() {
        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, Fr::from(1u64), 100, Fr::from(2u64));

        let cm1 = note.commitment();
        let cm2 = note.commitment();
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_different_nonce_different_commitment() {
        let note1 = Note::with_values(
            Fr::from(1u64),
            100,
            Fr::from(2u64),
            Fr::from(1u64),
            Fr::from(1u64),
        );
        let note2 = Note::with_values(
            Fr::from(1u64),
            100,
            Fr::from(2u64),
            Fr::from(2u64),
            Fr::from(1u64),
        );
        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_plaintext_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(&mut rng, Fr::from(1u64), 100, Fr::from(2u64));
        let recovered = Note::from_plaintext(&note.to_plaintext());
        assert_eq!(note, recovered);
    }

    #[test]
    fn test_asset_id_different_tokens() {
        let token1 = [1u8; 32];
        let token2 = [2u8; 32];
        assert_ne!(compute_asset_id(&token1), compute_asset_id(&token2));
    }
}

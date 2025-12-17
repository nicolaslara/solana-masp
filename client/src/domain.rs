//! Domain separation tags for Poseidon hashing
//!
//! Each hash operation uses a unique domain tag to prevent cross-protocol attacks.
//! The tag is the first input to the hash function.

use crate::types::Fr;

/// Domain separation tags for different hash operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DomainTag {
    /// Note commitment: binds all note fields together
    /// `cm = H(DOM, asset_id, amount, recipient, nullifier_nonce, note_randomness)`
    NoteCommitment = 1,

    /// Nullifier derivation: unique identifier revealed on spend
    /// `nf = H(DOM, nullifier_key, nullifier_nonce)`
    Nullifier = 2,

    /// Asset identifier: hides the actual token address
    /// `asset_id = H(DOM, token_address)`
    AssetId = 3,

    /// Multi-asset alpha challenge (Fiat-Shamir)
    /// `α = H(DOM, tx_binding_hash)`
    AssetAlpha = 4,

    /// Per-asset balance tag
    /// `tag = H(DOM, α, asset_id)`
    AssetTag = 5,

    /// Ciphertext binding (optional)
    /// `c_hash = H(DOM, ciphertext_chunks...)`
    Ciphertext = 6,

    /// Merkle tree internal nodes
    /// `parent = H(DOM, left, right)`
    MerkleNode = 7,

    /// Incoming viewing key derivation
    /// `ivk = H(DOM, ak_x, nk_x)`
    IncomingViewingKey = 8,

    /// Authorization secret key derivation
    /// `ask = H(DOM, spending_key)`
    AuthorizationSecret = 9,

    /// Nullifier secret key derivation
    /// `nsk = H(DOM, spending_key)`
    NullifierSecret = 10,

    /// Nullifier nonce derivation for outputs
    /// `nullifier_nonce = H(DOM, spent_commitment, output_index)`
    NullifierNonce = 11,

    /// Transaction binding hash
    /// `tx_hash = H(DOM, anchor, nullifiers..., commitments...)`
    TransactionBinding = 12,

    /// Outgoing viewing key derivation
    /// `ovk = H(DOM, ak_x, nk_x)`
    /// Used to decrypt C_out (notes sent BY this key)
    OutgoingViewingKey = 13,

    /// Outgoing ciphertext key derivation
    /// `ock = H(DOM, ovk, epk_x, commitment)`
    /// Symmetric key for C_out encryption
    OutgoingCiphertextKey = 14,
}

impl DomainTag {
    /// Convert to field element for use in hash
    pub fn to_field(self) -> Fr {
        Fr::from(self as u64)
    }
}

impl From<DomainTag> for Fr {
    fn from(tag: DomainTag) -> Fr {
        tag.to_field()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tags_unique() {
        let tags = [
            DomainTag::NoteCommitment,
            DomainTag::Nullifier,
            DomainTag::AssetId,
            DomainTag::AssetAlpha,
            DomainTag::AssetTag,
            DomainTag::Ciphertext,
            DomainTag::MerkleNode,
            DomainTag::IncomingViewingKey,
            DomainTag::AuthorizationSecret,
            DomainTag::NullifierSecret,
            DomainTag::NullifierNonce,
            DomainTag::TransactionBinding,
            DomainTag::OutgoingViewingKey,
            DomainTag::OutgoingCiphertextKey,
        ];

        for (i, tag_i) in tags.iter().enumerate() {
            for (j, tag_j) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(tag_i.to_field(), tag_j.to_field());
                }
            }
        }
    }
}

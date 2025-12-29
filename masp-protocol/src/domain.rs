//! Domain separation tags for Poseidon hashing
//!
//! Each hash operation uses a unique domain tag to prevent cross-protocol attacks.
//! The tag is the first input to the hash function.
//!
//! **WARNING**: These values are FROZEN. Changing them breaks existing commitments/nullifiers.

/// Domain separation tags for different hash operations.
///
/// These are used as the first input to Poseidon hashes to ensure that
/// different operations cannot collide (e.g., a commitment cannot equal a nullifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DomainTag {
    /// Note commitment: binds all note fields together
    /// `cm = H(DOM, asset_id, amount, recipient, diversifier_index, nullifier_nonce, note_randomness)`
    NoteCommitment = 1,

    /// Nullifier derivation: unique identifier revealed on spend
    /// `nf = H(DOM, nsk, nullifier_nonce)`
    Nullifier = 2,

    /// Asset identifier: hides the actual token address
    /// `asset_id = H(DOM, token_address)`
    AssetId = 3,

    /// Ciphertext hash binding
    /// `ct_hash = H(DOM, ephemeral_key || ciphertext_bytes)`
    Ciphertext = 4,

    /// Transaction binding hash
    /// Binds the proof to the transaction intent / ordering
    TransactionBinding = 5,

    /// Nullifier nonce derivation for outputs
    /// `nullifier_nonce = H(DOM, tx_binding, output_index)`
    NullifierNonce = 6,

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

    /// Outgoing viewing key derivation
    /// `ovk = H(DOM, ak_x, nk_x)`
    OutgoingViewingKey = 11,

    /// Outgoing ciphertext key derivation
    /// `ock = H(DOM, ovk, epk_x, commitment)`
    OutgoingCiphertextKey = 12,
}

impl DomainTag {
    /// Convert to u64 for use in hash (as first limb of a 256-bit field element)
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Convert to 32-byte big-endian representation (for field element encoding)
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let val = self as u64;
        // Place u64 in the last 8 bytes (big-endian field representation)
        bytes[24] = (val >> 56) as u8;
        bytes[25] = (val >> 48) as u8;
        bytes[26] = (val >> 40) as u8;
        bytes[27] = (val >> 32) as u8;
        bytes[28] = (val >> 24) as u8;
        bytes[29] = (val >> 16) as u8;
        bytes[30] = (val >> 8) as u8;
        bytes[31] = val as u8;
        bytes
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
            DomainTag::Ciphertext,
            DomainTag::TransactionBinding,
            DomainTag::NullifierNonce,
            DomainTag::MerkleNode,
            DomainTag::IncomingViewingKey,
            DomainTag::AuthorizationSecret,
            DomainTag::NullifierSecret,
            DomainTag::OutgoingViewingKey,
            DomainTag::OutgoingCiphertextKey,
        ];

        for (i, tag_i) in tags.iter().enumerate() {
            for (j, tag_j) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(tag_i.as_u64(), tag_j.as_u64(), "Tags must be unique");
                }
            }
        }
    }

    #[test]
    fn test_to_be_bytes() {
        let bytes = DomainTag::NoteCommitment.to_be_bytes();
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[..31], [0u8; 31]);

        let bytes = DomainTag::OutgoingCiphertextKey.to_be_bytes();
        assert_eq!(bytes[31], 12);
    }
}

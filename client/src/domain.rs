//! Domain separation tags for Poseidon hashing
//!
//! Re-exports from `masp_protocol` with convenience methods for field conversion.

use crate::types::Fr;

// Re-export the canonical DomainTag from the shared crate
pub use masp_protocol::DomainTag;

/// Extension trait to convert DomainTag to field element
pub trait DomainTagExt {
    /// Convert to field element for use in hash
    fn to_field(self) -> Fr;
}

impl DomainTagExt for DomainTag {
    fn to_field(self) -> Fr {
        Fr::from(self.as_u64())
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

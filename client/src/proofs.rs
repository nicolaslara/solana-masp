//! ZK Proof types for MASP
//!
//! ## What We Prove
//!
//! A spend requires proving three things:
//!
//! 1. **Membership** - The note commitment exists in the store
//!    - Mock: Verified via Merkle path
//!    - Light Protocol: Verified via Groth16 validity proof
//!
//! 2. **Non-membership** - The nullifier has NOT been spent
//!    - Mock: HashSet.contains() returns false
//!    - Light Protocol: Address insert succeeds (fails if exists)
//!
//! 3. **Spend Validity** - The spender knows a valid note
//!    - Abstracted via SpendProver/ProofVerifier traits
//!    - Current: UltraPlonk
//!    - Proves: commitment matches note, nullifier derivation, balance, etc.
//!
//! ## Proof System Abstraction
//!
//! The SpendProver/ProofVerifier traits (in traits.rs) abstract over:
//! - UltraPlonk (current implementation)
//! - Future proving systems
//!
//! ## Crate Separation
//!
//! Designed for splitting into:
//! - `masp-proofs-core` - MembershipWitness, StoreId (no_std)
//! - `masp-prover` - SpendProver implementations (std, prove feature)
//! - `masp-verifier` - ProofVerifier implementations (no_std, verify feature)

use crate::types::{Anchor, Commitment, Fr};

// ============================================================================
// Membership Witness (backend-specific)
// ============================================================================

/// Witness for proving commitment membership
///
/// This is backend-specific:
/// - Mock: Contains Merkle path (siblings + indices)
/// - Light Protocol: Contains Groth16 validity proof bytes
#[derive(Debug, Clone)]
pub enum MembershipWitness {
    /// Mock/local Merkle tree - explicit path
    MerklePath {
        /// Sibling hashes from leaf to root
        siblings: Vec<Fr>,
        /// Path indices: false = left, true = right
        path_indices: Vec<bool>,
        /// Root this proves against
        root: Anchor,
    },

    /// Light Protocol validity proof - opaque bytes
    LightValidityProof {
        /// Compressed Groth16 proof
        proof_bytes: Vec<u8>,
        /// Root this proves against
        root: Anchor,
    },
}

impl MembershipWitness {
    /// Create a Merkle path witness
    pub fn merkle_path(siblings: Vec<Fr>, path_indices: Vec<bool>, root: Anchor) -> Self {
        Self::MerklePath {
            siblings,
            path_indices,
            root,
        }
    }

    /// Create a Light Protocol validity proof witness
    pub fn light_proof(proof_bytes: Vec<u8>, root: Anchor) -> Self {
        Self::LightValidityProof { proof_bytes, root }
    }

    /// Get the root this witness proves against
    pub fn root(&self) -> Anchor {
        match self {
            Self::MerklePath { root, .. } => *root,
            Self::LightValidityProof { root, .. } => *root,
        }
    }

    /// Verify membership locally (only works for MerklePath)
    pub fn verify_local(&self, commitment: Commitment) -> bool {
        match self {
            Self::MerklePath {
                siblings,
                path_indices,
                root,
            } => {
                use crate::hash::merkle_hash;

                let mut current = commitment;
                for (sibling, &is_right) in siblings.iter().zip(path_indices.iter()) {
                    current = if is_right {
                        merkle_hash(*sibling, current)
                    } else {
                        merkle_hash(current, *sibling)
                    };
                }
                current == *root
            }
            Self::LightValidityProof { .. } => {
                // Cannot verify Light proof locally without verifier
                false
            }
        }
    }

    /// Check if this is a mock/local witness
    pub fn is_local(&self) -> bool {
        matches!(self, Self::MerklePath { .. })
    }
}

// ============================================================================
// Store Identifier (backend-specific)
// ============================================================================

/// Identifier for looking up commitments in the store
///
/// Different backends use different identifier schemes:
/// - Mock: commitment itself (or position)
/// - Light Protocol: address (can be set = commitment)
///
/// This enum abstracts over the identifier type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StoreId {
    /// Use the commitment directly as identifier
    /// Works for mock backend where we control the tree
    Commitment(Commitment),

    /// Use a position/index
    /// Works when tree is append-only and we track positions
    Position(u64),

    /// Use an address (Light Protocol style)
    /// Can be set to commitment for direct lookup
    Address([u8; 32]),
}

impl StoreId {
    /// Create from commitment (for mock backend)
    pub fn from_commitment(cm: Commitment) -> Self {
        Self::Commitment(cm)
    }

    /// Create from position (alternative for mock)
    pub fn from_position(pos: u64) -> Self {
        Self::Position(pos)
    }

    /// Create from address (for Light Protocol)
    pub fn from_address(addr: [u8; 32]) -> Self {
        Self::Address(addr)
    }

    /// Get as commitment if that's what it is
    pub fn as_commitment(&self) -> Option<Commitment> {
        match self {
            Self::Commitment(cm) => Some(*cm),
            _ => None,
        }
    }

    /// Get as position if that's what it is
    pub fn as_position(&self) -> Option<u64> {
        match self {
            Self::Position(pos) => Some(*pos),
            _ => None,
        }
    }
}

// ============================================================================
// Mock Implementations
// ============================================================================

use crate::traits::{
    ProofBytes, ProofSystemError, ProofVerifier, SpendPrivateInputs, SpendProver, SpendPublicInputs,
};
use async_trait::async_trait;

/// Mock prover that always returns a valid-looking proof
pub struct MockSpendProver;

impl SpendProver for MockSpendProver {
    fn prove(
        &self,
        _public_inputs: &SpendPublicInputs,
        _private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        // Return a placeholder proof
        Ok(ProofBytes::new(vec![0u8; 32]))
    }

    fn system_name(&self) -> &'static str {
        "mock"
    }
}

/// Mock verifier that always returns true
pub struct MockProofVerifier;

#[async_trait]
impl ProofVerifier for MockProofVerifier {
    async fn verify_local(
        &self,
        _public_inputs: &SpendPublicInputs,
        _proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        Ok(true)
    }

    fn system_name(&self) -> &'static str {
        "mock"
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_witness_merkle_verify() {
        use crate::hash::merkle_hash;

        let leaf = Fr::from(42u64);
        let sibling = Fr::from(100u64);
        let root = merkle_hash(leaf, sibling);

        let witness = MembershipWitness::merkle_path(vec![sibling], vec![false], root);

        assert!(witness.verify_local(leaf));
        assert!(!witness.verify_local(Fr::from(999u64)));
    }

    #[test]
    fn test_membership_witness_light_cannot_verify_locally() {
        let witness = MembershipWitness::light_proof(vec![1, 2, 3], Fr::from(0u64));

        // Light proofs cannot be verified locally
        assert!(!witness.verify_local(Fr::from(42u64)));
    }

    #[tokio::test]
    async fn test_mock_prover_verifier() {
        let prover = MockSpendProver;
        let verifier = MockProofVerifier;

        let public = SpendPublicInputs {
            anchor: Fr::from(0u64),
            nullifier: Fr::from(111u64),
            output_commitments: vec![],
            tx_binding: Fr::from(0u64),
        };

        let private = SpendPrivateInputs {
            note_asset_id: Fr::from(1u64),
            note_amount: 100,
            note_recipient: Fr::from(999u64),
            note_nullifier_nonce: Fr::from(123u64),
            note_randomness: Fr::from(456u64),
            nk: Fr::from(789u64),
            membership_witness: MembershipWitness::merkle_path(vec![], vec![], Fr::from(0u64)),
        };

        let proof = prover.prove(&public, &private).unwrap();
        assert!(verifier.verify_local(&public, &proof).await.unwrap());
    }

    #[test]
    fn test_store_id_variants() {
        let cm = Fr::from(42u64);

        let id1 = StoreId::from_commitment(cm);
        assert_eq!(id1.as_commitment(), Some(cm));
        assert_eq!(id1.as_position(), None);

        let id2 = StoreId::from_position(5);
        assert_eq!(id2.as_position(), Some(5));
        assert_eq!(id2.as_commitment(), None);
    }
}

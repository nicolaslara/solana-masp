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

use crate::domain::DomainTag;
use crate::hash::{field_to_bytes, poseidon_hash};

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
    ProofBytes, ProofPublicInputs, ProofSystemError, ProofVerifier, SpendPrivateInputs, SpendProver,
};
use async_trait::async_trait;

fn mock_public_inputs_hash(public_inputs: &ProofPublicInputs) -> Fr {
    // Bind mock proof bytes to the public inputs so the mock verifier cannot accept
    // “the same proof” under different public inputs (prevents swap/malleability in mocks).
    //
    // This does NOT attempt to prove the private statements — those checks are performed by
    // `MockSpendProver` when it is used.
    let dom = DomainTag::TransactionBinding.to_field();
    match public_inputs {
        ProofPublicInputs::Shield(pi) => poseidon_hash(&[
            dom,
            Fr::from(1u64), // discriminator: shield
            pi.new_commitment,
            pi.public_asset_id,
            Fr::from(pi.public_amount),
        ]),
        ProofPublicInputs::Transfer(pi) => {
            let mut inputs = Vec::with_capacity(6 + pi.output_commitments.len());
            inputs.push(dom);
            inputs.push(Fr::from(2u64)); // discriminator: transfer
            inputs.push(pi.anchor);
            inputs.push(pi.input_commitment);
            inputs.push(pi.nullifier);
            inputs.push(pi.tx_binding);
            inputs.push(Fr::from(pi.output_commitments.len() as u64));
            inputs.extend_from_slice(&pi.output_commitments);
            poseidon_hash(&inputs)
        }
        ProofPublicInputs::Unshield(pi) => poseidon_hash(&[
            dom,
            Fr::from(3u64), // discriminator: unshield
            pi.anchor,
            pi.input_commitment,
            pi.nullifier,
            pi.tx_binding,
            Fr::from(pi.public_amount),
            pi.public_recipient,
            pi.public_asset_id,
        ]),
    }
}

/// Construct a mock proof payload that is valid **only** for the given public inputs.
///
/// This is useful for tests that need to exercise chain/mempool behavior without building
/// full private inputs (i.e., without running `MockSpendProver`).
pub fn mock_proof_for_public_inputs(public_inputs: &ProofPublicInputs) -> ProofBytes {
    ProofBytes::new(field_to_bytes(&mock_public_inputs_hash(public_inputs)).to_vec())
}

/// Explicit "amount is a u64" range assertion.
///
/// In the host-language reference implementation, amounts are already `u64`, so this check is
/// semantically a no-op. We keep it **explicit** here so the mock semantics match what the
/// real circuit must enforce (i.e., range-checks must be constraints, not assumptions).
fn mock_assert_amount_is_u64(amount: u64) -> Result<(), ProofSystemError> {
    let max: u128 = 1u128 << 64;
    if (amount as u128) >= max {
        return Err(ProofSystemError::VerificationFailed);
    }
    Ok(())
}

/// Spend authorization (ownership) check for v0 reference semantics.
///
/// Enforces: the prover knows the **SpendingKey** corresponding to the spent note’s recipient.
/// This prevents a watch-only FullViewingKey from spending, even if it can decrypt notes and
/// compute nullifiers.
fn mock_check_spend_authorization(private: &SpendPrivateInputs) -> Result<(), ProofSystemError> {
    let sk = crate::keys::SpendingKey::from_field(private.spending_key);
    let fvk = sk.to_full_viewing_key();

    // Bind the provided nk to the spending key material.
    if fvk.nk_field() != private.nk {
        return Err(ProofSystemError::VerificationFailed);
    }

    // Bind the note recipient (part of the commitment preimage) to this spending key.
    let expected_recipient = fvk
        .diversified_address(private.note_diversifier_index)
        .to_field();
    if expected_recipient != private.note_recipient {
        return Err(ProofSystemError::VerificationFailed);
    }

    Ok(())
}

fn mock_check_transfer(
    public: &crate::traits::SpendPublicInputs,
    private: &SpendPrivateInputs,
) -> Result<(), ProofSystemError> {
    use crate::note::Note;
    use crate::nullifier::compute_nullifier;

    // Explicit range-check statement (no-op in Rust, but must exist in circuits).
    mock_assert_amount_is_u64(private.note_amount)?;

    // Transaction binding hash (anti-malleability / intent binding).
    let expected_tx_binding = crate::tx_binding::tx_binding_transfer(
        public.anchor,
        public.input_commitment,
        public.nullifier,
        &public.output_commitments,
    );
    if public.tx_binding != expected_tx_binding {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (1) "This note is a member of the commitment set for this anchor"
    // In the mock environment, this is a Merkle path check.
    if private.membership_witness.root() != public.anchor {
        return Err(ProofSystemError::VerificationFailed);
    }
    if !private
        .membership_witness
        .verify_local(public.input_commitment)
    {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (2) "I know the note plaintext that hashes to the commitment"
    let in_note = Note::with_values(
        private.note_asset_id,
        private.note_amount,
        private.note_recipient,
        private.note_diversifier_index,
        private.note_nullifier_nonce,
        private.note_randomness,
    );
    if in_note.commitment() != public.input_commitment {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (2.5) "I am authorized to spend this note" (SpendingKey-only ownership).
    mock_check_spend_authorization(private)?;

    // (3) "The nullifier is derived correctly from the owner's key material"
    if compute_nullifier(private.nk, private.note_nullifier_nonce) != public.nullifier {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (4) "Outputs are well-formed and balance is conserved"
    if private.output_notes.len() != public.output_commitments.len() {
        return Err(ProofSystemError::InvalidPublicInputs);
    }
    let mut sum_out: u64 = 0;
    for (i, (note, cm)) in private
        .output_notes
        .iter()
        .zip(public.output_commitments.iter())
        .enumerate()
    {
        mock_assert_amount_is_u64(note.amount)?;
        if note.commitment() != *cm {
            return Err(ProofSystemError::VerificationFailed);
        }
        // Stage-0 rule: single-asset transfers only.
        if note.asset_id != private.note_asset_id {
            return Err(ProofSystemError::VerificationFailed);
        }

        // Output nullifier nonce derivation (ties outputs to this spend context).
        //
        // This matches the intended circuit statement:
        //   out_i.nullifier_nonce == H(DOM_NULLIFIER_NONCE, input_commitment, output_index)
        let expected_nonce = Note::derive_nullifier_nonce(public.input_commitment, i as u64);
        if note.nullifier_nonce != expected_nonce {
            return Err(ProofSystemError::VerificationFailed);
        }

        sum_out = sum_out.saturating_add(note.amount);
    }
    if sum_out != private.note_amount {
        return Err(ProofSystemError::VerificationFailed);
    }

    Ok(())
}

fn mock_check_unshield(
    public: &crate::traits::UnshieldPublicInputs,
    private: &SpendPrivateInputs,
) -> Result<(), ProofSystemError> {
    use crate::note::Note;
    use crate::nullifier::compute_nullifier;

    mock_assert_amount_is_u64(private.note_amount)?;
    mock_assert_amount_is_u64(public.public_amount)?;

    // Transaction binding hash (anti-malleability / intent binding).
    let expected_tx_binding = crate::tx_binding::tx_binding_unshield(
        public.anchor,
        public.input_commitment,
        public.nullifier,
        public.public_amount,
        public.public_recipient,
        public.public_asset_id,
    );
    if public.tx_binding != expected_tx_binding {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (1) "This note is a member of the commitment set for this anchor"
    if private.membership_witness.root() != public.anchor {
        return Err(ProofSystemError::VerificationFailed);
    }
    if !private
        .membership_witness
        .verify_local(public.input_commitment)
    {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (2) "I know the note plaintext that hashes to the commitment"
    let in_note = Note::with_values(
        private.note_asset_id,
        private.note_amount,
        private.note_recipient,
        private.note_diversifier_index,
        private.note_nullifier_nonce,
        private.note_randomness,
    );
    if in_note.commitment() != public.input_commitment {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (2.5) "I am authorized to spend this note" (SpendingKey-only ownership).
    mock_check_spend_authorization(private)?;

    // (3) "The nullifier is derived correctly from the owner's key material"
    if compute_nullifier(private.nk, private.note_nullifier_nonce) != public.nullifier {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (5) For unshield: "public withdrawal fields match the spent note"
    if public.public_amount != private.note_amount {
        return Err(ProofSystemError::VerificationFailed);
    }
    if public.public_asset_id != private.note_asset_id {
        return Err(ProofSystemError::VerificationFailed);
    }

    Ok(())
}

/// Mock prover that checks statements in Rust and encodes a mock proof payload.
pub struct MockSpendProver;

impl SpendProver for MockSpendProver {
    fn prove(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        // Reference-implementation mock: run the *intended circuit statements* in Rust,
        // then return a trivial proof marker ("true").
        match public_inputs {
            ProofPublicInputs::Shield(pi) => {
                use crate::note::Note;

                mock_assert_amount_is_u64(private_inputs.note_amount)?;
                mock_assert_amount_is_u64(pi.public_amount)?;

                // "I know the note plaintext that hashes to the commitment"
                let note = Note::with_values(
                    private_inputs.note_asset_id,
                    private_inputs.note_amount,
                    private_inputs.note_recipient,
                    private_inputs.note_diversifier_index,
                    private_inputs.note_nullifier_nonce,
                    private_inputs.note_randomness,
                );
                if note.commitment() != pi.new_commitment {
                    return Err(ProofSystemError::VerificationFailed);
                }
                // Public binding to amount/asset at the transparent boundary.
                if pi.public_amount != private_inputs.note_amount {
                    return Err(ProofSystemError::VerificationFailed);
                }
                if pi.public_asset_id != private_inputs.note_asset_id {
                    return Err(ProofSystemError::VerificationFailed);
                }
            }
            ProofPublicInputs::Transfer(pi) => mock_check_transfer(pi, private_inputs)?,
            ProofPublicInputs::Unshield(pi) => mock_check_unshield(pi, private_inputs)?,
        }
        Ok(mock_proof_for_public_inputs(public_inputs))
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
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // Bind verification to the public inputs (prevents “swap public inputs under same proof” in mocks).
        let expected = mock_proof_for_public_inputs(public_inputs);
        Ok(proof.as_bytes() == expected.as_bytes())
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
    use crate::traits::SpendPublicInputs;

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

        // Use a real note commitment so the mock prover/verifier can validate preimage + nullifier.
        let sk = crate::keys::SpendingKey::from_bytes(&[9u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let recipient_addr = fvk.diversified_address(0);
        let recipient = recipient_addr.to_field();
        let note = crate::note::Note::with_values(
            Fr::from(1u64),
            100,
            recipient,
            recipient_addr.diversifier_index,
            Fr::from(3u64),
            Fr::from(4u64),
        );
        let cm = note.commitment();
        let nk = fvk.nk_field();
        let nf = crate::nullifier::compute_nullifier(nk, note.nullifier_nonce);

        // Output note must satisfy the v0 "derived nullifier nonce" rule for spends.
        let out_nonce = crate::note::Note::derive_nullifier_nonce(cm, 0);
        let out_note = crate::note::Note::with_values(
            note.asset_id,
            note.amount,
            note.recipient,
            note.diversifier_index,
            out_nonce,
            note.note_randomness,
        );
        let out_cm = out_note.commitment();

        let public = SpendPublicInputs {
            // With an empty Merkle path, our MembershipWitness local check treats root==leaf.
            anchor: cm,
            input_commitment: cm,
            nullifier: nf,
            output_commitments: vec![out_cm],
            tx_binding: crate::tx_binding::tx_binding_transfer(cm, cm, nf, &[out_cm]),
        };

        let private = SpendPrivateInputs {
            spending_key: sk.as_field(),
            note_asset_id: note.asset_id,
            note_amount: note.amount,
            note_recipient: note.recipient,
            note_diversifier_index: note.diversifier_index,
            note_nullifier_nonce: note.nullifier_nonce,
            note_randomness: note.note_randomness,
            nk,
            membership_witness: MembershipWitness::merkle_path(vec![], vec![], cm),
            output_notes: vec![out_note],
        };

        let proof = prover
            .prove(&ProofPublicInputs::Transfer(public.clone()), &private)
            .unwrap();
        assert!(verifier
            .verify_local(&ProofPublicInputs::Transfer(public), &proof)
            .await
            .unwrap());
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

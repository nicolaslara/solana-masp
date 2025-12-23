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
use crate::hash::{field_to_bytes, poseidon2_hash_noir};

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
    ProofBytes, ProofPrivateInputs, ProofPublicInputs, ProofSystemError, ProofVerifier,
    SpendProver, TransferPrivateInputs, TransferPublicInputs, UnshieldPrivateInputs,
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
        ProofPublicInputs::Shield(pi) => {
            let inputs = [
                dom,
                Fr::from(1u64), // discriminator: shield
                pi.new_commitment,
                pi.public_asset_id,
                Fr::from(pi.public_amount),
            ];
            poseidon2_hash_noir(&inputs, 5)
        }
        ProofPublicInputs::Transfer(pi) => {
            // Bind to the canonical public input layout:
            // anchor, padded nullifiers, padded output commitments, counts, tx_binding.
            let mut inputs = Vec::with_capacity(
                1 + 1 + 1 + 2 + crate::tx_binding::MAX_INPUTS + crate::tx_binding::MAX_OUTPUTS + 1,
            );
            inputs.push(dom);
            inputs.push(Fr::from(2u64)); // discriminator: transfer
            inputs.push(pi.anchor);
            inputs.push(Fr::from(pi.input_count as u64));
            inputs.push(Fr::from(pi.output_count as u64));
            inputs.extend_from_slice(&pi.nullifiers);
            inputs.extend_from_slice(&pi.output_commitments);
            inputs.push(pi.tx_binding);
            poseidon2_hash_noir(&inputs, inputs.len() as u32)
        }
        ProofPublicInputs::Unshield(pi) => {
            let inputs = [
                dom,
                Fr::from(3u64), // discriminator: unshield
                pi.anchor,
                pi.nullifier,
                pi.tx_binding,
                Fr::from(pi.public_amount),
                Fr::from(pi.public_recipient_limbs[0]),
                Fr::from(pi.public_recipient_limbs[1]),
                Fr::from(pi.public_recipient_limbs[2]),
                Fr::from(pi.public_recipient_limbs[3]),
                pi.public_asset_id,
            ];
            poseidon2_hash_noir(&inputs, 11)
        }
    }
}

/// Construct a mock proof payload that is valid **only** for the given public inputs.
///
/// This is useful for tests that need to exercise chain/mempool behavior without building
/// full private inputs (i.e., without running `MockSpendProver`).
pub fn mock_proof_for_public_inputs(public_inputs: &ProofPublicInputs) -> ProofBytes {
    ProofBytes::new(field_to_bytes(&mock_public_inputs_hash(public_inputs)).to_vec())
}

/// Spend authorization (ownership) check for the current reference semantics.
///
/// Enforces: the prover knows the **SpendingKey** corresponding to the spent note's recipient.
///
/// This mirrors the circuit logic in `prove_spend_authorization`:
/// 1. Derive ask = H(DOM_AUTH_SECRET, spending_key)
/// 2. Derive nsk = H(DOM_NULLIFIER_SECRET, spending_key)
/// 3. Compute ak = ask * G, nk = nsk * G
/// 4. Derive ivk = H(DOM_IVK, ak.x, nk.x)
/// 5. Derive g_d = H(diversifier_index) * G
/// 6. Compute pk_d = ivk * g_d
/// 7. Assert note_recipient == pk_d.x
fn mock_check_spend_authorization(
    spending_key: Fr,
    note_recipient: Fr,
    note_diversifier_index: u64,
) -> Result<(), ProofSystemError> {
    use crate::domain::DomainTag;
    use crate::hash::poseidon2_hash_noir;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_grumpkin::{Fr as GrumpkinScalar, Projective as GrumpkinProjective};

    // Helper: convert BN254 Fr to Grumpkin scalar
    fn to_grumpkin_scalar(f: Fr) -> GrumpkinScalar {
        let bytes = f.into_bigint().to_bytes_le();
        GrumpkinScalar::from_le_bytes_mod_order(&bytes)
    }

    // Helper: convert Grumpkin base field to BN254 Fr
    fn from_grumpkin_base(fq: ark_grumpkin::Fq) -> Fr {
        let bytes = fq.into_bigint().to_bytes_le();
        Fr::from_le_bytes_mod_order(&bytes)
    }

    // 1. Derive ask and nsk from spending_key (using Poseidon2 to match Noir)
    let ask = poseidon2_hash_noir(
        &[DomainTag::AuthorizationSecret.to_field(), spending_key],
        2,
    );
    let nsk = poseidon2_hash_noir(&[DomainTag::NullifierSecret.to_field(), spending_key], 2);

    // 2. Compute ak = ask * G, nk = nsk * G
    let generator = GrumpkinProjective::generator();
    let ak = (generator * to_grumpkin_scalar(ask)).into_affine();
    let nk = (generator * to_grumpkin_scalar(nsk)).into_affine();

    // 3. Derive ivk = H(DOM_IVK, ak.x, nk.x) (using Poseidon2 to match Noir)
    let ak_x = from_grumpkin_base(ak.x);
    let nk_x = from_grumpkin_base(nk.x);
    let ivk = poseidon2_hash_noir(&[DomainTag::IncomingViewingKey.to_field(), ak_x, nk_x], 3);

    // 4. Derive g_d = H(diversifier_index) * G (using Poseidon2 to match Noir)
    let g_d_scalar_field = poseidon2_hash_noir(&[Fr::from(note_diversifier_index)], 1);
    let g_d = (generator * to_grumpkin_scalar(g_d_scalar_field)).into_affine();

    // 5. Compute pk_d = ivk * g_d
    let pk_d = (GrumpkinProjective::from(g_d) * to_grumpkin_scalar(ivk)).into_affine();

    // 6. Assert note_recipient == pk_d.x
    let expected_recipient = from_grumpkin_base(pk_d.x);
    if note_recipient != expected_recipient {
        return Err(ProofSystemError::VerificationFailed);
    }

    Ok(())
}

// ============================================================================
// Single-Asset Conservation
// ============================================================================
//
// IMPORTANT:
// - We intentionally do NOT use “single field equation tag schemes” for consensus-critical “no asset mixing” enforcement.
// - Current semantics: each spend action (transfer/unshield) is **single-asset**:
//   - all outputs must have the same `asset_id` as the input note
//   - value conservation is enforced as an integer equality on `u64` amounts

fn mock_check_transfer(
    public: &TransferPublicInputs,
    private: &TransferPrivateInputs,
) -> Result<(), ProofSystemError> {
    use crate::note::Note;
    use crate::nullifier::compute_nullifier;

    // Note: Amount range checks are enforced by Noir's u64 type system in the real circuits.
    // In Rust, amounts are already `u64`, so no explicit check is needed here.

    // (T2b) Transaction binding hash (anti-malleability / intent binding).
    // Statement: "This proof is bound to the transaction intent (anchor + counts + padded nullifiers),
    // so nullifiers/outputs cannot be swapped or spliced by an intermediary."
    let expected_tx_binding = crate::tx_binding::tx_binding_transfer(
        public.anchor,
        &public.nullifiers,
        public.input_count,
        public.output_count,
    );
    if public.tx_binding != expected_tx_binding {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (T7b) Count correctness + slot gating.
    // Statement: "Enabled flags match (input_count, output_count) and disabled slots are ignored."
    if private.input_count() != public.input_count || private.output_count() != public.output_count
    {
        return Err(ProofSystemError::InvalidPublicInputs);
    }

    // Enabled inputs: membership + preimage + spend authorization + nullifier correctness.
    let mut transfer_asset_id: Option<Fr> = None;
    let mut in_sum: u128 = 0;

    for i in 0..crate::tx_binding::MAX_INPUTS {
        let slot = &private.inputs[i];

        if !slot.enabled {
            // (T4) Disabled nullifier slot must be zero.
            // Statement: "Dummy input slots are fully zeroed in public state (nullifier == 0)."
            if public.nullifiers[i] != Fr::from(0u64) {
                return Err(ProofSystemError::VerificationFailed);
            }
            continue;
        }

        // (T3) Input preimage knowledge.
        // Statement: "I know the note plaintext that hashes to the commitment."
        //
        // Derive input commitment from private note fields (not a public input).
        let in_note = Note::with_values(
            slot.note_asset_id,
            slot.note_amount,
            slot.note_recipient,
            slot.note_diversifier_index,
            slot.note_nullifier_nonce,
            slot.note_randomness,
        );
        let input_commitment = in_note.commitment();

        // (T1) Membership.
        // Statement: "This note is a member of the commitment set for this anchor."
        if slot.membership_witness.root() != public.anchor {
            return Err(ProofSystemError::VerificationFailed);
        }
        if !slot.membership_witness.verify_local(input_commitment) {
            return Err(ProofSystemError::VerificationFailed);
        }

        // (T2) Spend authorization / ownership.
        // Statement: "I am authorized to spend this note (SpendingKey-only)."
        // Derives ask and nsk from spending_key internally.
        mock_check_spend_authorization(
            slot.spending_key,
            slot.note_recipient,
            slot.note_diversifier_index,
        )?;

        // (T4) Nullifier correctness.
        // Statement: "The revealed nullifier is correctly derived from the owner's key material and this note."
        // **SECURITY:** Uses nsk (secret), NOT nk.x (public). This ensures FVK holders can't spend.
        let sk = crate::keys::SpendingKey::from_field(slot.spending_key);
        let nsk = sk.nsk();
        let expected_nf = compute_nullifier(nsk, slot.note_nullifier_nonce);
        if expected_nf != public.nullifiers[i] {
            return Err(ProofSystemError::VerificationFailed);
        }

        // (T7) Asset rule (current semantics): single-asset per transfer.
        // Statement: "All enabled inputs share the same asset_id."
        match transfer_asset_id {
            None => transfer_asset_id = Some(slot.note_asset_id),
            Some(a) => {
                if a != slot.note_asset_id {
                    return Err(ProofSystemError::VerificationFailed);
                }
            }
        }

        in_sum = in_sum
            .checked_add(slot.note_amount as u128)
            .ok_or(ProofSystemError::VerificationFailed)?;
    }

    let transfer_asset_id = transfer_asset_id.ok_or(ProofSystemError::InvalidPublicInputs)?;

    // Enabled outputs: commitment correctness + output nonce derivation + single-asset + conservation.
    let mut out_sum: u128 = 0;
    for j in 0..crate::tx_binding::MAX_OUTPUTS {
        let slot = &private.outputs[j];

        if !slot.enabled {
            // (T5) Disabled output commitment must be zero.
            // Statement: "Dummy output slots are fully zeroed in public state (commitment == 0)."
            if public.output_commitments[j] != Fr::from(0u64) {
                return Err(ProofSystemError::VerificationFailed);
            }
            continue;
        }

        // (T5) Output well-formedness.
        // Statement: "I know the output note plaintext that hashes to the public output commitment."
        if slot.note.commitment() != public.output_commitments[j] {
            return Err(ProofSystemError::VerificationFailed);
        }

        // (T6) Output nonce derivation.
        // Statement: "out_j.nullifier_nonce is deterministically derived from (tx_binding, j)."
        let expected_nonce = crate::tx_binding::derive_output_nonce_nm(public.tx_binding, j as u64);
        if slot.note.nullifier_nonce != expected_nonce {
            return Err(ProofSystemError::VerificationFailed);
        }

        // (T7) Asset rule (current semantics): single-asset per transfer.
        // Statement: "All enabled outputs share the same asset_id as the enabled inputs."
        if slot.note.asset_id != transfer_asset_id {
            return Err(ProofSystemError::VerificationFailed);
        }

        out_sum = out_sum
            .checked_add(slot.note.amount as u128)
            .ok_or(ProofSystemError::VerificationFailed)?;
    }

    // (T7) Value conservation.
    // Statement: "No inflation: Σ(enabled_input.amount) == Σ(enabled_output.amount)."
    if in_sum != out_sum {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (T8) Ciphertext hash binding (Option 1A weak binding).
    // Statement: "Each enabled output has a non-zero ct_hash, each disabled output has ct_hash = 0."
    //
    // Note: In Option 1A, the circuit does NOT verify that ct_hash was correctly derived from
    // the ciphertext. It only binds ct_hash as a public input. The wallet verifies the actual
    // hash binding when accepting the note.
    for j in 0..crate::traits::MAX_OUTPUTS {
        let slot = &private.outputs[j];
        if slot.enabled {
            // Enabled outputs must have non-zero ct_hash (proof commits to the ciphertext binding)
            if public.ct_hashes[j] == Fr::from(0u64) {
                return Err(ProofSystemError::VerificationFailed);
            }
        } else {
            // Disabled outputs must have zero ct_hash (no ciphertext for dummy slots)
            if public.ct_hashes[j] != Fr::from(0u64) {
                return Err(ProofSystemError::VerificationFailed);
            }
        }
    }

    Ok(())
}

fn mock_check_unshield(
    public: &crate::traits::UnshieldPublicInputs,
    private: &UnshieldPrivateInputs,
) -> Result<(), ProofSystemError> {
    use crate::note::Note;
    use crate::nullifier::compute_nullifier;

    // Note: Amount range checks are enforced by Noir's u64 type system in the real circuits.
    // In Rust, amounts are already `u64`, so no explicit check is needed here.

    // Derive input commitment from private note fields (not a public input).
    let in_note = Note::with_values(
        private.note_asset_id,
        private.note_amount,
        private.note_recipient,
        private.note_diversifier_index,
        private.note_nullifier_nonce,
        private.note_randomness,
    );
    let input_commitment = in_note.commitment();

    // Transaction binding hash (anti-malleability / intent binding).
    // Note: input_commitment is NOT included in tx_binding; it's private (witness-only)
    // and the proof already binds to it via preimage knowledge.
    let expected_tx_binding = crate::tx_binding::tx_binding_unshield(
        public.anchor,
        public.nullifier,
        public.public_amount,
        public.public_recipient_limbs,
        public.public_asset_id,
    );
    if public.tx_binding != expected_tx_binding {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (1) "This note is a member of the commitment set for this anchor"
    if private.membership_witness.root() != public.anchor {
        return Err(ProofSystemError::VerificationFailed);
    }
    if !private.membership_witness.verify_local(input_commitment) {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (2) "I know the note plaintext that hashes to the commitment"
    // (already established by deriving `input_commitment` from the private note fields above)

    // (2.5) "I am authorized to spend this note" (SpendingKey-only ownership).
    // Derives ask and nsk from spending_key internally.
    mock_check_spend_authorization(
        private.spending_key,
        private.note_recipient,
        private.note_diversifier_index,
    )?;

    // (3) "The nullifier is derived correctly from the owner's key material"
    // **SECURITY:** Uses nsk (secret), NOT nk.x (public). This ensures FVK holders can't spend.
    let sk = crate::keys::SpendingKey::from_field(private.spending_key);
    let nsk = sk.nsk();
    if compute_nullifier(nsk, private.note_nullifier_nonce) != public.nullifier {
        return Err(ProofSystemError::VerificationFailed);
    }

    // (5) For unshield: public withdrawal must exactly match the spent note
    // (amount + asset id). This is hard-sound and prevents “asset mixing”.
    if public.public_asset_id != private.note_asset_id {
        return Err(ProofSystemError::VerificationFailed);
    }
    if public.public_amount != private.note_amount {
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
        private_inputs: &ProofPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        // Reference-implementation mock: run the *intended circuit statements* in Rust,
        // then return a trivial proof marker ("true").
        match (public_inputs, private_inputs) {
            (ProofPublicInputs::Shield(pi), ProofPrivateInputs::Shield(private_inputs)) => {
                use crate::note::Note;

                // Note: Amount range checks are enforced by Noir's u64 type system.
                // In Rust, amounts are already `u64`, so no explicit check is needed.

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

                // (S5) Ciphertext hash binding (Option 1A weak binding).
                // Statement: "Shield has a non-zero ct_hash, binding the output ciphertext to the proof."
                //
                // Note: In Option 1A, the circuit does NOT verify that ct_hash was correctly derived
                // from the ciphertext. It only binds ct_hash as a public input. The wallet verifies
                // the actual hash binding when accepting the note.
                if pi.ct_hash == Fr::from(0u64) {
                    return Err(ProofSystemError::VerificationFailed);
                }
            }
            (ProofPublicInputs::Transfer(pi), ProofPrivateInputs::Transfer(private_inputs)) => {
                mock_check_transfer(pi, private_inputs)?
            }
            (ProofPublicInputs::Unshield(pi), ProofPrivateInputs::Unshield(private_inputs)) => {
                mock_check_unshield(pi, private_inputs)?
            }
            _ => return Err(ProofSystemError::InvalidPublicInputs),
        }
        Ok(mock_proof_for_public_inputs(public_inputs))
    }

    fn system_name(&self) -> &'static str {
        "mock"
    }
}

/// Mock verifier that checks proof == poseidon2_hash(public_inputs)
pub struct MockProofVerifier;

#[async_trait]
impl ProofVerifier for MockProofVerifier {
    async fn verify_local(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // Bind verification to the public inputs (prevents "swap public inputs under same proof" in mocks).
        let expected = mock_proof_for_public_inputs(public_inputs);
        Ok(proof.as_bytes() == expected.as_bytes())
    }

    fn system_name(&self) -> &'static str {
        "mock"
    }
}

// ============================================================================
// On-Chain Mock Prover/Verifier (for testing with Solana program)
// ============================================================================
//
// ⚠️ FOR LOCAL TESTING ONLY - Feature-gated behind `onchain-mock`
//
// This code is only compiled when the `onchain-mock` feature is enabled.
// It generates proofs compatible with the on-chain `mock` verifier.

#[cfg(feature = "onchain-mock")]
mod onchain_mock {
    use super::*;
    use sha3::{Digest, Keccak256};

    /// Compute the expected on-chain mock proof for given public inputs.
    ///
    /// This uses keccak256 to match the on-chain mock verifier.
    /// Formula: proof = keccak256(circuit_type || public_inputs_bytes)
    pub fn onchain_mock_proof_for_public_inputs(public_inputs: &ProofPublicInputs) -> ProofBytes {
        let circuit_type: u8 = match public_inputs {
            ProofPublicInputs::Shield(_) => 0,
            ProofPublicInputs::Transfer(_) => 1,
            ProofPublicInputs::Unshield(_) => 2,
        };

        // Build the same byte layout as on-chain verifier:
        // [circuit_type: u8] [public_input_0: [u8; 32]] [public_input_1: [u8; 32]] ...
        let mut hasher = Keccak256::new();
        hasher.update([circuit_type]);

        match public_inputs {
            ProofPublicInputs::Shield(pi) => {
                hasher.update(field_to_bytes(&pi.new_commitment));
                hasher.update(field_to_bytes(&pi.public_asset_id));
                // public_amount as 32-byte big-endian
                let mut amount_bytes = [0u8; 32];
                amount_bytes[24..32].copy_from_slice(&pi.public_amount.to_be_bytes());
                hasher.update(amount_bytes);
                hasher.update(field_to_bytes(&pi.ct_hash));
            }
            ProofPublicInputs::Transfer(pi) => {
                hasher.update(field_to_bytes(&pi.anchor));
                for nf in &pi.nullifiers {
                    hasher.update(field_to_bytes(nf));
                }
                for cm in &pi.output_commitments {
                    hasher.update(field_to_bytes(cm));
                }
                // input_count as 32-byte big-endian
                let mut count_bytes = [0u8; 32];
                count_bytes[28..32].copy_from_slice(&pi.input_count.to_be_bytes());
                hasher.update(count_bytes);
                // output_count as 32-byte big-endian
                count_bytes = [0u8; 32];
                count_bytes[28..32].copy_from_slice(&pi.output_count.to_be_bytes());
                hasher.update(count_bytes);
                for ct in &pi.ct_hashes {
                    hasher.update(field_to_bytes(ct));
                }
                hasher.update(field_to_bytes(&pi.tx_binding));
            }
            ProofPublicInputs::Unshield(pi) => {
                hasher.update(field_to_bytes(&pi.anchor));
                hasher.update(field_to_bytes(&pi.nullifier));
                hasher.update(field_to_bytes(&pi.tx_binding));
                // public_amount as 32-byte big-endian
                let mut amount_bytes = [0u8; 32];
                amount_bytes[24..32].copy_from_slice(&pi.public_amount.to_be_bytes());
                hasher.update(amount_bytes);
                // recipient limbs as 32-byte big-endian each
                for limb in &pi.public_recipient_limbs {
                    let mut limb_bytes = [0u8; 32];
                    limb_bytes[24..32].copy_from_slice(&limb.to_be_bytes());
                    hasher.update(limb_bytes);
                }
                hasher.update(field_to_bytes(&pi.public_asset_id));
            }
        }

        let hash: [u8; 32] = hasher.finalize().into();
        ProofBytes::new(hash.to_vec())
    }

    /// On-chain mock prover for testing with Solana program.
    ///
    /// This prover generates proofs compatible with the on-chain `mock` verifier
    /// (keccak256-based). Use this when testing against a Solana program compiled
    /// with `local-testing` and `mock-proofs` features.
    ///
    /// ⚠️ This does NOT verify circuit statements - it just generates the expected hash.
    /// For statement checking, use `MockSpendProver` which validates in Rust.
    pub struct OnChainMockSpendProver;

    impl SpendProver for OnChainMockSpendProver {
        fn prove(
            &self,
            public_inputs: &ProofPublicInputs,
            _private_inputs: &ProofPrivateInputs,
        ) -> Result<ProofBytes, ProofSystemError> {
            // Note: Unlike MockSpendProver, we don't check statements here.
            // This is just for generating proofs that the on-chain mock verifier will accept.
            // For statement validation, use MockSpendProver first, then this for on-chain.
            Ok(onchain_mock_proof_for_public_inputs(public_inputs))
        }

        fn system_name(&self) -> &'static str {
            "onchain-mock"
        }
    }

    /// On-chain mock verifier (client-side, for testing on-chain mock proofs locally).
    ///
    /// This verifier checks proofs generated by `OnChainMockSpendProver`.
    pub struct OnChainMockProofVerifier;

    #[async_trait]
    impl ProofVerifier for OnChainMockProofVerifier {
        async fn verify_local(
            &self,
            public_inputs: &ProofPublicInputs,
            proof: &ProofBytes,
        ) -> Result<bool, ProofSystemError> {
            let expected = onchain_mock_proof_for_public_inputs(public_inputs);
            Ok(proof.as_bytes() == expected.as_bytes())
        }

        fn system_name(&self) -> &'static str {
            "onchain-mock"
        }
    }
}

#[cfg(feature = "onchain-mock")]
pub use onchain_mock::{
    onchain_mock_proof_for_public_inputs, OnChainMockProofVerifier, OnChainMockSpendProver,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{
        InputSlot, OutputSlot, TransferPrivateInputs, TransferPublicInputs, UnshieldPrivateInputs,
    };

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
        // Use nsk (secret) for nullifier, NOT nk.x (public)
        let nsk = sk.nsk();
        let nf = crate::nullifier::compute_nullifier(nsk, note.nullifier_nonce);

        let nullifiers = [nf, Fr::from(0u64), Fr::from(0u64)];
        let tx_binding = crate::tx_binding::tx_binding_transfer(cm, &nullifiers, 1, 1);

        // Output note must satisfy nonce derivation: H(DOM_NULLIFIER_NONCE, tx_binding, j).
        let out_nonce = crate::tx_binding::derive_output_nonce_nm(tx_binding, 0);
        let out_note = crate::note::Note::with_values(
            note.asset_id,
            note.amount,
            note.recipient,
            note.diversifier_index,
            out_nonce,
            note.note_randomness,
        );
        let out_cm = out_note.commitment();

        let public = TransferPublicInputs {
            // With an empty Merkle path, our MembershipWitness local check treats root==leaf.
            anchor: cm,
            nullifiers,
            output_commitments: [out_cm, Fr::from(0u64), Fr::from(0u64)],
            input_count: 1,
            output_count: 1,
            // Placeholder ct_hashes: non-zero for enabled outputs
            ct_hashes: TransferPublicInputs::placeholder_ct_hashes(1),
            tx_binding,
        };

        let private = TransferPrivateInputs {
            inputs: [
                InputSlot {
                    enabled: true,
                    note_asset_id: note.asset_id,
                    note_amount: note.amount,
                    note_recipient: note.recipient,
                    note_diversifier_index: note.diversifier_index,
                    note_nullifier_nonce: note.nullifier_nonce,
                    note_randomness: note.note_randomness,
                    spending_key: sk.as_field(),
                    membership_witness: MembershipWitness::merkle_path(vec![], vec![], cm),
                },
                InputSlot::default(),
                InputSlot::default(),
            ],
            outputs: [
                OutputSlot {
                    enabled: true,
                    note: out_note,
                },
                OutputSlot::default(),
                OutputSlot::default(),
            ],
        };

        let private_inputs = ProofPrivateInputs::Transfer(private);
        let proof = prover
            .prove(
                &ProofPublicInputs::Transfer(public.clone()),
                &private_inputs,
            )
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

    #[test]
    fn test_mock_transfer_rejects_output_asset_mismatch() {
        use crate::note::Note;

        let sk = crate::keys::SpendingKey::from_bytes(&[7u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let recipient_addr = fvk.diversified_address(0);
        let recipient = recipient_addr.to_field();

        let in_note = Note::with_values(
            Fr::from(1u64), // input asset
            100,
            recipient,
            recipient_addr.diversifier_index,
            Fr::from(3u64),
            Fr::from(4u64),
        );
        let in_cm = in_note.commitment();
        // Use nsk (secret) for nullifier, NOT nk.x (public)
        let nsk = sk.nsk();
        let nf = crate::nullifier::compute_nullifier(nsk, in_note.nullifier_nonce);

        let nullifiers = [nf, Fr::from(0u64), Fr::from(0u64)];
        let tx_binding = crate::tx_binding::tx_binding_transfer(in_cm, &nullifiers, 1, 1);

        // Create an output note with a DIFFERENT asset id but same amount,
        // which must be rejected by the single-asset conservation rule.
        let out_nonce = crate::tx_binding::derive_output_nonce_nm(tx_binding, 0);
        let out_note = Note::with_values(
            Fr::from(2u64), // different asset
            100,
            recipient,
            recipient_addr.diversifier_index,
            out_nonce,
            Fr::from(9u64),
        );
        let out_cm = out_note.commitment();

        let public = TransferPublicInputs {
            anchor: in_cm,
            nullifiers,
            output_commitments: [out_cm, Fr::from(0u64), Fr::from(0u64)],
            input_count: 1,
            output_count: 1,
            // Placeholder ct_hashes: non-zero for enabled outputs
            ct_hashes: TransferPublicInputs::placeholder_ct_hashes(1),
            tx_binding,
        };
        let private = TransferPrivateInputs {
            inputs: [
                InputSlot {
                    enabled: true,
                    note_asset_id: in_note.asset_id,
                    note_amount: in_note.amount,
                    note_recipient: in_note.recipient,
                    note_diversifier_index: in_note.diversifier_index,
                    note_nullifier_nonce: in_note.nullifier_nonce,
                    note_randomness: in_note.note_randomness,
                    spending_key: sk.as_field(),
                    membership_witness: MembershipWitness::merkle_path(vec![], vec![], in_cm),
                },
                InputSlot::default(),
                InputSlot::default(),
            ],
            outputs: [
                OutputSlot {
                    enabled: true,
                    note: out_note,
                },
                OutputSlot::default(),
                OutputSlot::default(),
            ],
        };

        let prover = MockSpendProver;
        let private_inputs = ProofPrivateInputs::Transfer(private);
        let err = prover
            .prove(&ProofPublicInputs::Transfer(public), &private_inputs)
            .unwrap_err();
        assert!(matches!(err, ProofSystemError::VerificationFailed));
    }

    #[test]
    fn test_mock_unshield_rejects_public_asset_mismatch() {
        use crate::note::Note;

        let sk = crate::keys::SpendingKey::from_bytes(&[8u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let recipient_addr = fvk.diversified_address(0);
        let recipient = recipient_addr.to_field();

        let note = Note::with_values(
            Fr::from(1u64), // note asset
            50,
            recipient,
            recipient_addr.diversifier_index,
            Fr::from(11u64),
            Fr::from(12u64),
        );
        let cm = note.commitment();
        // Use nsk (secret) for nullifier, NOT nk.x (public)
        let nsk = sk.nsk();
        let nf = crate::nullifier::compute_nullifier(nsk, note.nullifier_nonce);

        let public = crate::traits::UnshieldPublicInputs {
            anchor: cm,
            nullifier: nf,
            tx_binding: crate::tx_binding::tx_binding_unshield(
                cm,
                nf,
                50,
                [999u64, 0u64, 0u64, 0u64],
                Fr::from(2u64), // different public asset
            ),
            public_amount: 50,
            public_recipient_limbs: [999u64, 0u64, 0u64, 0u64],
            public_asset_id: Fr::from(2u64), // different from note.asset_id
        };

        let private = UnshieldPrivateInputs {
            spending_key: sk.as_field(),
            note_asset_id: note.asset_id,
            note_amount: note.amount,
            note_recipient: note.recipient,
            note_diversifier_index: note.diversifier_index,
            note_nullifier_nonce: note.nullifier_nonce,
            note_randomness: note.note_randomness,
            membership_witness: MembershipWitness::merkle_path(vec![], vec![], cm),
        };

        let prover = MockSpendProver;
        let private_inputs = ProofPrivateInputs::Unshield(private);
        let err = prover
            .prove(&ProofPublicInputs::Unshield(public), &private_inputs)
            .unwrap_err();
        assert!(matches!(err, ProofSystemError::VerificationFailed));
    }
}

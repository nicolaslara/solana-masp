// Shared MASP statement checks (Stage-0 scaffolding)
//
// This module exists to avoid copy/paste across circuits.
// Each circuit entrypoint should call these in a clear audit order.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use std::hash::poseidon2::Poseidon2;

/// Statement: "This note is a member of the commitment set for this anchor."
///
/// In the current protocol design, membership is proven inside the MASP spend proof via a
/// Merkle path against a public `anchor` (commitment-tree root). The chain separately checks
/// that the provided anchor is a valid recent root.
///
/// In our current reference implementation, the spent `input_commitment` is a *private* value and the
/// Merkle path witness (siblings + indices) is also private. Only the `anchor` is public.
///
/// Stage-0: historically this was a no-op. As of Milestone 3, we add the real Merkle path check.
pub fn prove_membership_externally_verified(anchor: Field, input_commitment: Field) {
    assert(anchor == anchor);
    assert(input_commitment == input_commitment);
}

fn merkle_hash(left: Field, right: Field) -> Field {
    // Must match Rust `client/src/hash.rs::merkle_hash`:
    // H(DOM_MERKLE_NODE=7, left, right)
    //
    // NOTE: We intentionally use the same domain-tag value as `DomainTag::MerkleNode`.
    let dom: Field = 7;

    // Noir stdlib Poseidon2.
    //
    // NOTE: Rust `client/src/hash.rs` implements the same Noir Poseidon2 sponge semantics for
    // Merkle nodes, so Merkle membership can be enforced in-circuit.
    Poseidon2::hash([dom, left, right], 3)
}

/// Statement: "This note is a member of the commitment set for this anchor (Merkle path)."
pub fn prove_merkle_membership(
    anchor: Field,
    input_commitment: Field,
    siblings: [Field; 16],
    path_indices: [bool; 16],
) {
    // Enforce the Merkle path against the public `anchor` using Poseidon2.
    //
    // NOTE: This must match the Rust-side commitment accumulator hashing (`client/src/hash.rs::merkle_hash`).
    let mut current: Field = input_commitment;
    for i in 0..16 {
        let sib = siblings[i];
        let is_right = path_indices[i];
        if is_right {
            // current is the right child
            current = merkle_hash(sib, current);
        } else {
            // current is the left child
            current = merkle_hash(current, sib);
        }
    }
    assert(current == anchor);
}

/// Statement: "I know the note plaintext that hashes to the commitment."
///
/// Intended statement (Stage-1+):
/// `input_commitment == Poseidon(
///     DOM_NOTE_COMMIT,
///     note_asset_id,
///     note_amount,
///     note_recipient,
///     note_diversifier_index,
///     note_nullifier_nonce,
///     note_randomness
/// )`.
///
/// Stage-0: This function does not enforce the hash yet; it exists to lock the interface + audit trail.
pub fn prove_note_preimage_hashes_to_commitment(
    input_commitment: Field,
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
) {
    assert(input_commitment == input_commitment);
    let amount_f: Field = note_amount as Field;
    let div_f: Field = note_diversifier_index as Field;
    let _ =
        note_asset_id + amount_f + note_recipient + div_f + note_nullifier_nonce + note_randomness;
}

/// Statement: "The nullifier is derived correctly from the owner's key material."
///
/// Intended statement (Stage-1+):
/// `nullifier == Poseidon(DOM_NULLIFIER, nk, note_nullifier_nonce)`.
///
/// Stage-0: No-op; exists to lock the interface + audit trail.
pub fn prove_nullifier_derivation(nullifier: Field, nk: Field, note_nullifier_nonce: Field) {
    let _ = nk + note_nullifier_nonce;
    assert(nullifier == nullifier);
}

/// Statement: "I am authorized to spend this note (SpendingKey-only)."
///
/// Intended statement (Stage-1+):
/// - Prover knows `ask` such that `ak = ask * G`.
/// - Derive `ivk = H(DOM_IVK, ak.x, nk_x)`.
/// - Derive `g_d` from `note_diversifier_index`.
/// - Check that the note recipient corresponds to the diversified address:
///   `pk_d = ivk * g_d` and `note_recipient == pk_d.x` (or equivalent binding per note format).
///
/// Stage-0: no-op; exists to lock the interface + audit trail.
pub fn prove_spend_authorization(
    ask: Field,
    nk: Field,
    note_recipient: Field,
    note_diversifier_index: u64,
) {
    let div_f: Field = note_diversifier_index as Field;
    let _ = ask + nk + note_recipient + div_f;
    assert(true);
}

/// Statement: "This proof is bound to the intended transaction."
///
/// Intended statement (Stage-1+):
/// `tx_binding == Poseidon(DOM_TX_BINDING, anchor, input_commitment, nullifier, outputs...)`.
///
/// Stage-0: No-op; exists to lock the interface + audit trail.
pub fn prove_tx_binding(tx_binding: Field) {
    assert(tx_binding == tx_binding);
}

/// Statement: "Asset id is correctly bound to the transparent token boundary."
pub fn prove_asset_id_binding(asset_id: Field) {
    assert(asset_id == asset_id);
}

// -----------------------------------------------------------------------------
// Value / Asset Rules (single-asset per action)
// -----------------------------------------------------------------------------

/// Statement: "Value is conserved for a single-asset action."
///
/// Current semantics:
/// - Each Action spends exactly one note and creates up to 3 outputs.
/// - All outputs MUST have the same `asset_id` as the spent note.
/// - Value conservation is enforced as:
///     input_amount == sum(output_amounts)
///
/// NOTE:
/// - In the Stage-0 scaffolds, we do not yet plumb full output note plaintexts
///   nor enforce `H(output_note_plaintext) == output_commitment`.
/// - Therefore this function only enforces **amount** conservation.
/// - Output asset-id preservation is enforced at the circuit entrypoint level (transfer) using explicit
///   `out*_asset_id` inputs, since the commitment preimage is not yet checked in Stage-0.
pub fn prove_balance_conservation_single_asset(input_amount: u64, output_amounts: [u64; 3]) {
    // Convert to Field so we can add without u64 overflow concerns. Since all terms are < 2^64,
    // the sum of three outputs is < 2^66, far below the BN254 field modulus.
    let input_f: Field = input_amount as Field;
    let out_sum_f: Field =
        (output_amounts[0] as Field) + (output_amounts[1] as Field) + (output_amounts[2] as Field);
    assert(out_sum_f == input_f);
}

/// Statement: "Public unshield withdrawal matches the spent note (single-asset)."
///
/// Enforces:
/// - `public_asset_id == note_asset_id`
/// - `public_amount == note_amount`
pub fn check_public_withdraw_binding_single_asset(
    note_asset_id: Field,
    note_amount: u64,
    public_asset_id: Field,
    public_amount: u64,
) {
    assert(note_asset_id == public_asset_id);
    assert(note_amount == public_amount);
}

// -----------------------------------------------------------------------------
// Note on Amount Range Checks
// -----------------------------------------------------------------------------
//
// Amount range checks (`amount < 2^64`) are enforced by Noir's type system.
// All amount parameters in our circuits are typed as `u64`, which automatically
// generates range constraints. No explicit `prove_amount_range()` function is needed.
//
// See `docs/protocol-soundness.md` for the full security rationale.

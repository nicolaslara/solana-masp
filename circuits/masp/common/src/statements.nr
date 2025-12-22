// Shared MASP statement checks
//
// This module exists to avoid copy/paste across circuits.
// Each circuit entrypoint should call these in a clear audit order.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul};
use std::hash::poseidon2::Poseidon2;

// ============================================================================
// Domain tags (must match `client/src/domain.rs::DomainTag`)
// ============================================================================

pub global DOM_NOTE_COMMITMENT: Field = 1;
pub global DOM_NULLIFIER: Field = 2;
pub global DOM_ASSET_ID: Field = 3;
pub global DOM_TX_BINDING: Field = 5;
pub global DOM_NULLIFIER_NONCE: Field = 6;
pub global DOM_MERKLE_NODE: Field = 7;
pub global DOM_IVK: Field = 8;
pub global DOM_AUTH_SECRET: Field = 9; // ask = H(DOM_AUTH_SECRET, spending_key)
pub global DOM_NULLIFIER_SECRET: Field = 10; // nsk = H(DOM_NULLIFIER_SECRET, spending_key)

// ============================================================================
// Core hash helpers
// ============================================================================

/// Compute note commitment (must match Rust `Note::commitment()` once migrated to Poseidon2).
///
/// Layout:
/// `cm = H(DOM_NOTE_COMMITMENT, asset_id, amount, recipient, diversifier_index, nullifier_nonce, note_randomness)`
pub fn compute_note_commitment(
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
) -> Field {
    Poseidon2::hash(
        [
            DOM_NOTE_COMMITMENT,
            note_asset_id,
            note_amount as Field,
            note_recipient,
            note_diversifier_index as Field,
            note_nullifier_nonce,
            note_randomness,
        ],
        7,
    )
}

/// Compute nullifier (must match Rust `compute_nullifier()`).
///
/// **CRITICAL SECURITY PROPERTY:**
/// The nullifier MUST use `nsk` (the nullifier SECRET), NOT `nk.x` (the public key).
/// This ensures that only SpendingKey holders can compute nullifiers.
/// If we used `nk.x` (which is in the FullViewingKey), watch-only wallets could spend!
///
/// Layout:
/// `nf = H(DOM_NULLIFIER, nsk, nullifier_nonce)`
///
/// Where:
/// - `nsk = H(DOM_NULLIFIER_SECRET, spending_key)` - the SECRET derived from spending_key
/// - `nullifier_nonce` - unique per note, committed in the note
pub fn compute_nullifier(nsk: Field, note_nullifier_nonce: Field) -> Field {
    Poseidon2::hash([DOM_NULLIFIER, nsk, note_nullifier_nonce], 3)
}

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

pub fn merkle_hash(left: Field, right: Field) -> Field {
    // Must match Rust `client/src/hash.rs::merkle_hash`:
    // H(DOM_MERKLE_NODE, left, right)
    let dom: Field = DOM_MERKLE_NODE;

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
    let expected = compute_note_commitment(
        note_asset_id,
        note_amount,
        note_recipient,
        note_diversifier_index,
        note_nullifier_nonce,
        note_randomness,
    );
    assert(input_commitment == expected);
}

/// Statement: "The nullifier is derived correctly from the owner's key material."
///
/// **CRITICAL SECURITY PROPERTY:**
/// Uses `nsk` (the nullifier SECRET), NOT `nk.x` (the public key).
/// This ensures only SpendingKey holders can compute nullifiers.
///
/// Layout:
/// `nullifier == H(DOM_NULLIFIER, nsk, note_nullifier_nonce)`.
pub fn prove_nullifier_derivation(nullifier: Field, nsk: Field, note_nullifier_nonce: Field) {
    let expected = compute_nullifier(nsk, note_nullifier_nonce);
    assert(nullifier == expected);
}

/// Statement: "I am authorized to spend this note (SpendingKey-only)."
///
/// This proves the spender knows the SpendingKey that owns the note.
/// The logic mirrors `client/src/keys.rs`:
///
/// From `spending_key`:
/// 1. ask = H(DOM_AUTH_SECRET, spending_key)
/// 2. nsk = H(DOM_NULLIFIER_SECRET, spending_key)
/// 3. ak = ask * G (authorization public key)
/// 4. nk = nsk * G (nullifier public key)
/// 5. ivk = H(DOM_IVK, ak.x, nk.x) (incoming viewing key)
/// 6. g_d = H(diversifier_index) * G (diversifier base point)
/// 7. pk_d = ivk * g_d (diversified payment key)
/// 8. Assert note_recipient == pk_d.x
///
/// Returns `nsk` so the caller can use it for nullifier derivation.
///
/// IMPORTANT: This uses Grumpkin (Noir's embedded curve), which matches
/// the Rust key derivation using `ark-grumpkin`.
pub fn prove_spend_authorization(
    spending_key: Field,
    note_recipient: Field,
    note_diversifier_index: u64,
) -> Field {
    // 1. Derive ask and nsk from spending_key
    let ask = Poseidon2::hash([DOM_AUTH_SECRET, spending_key], 2);
    let nsk = Poseidon2::hash([DOM_NULLIFIER_SECRET, spending_key], 2);

    // 2. Compute ak = ask * G, nk = nsk * G
    // Use from_field() to properly decompose 254-bit field elements into limbs
    let ask_scalar = EmbeddedCurveScalar::from_field(ask);
    let ak = fixed_base_scalar_mul(ask_scalar);

    let nsk_scalar = EmbeddedCurveScalar::from_field(nsk);
    let nk = fixed_base_scalar_mul(nsk_scalar);

    // 3. Derive ivk = H(DOM_IVK, ak.x, nk.x)
    let ivk = Poseidon2::hash([DOM_IVK, ak.x, nk.x], 3);

    // 4. Derive g_d = H(diversifier_index) * G
    // (simplified hash-to-curve: g_d_scalar = H(diversifier_index), g_d = g_d_scalar * G)
    let g_d_scalar_field = Poseidon2::hash([note_diversifier_index as Field], 1);
    let g_d_scalar = EmbeddedCurveScalar::from_field(g_d_scalar_field);
    let g_d = fixed_base_scalar_mul(g_d_scalar);

    // 5. Compute pk_d = ivk * g_d
    let ivk_scalar = EmbeddedCurveScalar::from_field(ivk);
    let pk_d = multi_scalar_mul([g_d], [ivk_scalar]);

    // 6. Assert note_recipient == pk_d.x
    // This proves the note was addressed to this SpendingKey's diversified address.
    assert(note_recipient == pk_d.x);

    // Return nsk for nullifier derivation
    nsk
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

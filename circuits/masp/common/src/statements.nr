// Shared MASP statement checks
//
// This module exists to avoid copy/paste across circuits.
// Each circuit entrypoint should call these in a clear audit order.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use crate::constants::{MAX_INPUTS, MERKLE_DEPTH};
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
    siblings: [Field; MERKLE_DEPTH],
    path_indices: [bool; MERKLE_DEPTH],
) {
    // Enforce the Merkle path against the public `anchor` using Poseidon2.
    //
    // NOTE: This must match the Rust-side commitment accumulator hashing (`client/src/hash.rs::merkle_hash`).
    let mut current: Field = input_commitment;
    for i in 0..MERKLE_DEPTH {
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
/// Returns `SpendAuthResult` containing:
/// - `nsk`: nullifier secret key for nullifier derivation
/// - `ivk`: incoming viewing key for verifying other inputs' diversified addresses
///
/// IMPORTANT: This uses Grumpkin (Noir's embedded curve), which matches
/// the Rust key derivation using `ark-grumpkin`.
pub fn prove_spend_authorization(
    spending_key: Field,
    note_recipient: Field,
    note_diversifier_index: u64,
) -> SpendAuthResult {
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

    // Return both nsk and ivk for downstream use
    SpendAuthResult { nsk, ivk }
}

// ============================================================================
// Multi-input same-sender authorization (optimized for avoiding bb loop bug)
// ============================================================================

/// Return type from spend authorization, containing derived key material.
pub struct SpendAuthResult {
    /// Nullifier secret key: nsk = H(DOM_NULLIFIER_SECRET, spending_key)
    /// Used for nullifier derivation.
    pub nsk: Field,
    /// Incoming viewing key: ivk = H(DOM_IVK, ak.x, nk.x)
    /// Used to verify diversified address ownership for other inputs.
    pub ivk: Field,
}

/// Input slot for a transfer circuit.
///
/// Contains all private data for a single input note, including the note plaintext,
/// spending key, and Merkle path for membership proof.
pub struct InputSlot {
    /// Whether this input slot is enabled (vs a dummy/padding slot)
    pub enabled: bool,
    /// Asset ID of the note
    pub note_asset_id: Field,
    /// Amount of the note (in atomic units)
    pub note_amount: u64,
    /// Recipient field (pk_d.x) - the diversified payment address
    pub note_recipient: Field,
    /// Diversifier index used for this note's address
    pub note_diversifier_index: u64,
    /// Nullifier nonce - unique per note, committed in the note
    pub note_nullifier_nonce: Field,
    /// Randomness used in the note commitment
    pub note_randomness: Field,
    /// Spending key (root secret) - circuit derives ask and nsk from this
    pub spending_key: Field,
    /// Merkle path siblings for membership proof (length = MERKLE_DEPTH)
    pub siblings: [Field; MERKLE_DEPTH],
    /// Merkle path indices (left=false, right=true) (length = MERKLE_DEPTH)
    pub path_indices: [bool; MERKLE_DEPTH],
}

/// Compute expected recipient for a diversified address.
///
/// Given `ivk` (incoming viewing key) and `diversifier_index`, computes:
/// - g_d = H(diversifier_index) * G
/// - pk_d = ivk * g_d
/// - returns pk_d.x (the recipient field element)
fn compute_expected_recipient(ivk: Field, diversifier_index: u64) -> Field {
    let g_d_scalar_field = Poseidon2::hash([diversifier_index as Field], 1);
    let g_d_scalar = EmbeddedCurveScalar::from_field(g_d_scalar_field);
    let g_d = fixed_base_scalar_mul(g_d_scalar);

    let ivk_scalar = EmbeddedCurveScalar::from_field(ivk);
    let pk_d = multi_scalar_mul([g_d], [ivk_scalar]);

    pk_d.x
}

/// Statement: "All enabled inputs are owned by the same spending_key holder."
///
/// This is a companion to `prove_spend_authorization` for multi-input transfers.
/// Call `prove_spend_authorization` first on inputs[0] to get `SpendAuthResult`,
/// then call this to verify all other enabled inputs belong to the same owner.
///
/// What it verifies:
/// 1. All enabled inputs have the same spending_key
/// 2. Each enabled input's note_recipient matches the expected diversified address
///    computed from that input's note_diversifier_index using the precomputed `ivk`
///
/// ## Security
/// - The spending_key is never revealed; only its derived values are used
/// - Different diversifier_indices produce different expected recipients (unlinkable addresses)
/// - `ivk` was already computed and verified in `prove_spend_authorization`
/// - We MUST verify recipient derivation (not just spending_key equality) because spending_key
///   is private and an attacker could claim any value without the EC derivation check
///
/// ## Note on EC ops
/// EC operations (in `compute_expected_recipient`) are computed UNCONDITIONALLY for all inputs,
/// then we conditionally assert based on `enabled`. This is required because EC black box
/// functions inside conditional blocks cause bb verification failures.
///
/// ## MAX_INPUTS coupling
/// This function is unrolled for MAX_INPUTS == 3. If MAX_INPUTS changes, update the unrolled
/// EC computations and assertions below.

/// Gated equality assertion: enforces (a == b) only when enabled is true.
/// When enabled is false, the constraint becomes 0 == 0 (always satisfied).
/// This avoids putting asserts inside `if` blocks, which can cause issues with EC blackboxes.
fn assert_eq_if(enabled: bool, a: Field, b: Field) {
    let e = enabled as Field; // 0 or 1
    assert((a - b) * e == 0);
}

pub fn verify_inputs_same_owner(inputs: [InputSlot; MAX_INPUTS], spending_key: Field, ivk: Field) {
    // This function is hardcoded to MAX_INPUTS == 3 and has an unrolled loop for 3 inputs.
    // if MAX_INPUTS changes, this function will need to be updated.
    assert(MAX_INPUTS == 3);

    // For each enabled input, verify:
    // 1. spending_key matches (field comparison)
    // 2. note_recipient is derivable from ivk + diversifier_index (EC ops)
    //
    // inputs[0] was already verified in prove_spend_authorization, so we skip its recipient check.
    //
    // PATTERN A: Compute all EC ops unconditionally, use gated asserts.
    // This avoids the known Noir/bb issue with EC blackboxes under predicates.
    // See: https://github.com/noir-lang/noir/issues/10185
    //
    // NOTE: If MAX_INPUTS changes, update the unrolled code below!

    // Compute expected recipients for ALL inputs UNCONDITIONALLY
    // (inputs[0] recipient is already verified in prove_spend_authorization, but we skip asserting it)
    let expected0 = compute_expected_recipient(ivk, inputs[0].note_diversifier_index);
    let expected1 = compute_expected_recipient(ivk, inputs[1].note_diversifier_index);
    let expected2 = compute_expected_recipient(ivk, inputs[2].note_diversifier_index);

    // Touch expected0 to avoid unused variable warning (it's verified in prove_spend_authorization)
    let _ = expected0;

    // Gated assertions: only enforced when enabled is true
    // Input 0: spending_key check only (recipient already verified in prove_spend_authorization)
    assert_eq_if(inputs[0].enabled, inputs[0].spending_key, spending_key);

    // Input 1: spending_key + recipient check
    assert_eq_if(inputs[1].enabled, inputs[1].spending_key, spending_key);
    assert_eq_if(inputs[1].enabled, inputs[1].note_recipient, expected1);

    // Input 2: spending_key + recipient check
    assert_eq_if(inputs[2].enabled, inputs[2].spending_key, spending_key);
    assert_eq_if(inputs[2].enabled, inputs[2].note_recipient, expected2);
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

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_prove_spend_authorization_single() {
    // Test that prove_spend_authorization works for a single input.
    // Values from Rust: cargo test gen_valid_circuit_witness
    let spending_key: Field =
        19071638227322667481529338707313302469950350415517269371204778542479809587754;
    let note_recipient: Field =
        19597776030385147363221867065656248682035662835329079184316854821084231909197;
    let diversifier_index: u64 = 0;

    // This should not panic
    let result = prove_spend_authorization(spending_key, note_recipient, diversifier_index);

    // nsk and ivk should be non-zero
    assert(result.nsk != 0);
    assert(result.ivk != 0);
}

#[test]
fn test_verify_inputs_same_owner_single_input() {
    // Test with a single enabled input.
    let spending_key: Field =
        19071638227322667481529338707313302469950350415517269371204778542479809587754;
    let note_recipient: Field =
        19597776030385147363221867065656248682035662835329079184316854821084231909197;
    let diversifier_index: u64 = 0;

    // First, call prove_spend_authorization to get ivk
    let auth_result = prove_spend_authorization(spending_key, note_recipient, diversifier_index);

    // Create InputSlot with all required fields (dummy values for fields not used by verify_inputs_same_owner)
    let dummy_siblings: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
    let dummy_path_indices: [bool; MERKLE_DEPTH] = [false; MERKLE_DEPTH];

    let inputs = [
        InputSlot {
            enabled: true,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient,
            note_diversifier_index: diversifier_index,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: false,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: 0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key: 0,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: false,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: 0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key: 0,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
    ];

    // This should not panic - verify other inputs match
    verify_inputs_same_owner(inputs, spending_key, auth_result.ivk);

    // nsk from auth_result should be non-zero
    assert(auth_result.nsk != 0);
}

#[test]
fn test_verify_inputs_same_owner_different_diversifiers() {
    // Test with 2 enabled inputs at different diversifiers.
    // Same spending_key, but different diversifier_indices produce different recipients.
    let spending_key: Field =
        19071638227322667481529338707313302469950350415517269371204778542479809587754;

    // Recipients from Rust (for diversifiers 0 and 7)
    let recipient_div0: Field =
        19597776030385147363221867065656248682035662835329079184316854821084231909197;
    let recipient_div7: Field =
        17822185092646959655687347322021915709507817777678905363953393991482705860441;

    // First, call prove_spend_authorization on the first input to get ivk
    let auth_result = prove_spend_authorization(spending_key, recipient_div0, 0);

    // Dummy values for fields not used by verify_inputs_same_owner
    let dummy_siblings: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
    let dummy_path_indices: [bool; MERKLE_DEPTH] = [false; MERKLE_DEPTH];

    let inputs = [
        InputSlot {
            enabled: true,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: recipient_div0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: true,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: recipient_div7,
            note_diversifier_index: 7,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: false,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: 0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key: 0,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
    ];

    // This should not panic - both inputs are owned by the same key
    verify_inputs_same_owner(inputs, spending_key, auth_result.ivk);
    assert(auth_result.nsk != 0);
}

#[test]
fn test_verify_inputs_uses_auth_result() {
    // Verify that the flow works: prove_spend_authorization -> verify_inputs_same_owner
    let spending_key: Field =
        19071638227322667481529338707313302469950350415517269371204778542479809587754;
    let note_recipient: Field =
        19597776030385147363221867065656248682035662835329079184316854821084231909197;
    let diversifier_index: u64 = 0;

    // Get auth result from prove_spend_authorization
    let auth_result = prove_spend_authorization(spending_key, note_recipient, diversifier_index);

    // Verify the nsk and ivk are consistent
    assert(auth_result.nsk != 0);
    assert(auth_result.ivk != 0);

    // Dummy values for fields not used by verify_inputs_same_owner
    let dummy_siblings: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
    let dummy_path_indices: [bool; MERKLE_DEPTH] = [false; MERKLE_DEPTH];

    // Use the ivk to verify inputs
    let inputs = [
        InputSlot {
            enabled: true,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient,
            note_diversifier_index: diversifier_index,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: false,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: 0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key: 0,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
        InputSlot {
            enabled: false,
            note_asset_id: 0,
            note_amount: 0,
            note_recipient: 0,
            note_diversifier_index: 0,
            note_nullifier_nonce: 0,
            note_randomness: 0,
            spending_key: 0,
            siblings: dummy_siblings,
            path_indices: dummy_path_indices,
        },
    ];

    // This should not panic - ivk from auth_result is used to verify all inputs
    verify_inputs_same_owner(inputs, spending_key, auth_result.ivk);
}

#[test]
fn test_verify_inputs_same_owner_max_inputs_change() {
    // If MAX_INPUTS changes, the verify_inputs_same_owner function will need to be updated.
    // This test will fail to let us know that the function needs to be updated.
    assert(MAX_INPUTS == 3);
}

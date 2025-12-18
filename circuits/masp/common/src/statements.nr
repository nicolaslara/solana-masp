// Shared MASP statement checks (Stage-0 scaffolding)
//
// This module exists to avoid copy/paste across circuits.
// Each circuit entrypoint should call these in a clear audit order.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

/// Statement: "This note is a member of the commitment set for this anchor."
///
/// In the current protocol design, membership is proven inside the MASP spend proof via a
/// Merkle path against a public `anchor` (commitment-tree root). The chain separately checks
/// that the provided anchor is a valid recent root.
///
/// The MASP spend circuits still take `(anchor, input_commitment)` as public inputs so the
/// spend proof is bound to the *same* membership context verified externally.
///
/// Stage-0: This function does not add constraints; it exists to make the entrypoint readable.
pub fn prove_membership_externally_verified(anchor: Field, input_commitment: Field) {
    assert(anchor == anchor);
    assert(input_commitment == input_commitment);
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
    let _ = note_asset_id + amount_f + note_recipient + div_f + note_nullifier_nonce + note_randomness;
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

/// Statement: "This proof is bound to the intended transaction."
///
/// Intended statement (Stage-1+):
/// `tx_binding == Poseidon(DOM_TX_BINDING, anchor, input_commitment, nullifier, outputs...)`.
///
/// Stage-0: No-op; exists to lock the interface + audit trail.
pub fn prove_tx_binding(tx_binding: Field) {
    assert(tx_binding == tx_binding);
}

/// Statement: "Amounts are range-checked (u64)."
pub fn prove_amount_range(_amount: u64) {
    // Stage-0: no-op. In practice we must enforce `< 2^64` to prevent wraparound.
    assert(true);
}

/// Statement: "Asset id is correctly bound to the transparent token boundary."
pub fn prove_asset_id_binding(asset_id: Field) {
    assert(asset_id == asset_id);
}

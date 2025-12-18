// MASP Shield Circuit (Deposit) - Stage 0 Scaffold
//
// Goal:
// - Keep a production-shaped *interface* for shield (deposit).
// - Keep constraints mostly "no-op" for now, but make the *entrypoint narrative* auditable:
//   `main` should call one function per statement we intend to prove.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use dep::masp_common::{prove_amount_range, prove_asset_id_binding};

// -----------------------------------------------------------------------------
// Statement check functions (Stage-0 placeholders)
// -----------------------------------------------------------------------------

/// Statement: "I know the note plaintext that hashes to the new commitment."
///
/// Intended statement (Stage-1+):
/// `new_commitment == Poseidon(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)`.
fn prove_new_commitment_is_note_preimage_hash(
    new_commitment: Field,
    asset_id: Field,
    amount: u64,
    recipient: Field,
    diversifier_index: u64,
    nullifier_nonce: Field,
    note_randomness: Field,
) {
    assert(new_commitment == new_commitment);
    let _ = asset_id
        + (amount as Field)
        + recipient
        + (diversifier_index as Field)
        + nullifier_nonce
        + note_randomness;
}

/// 1.2 Amount range check: implemented in `masp_common` (placeholder).
/// 1.3 Asset binding: implemented in `masp_common` (placeholder).

// -----------------------------------------------------------------------------
// Internal structs (for readability inside `main`)
// -----------------------------------------------------------------------------

struct ShieldPublic {
    new_commitment: Field,
    asset_id: Field,
    amount: u64,
}

struct ShieldPrivate {
    recipient: Field,
    diversifier_index: u64,
    nullifier_nonce: Field,
    note_randomness: Field,
}

fn main(
    // Public inputs (production-shaped)
    new_commitment: pub Field,
    public_asset_id: pub Field,
    public_amount: pub u64,
    // Private inputs (production-shaped)
    recipient: Field,
    diversifier_index: u64,
    nullifier_nonce: Field,
    note_randomness: Field,
) {
    let public = ShieldPublic { new_commitment, asset_id: public_asset_id, amount: public_amount };
    let private = ShieldPrivate { recipient, diversifier_index, nullifier_nonce, note_randomness };

    // Protocol narrative (Stage-0 scaffolding):
    //
    // - "Amounts are range-checked (u64)"
    prove_amount_range(public.amount);
    //
    // - "Asset id is correctly bound to the transparent token boundary"
    prove_asset_id_binding(public.asset_id);
    //
    // - "I know the note plaintext that hashes to the new commitment"
    prove_new_commitment_is_note_preimage_hash(
        public.new_commitment,
        public.asset_id,
        public.amount,
        private.recipient,
        private.diversifier_index,
        private.nullifier_nonce,
        private.note_randomness,
    );
}

// MASP Unshield Circuit (Withdraw) - Stage 0 Scaffold
//
// Goal:
// - Keep a production-shaped *interface* for unshield (withdraw).
// - Keep constraints mostly "no-op" for now, but make the *entrypoint narrative* auditable:
//   `main` should call one function per statement we intend to prove.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use dep::masp_common::{
    prove_membership_externally_verified, prove_note_preimage_hashes_to_commitment,
    prove_nullifier_derivation,
};

// -----------------------------------------------------------------------------
// Statement check functions (Stage-0 placeholders)
// -----------------------------------------------------------------------------

/// Statement: "The spender is authorized to spend this note."
fn prove_ownership_authorization() {
    assert(true);
}

/// 3.5 Public output binding (Stage-0 partial)
///
/// Intended statement (Stage-1+):
/// `note.amount == public_amount` and `note.asset_id == public_asset_id`.
fn check_public_withdraw_binding(
    public_amount: u64,
    public_asset_id: Field,
    note_amount: u64,
    note_asset_id: Field,
) {
    assert(public_amount == note_amount);
    assert(public_asset_id == note_asset_id);
}

// -----------------------------------------------------------------------------
// Internal structs (for readability inside `main`)
// -----------------------------------------------------------------------------

struct Note {
    asset_id: Field,
    amount: u64,
    recipient: Field,
    nullifier_nonce: Field,
    note_randomness: Field,
}

struct UnshieldPublic {
    anchor: Field,
    input_commitment: Field,
    nullifier: Field,
    public_amount: u64,
    public_recipient: Field,
    public_asset_id: Field,
}

struct UnshieldPrivate {
    note: Note,
    nk: Field,
}

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    input_commitment: pub Field,
    nullifier: pub Field,
    public_amount: pub u64,
    public_recipient: pub Field,
    public_asset_id: pub Field,
    // Private inputs (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
) {
    let public = UnshieldPublic {
        anchor,
        input_commitment,
        nullifier,
        public_amount,
        public_recipient,
        public_asset_id,
    };
    let private = UnshieldPrivate {
        note: Note {
            asset_id: note_asset_id,
            amount: note_amount,
            recipient: note_recipient,
            nullifier_nonce: note_nullifier_nonce,
            note_randomness,
        },
        nk,
    };

    // Protocol narrative (Stage-0 scaffolding):
    //
    // - "This note is a member of the commitment set for this anchor"
    prove_membership_externally_verified(public.anchor, public.input_commitment);
    //
    // - "I know the note plaintext that hashes to the commitment"
    prove_note_preimage_hashes_to_commitment(
        public.input_commitment,
        private.note.asset_id,
        private.note.amount,
        private.note.recipient,
        private.note.nullifier_nonce,
        private.note.note_randomness,
    );
    //
    // - "The nullifier is derived correctly from the owner's key material"
    prove_nullifier_derivation(public.nullifier, private.nk, private.note.nullifier_nonce);
    prove_ownership_authorization();
    //
    // - For unshield: "public withdrawal fields match the spent note"
    check_public_withdraw_binding(
        public.public_amount,
        public.public_asset_id,
        private.note.amount,
        private.note.asset_id,
    );

    // Touch remaining public input (recipient encoding decision is deferred).
    assert(public.public_recipient == public.public_recipient);
}

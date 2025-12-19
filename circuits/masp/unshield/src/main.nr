// MASP Unshield Circuit (Withdraw) - Stage 0 Scaffold
//
// Goal:
// - Keep a production-shaped *interface* for unshield (withdraw).
// - Keep constraints mostly "no-op" for now, but make the *entrypoint narrative* auditable:
//   `main` should call one function per statement we intend to prove.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use dep::masp_common::{
    check_public_withdraw_binding_single_asset, prove_merkle_membership,
    prove_note_preimage_hashes_to_commitment, prove_nullifier_derivation, prove_spend_authorization,
    prove_tx_binding,
};

/// Public withdrawal binding (single-asset semantics).
fn check_public_withdraw_binding_single_asset_action(
    note_asset_id: Field,
    note_amount: u64,
    public_asset_id: Field,
    public_amount: u64,
) {
    check_public_withdraw_binding_single_asset(
        note_asset_id,
        note_amount,
        public_asset_id,
        public_amount,
    );
}

// -----------------------------------------------------------------------------
// Internal structs (for readability inside `main`)
// -----------------------------------------------------------------------------

struct Note {
    asset_id: Field,
    amount: u64,
    recipient: Field,
    diversifier_index: u64,
    nullifier_nonce: Field,
    note_randomness: Field,
}

struct UnshieldPublic {
    anchor: Field,
    nullifier: Field,
    tx_binding: Field,
    public_amount: u64,
    public_recipient: Field,
    public_asset_id: Field,
}

struct UnshieldPrivate {
    note: Note,
    nk: Field,
    ask: Field,
}

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    nullifier: pub Field,
    tx_binding: pub Field,
    public_amount: pub u64,
    public_recipient: pub Field,
    public_asset_id: pub Field,
    // Private-only (wallet-local): spent commitment (not a public input)
    input_commitment: Field,
    // Private Merkle path witness (leaf -> root)
    siblings: [Field; 16],
    path_indices: [bool; 16],
    // Private inputs (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
    ask: Field,
) {
    let public = UnshieldPublic {
        anchor,
        nullifier,
        tx_binding,
        public_amount,
        public_recipient,
        public_asset_id,
    };
    let private = UnshieldPrivate {
        note: Note {
            asset_id: note_asset_id,
            amount: note_amount,
            recipient: note_recipient,
            diversifier_index: note_diversifier_index,
            nullifier_nonce: note_nullifier_nonce,
            note_randomness,
        },
        nk,
        ask,
    };

    // Protocol narrative (Stage-0 scaffolding):
    //
    // - "This note is a member of the commitment set for this anchor"
    prove_merkle_membership(public.anchor, input_commitment, siblings, path_indices);
    //
    // - "I know the note plaintext that hashes to the commitment"
    prove_note_preimage_hashes_to_commitment(
        input_commitment,
        private.note.asset_id,
        private.note.amount,
        private.note.recipient,
        private.note.diversifier_index,
        private.note.nullifier_nonce,
        private.note.note_randomness,
    );
    //
    // - "The nullifier is derived correctly from the owner's key material"
    prove_nullifier_derivation(public.nullifier, private.nk, private.note.nullifier_nonce);
    prove_spend_authorization(
        private.ask,
        private.nk,
        private.note.recipient,
        private.note.diversifier_index,
    );
    //
    // - "This proof is bound to the intended unshield intent"
    prove_tx_binding(public.tx_binding);
    //
    // - For unshield: "public withdrawal matches spent note (single-asset)"
    check_public_withdraw_binding_single_asset_action(
        private.note.asset_id,
        private.note.amount,
        public.public_asset_id,
        public.public_amount,
    );

    // Touch remaining public input (recipient encoding decision is deferred).
    assert(public.public_recipient == public.public_recipient);
}

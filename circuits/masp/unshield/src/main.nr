// MASP Unshield Circuit (Withdraw) - Stage 0 Scaffold
//
// Goal:
// - Keep a production-shaped *interface* for unshield (withdraw).
// - Keep constraints mostly "no-op" for now, but make the *entrypoint narrative* auditable:
//   `main` should call one function per statement we intend to prove.
//
// Security requirements: see `docs/circuit-security-requirements.md`.

use dep::masp_common::{
    check_public_withdraw_binding_single_asset, compute_note_commitment, prove_merkle_membership,
    prove_note_preimage_hashes_to_commitment, prove_nullifier_derivation, prove_spend_authorization,
};

use std::hash::poseidon2::Poseidon2;

// Domain tags (must match `client/src/domain.rs::DomainTag`)
global DOM_TX_BINDING: Field = 5;

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
    public_recipient_limbs: [u64; 4],
    public_asset_id: Field,
}

struct UnshieldPrivate {
    note: Note,
    // Spending key (root secret).
    // Circuit derives: ask = H(DOM_AUTH_SECRET, spending_key), nsk = H(DOM_NULLIFIER_SECRET, spending_key)
    spending_key: Field,
}

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    nullifier: pub Field,
    tx_binding: pub Field,
    public_amount: pub u64,
    public_recipient_limbs: pub [u64; 4],
    public_asset_id: pub Field,
    // Private inputs (production-shaped)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    // Spending key (root secret). Circuit derives ask/nsk from it.
    spending_key: Field,
    // Private Merkle path witness (leaf -> root)
    siblings: [Field; 16],
    path_indices: [bool; 16],
) {
    let public = UnshieldPublic {
        anchor,
        nullifier,
        tx_binding,
        public_amount,
        public_recipient_limbs,
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
        spending_key,
    };

    // Recompute the spent commitment from the note plaintext (private).
    let input_commitment = compute_note_commitment(
        private.note.asset_id,
        private.note.amount,
        private.note.recipient,
        private.note.diversifier_index,
        private.note.nullifier_nonce,
        private.note.note_randomness,
    );

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
    // - "I am authorized to spend this note (SpendingKey-only)" + nullifier derivation
    // prove_spend_authorization derives ask/nsk from spending_key and returns nsk.
    let nsk = prove_spend_authorization(
        private.spending_key,
        private.note.recipient,
        private.note.diversifier_index,
    );
    // - "The nullifier is derived correctly from the owner's key material"
    // **SECURITY:** Uses nsk (SECRET), NOT nk.x (public). This ensures FVK holders can't spend.
    prove_nullifier_derivation(public.nullifier, nsk, private.note.nullifier_nonce);
    //
    // - "This proof is bound to the intended unshield intent"
    let expected_tx_binding = Poseidon2::hash(
        [
            DOM_TX_BINDING,
            3, // discriminator: unshield
            public.anchor,
            public.nullifier,
            public.public_amount as Field,
            public.public_recipient_limbs[0] as Field,
            public.public_recipient_limbs[1] as Field,
            public.public_recipient_limbs[2] as Field,
            public.public_recipient_limbs[3] as Field,
            public.public_asset_id,
        ],
        10,
    );
    assert(public.tx_binding == expected_tx_binding);
    //
    // - For unshield: "public withdrawal matches spent note (single-asset)"
    check_public_withdraw_binding_single_asset_action(
        private.note.asset_id,
        private.note.amount,
        public.public_asset_id,
        public.public_amount,
    );

    // Touch remaining public input (recipient encoding decision is deferred).
    // Statement: "The public recipient bytes (limb encoding) are bound as public inputs."
    assert(public.public_recipient_limbs[0] == public.public_recipient_limbs[0]);
    assert(public.public_recipient_limbs[1] == public.public_recipient_limbs[1]);
    assert(public.public_recipient_limbs[2] == public.public_recipient_limbs[2]);
    assert(public.public_recipient_limbs[3] == public.public_recipient_limbs[3]);
}

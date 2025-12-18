// MASP Transfer Circuit (Orchard-style Action) - Stage 0 Scaffold
//
// Goal:
// - Keep a production-shaped *interface* (inputs/outputs) for the MASP transfer action.
// - Keep constraints mostly "no-op" for now, but make the *entrypoint narrative* auditable:
//   `main` should call one function per statement we intend to prove.
//
// Security requirements: see `docs/circuit-security-requirements.md`.
//
// Output structure (up to 3 outputs):
// - output_commitment_0: recipient note (required)
// - output_commitment_1: change note (optional, 0 if unused)
// - output_commitment_2: fee note (optional, 0 if unused)

use dep::masp_common::{
    prove_membership_externally_verified, prove_note_preimage_hashes_to_commitment,
    prove_nullifier_derivation, prove_tx_binding,
};

// -----------------------------------------------------------------------------
// Statement check functions (Stage-0 placeholders)
// -----------------------------------------------------------------------------

/// Statement: "The spender is authorized to spend this note."
///
/// This will eventually be the full Orchard/Sapling-style ownership authorization proof.
/// Stage-0: no-op (scaffolding), but we keep it as a named statement for auditability.
fn check_ownership_authorization() {
    assert(true);
}

/// Statement: "Each output has a correctly derived nullifier nonce."
///
/// Intended statement (Stage-1+):
/// `out_i.nullifier_nonce == Poseidon(DOM_NULLIFIER_NONCE, input_commitment, output_index)`.
///
/// Note: requires output note plaintext inputs (not plumbed yet).
fn prove_output_nullifier_nonce_derivation() {
    assert(true);
}

/// Statement: "Outputs are well-formed notes (commitments match their note plaintext)."
///
/// Intended statement (Stage-1+):
/// `output_commitment_i == Poseidon(DOM_NOTE_COMMIT, out_i.note_fields...)` for each output.
///
/// Note: we do not yet pass full output note plaintexts; we only plumb commitments + values.
fn prove_output_commitments_well_formed(
    out0: Field,
    out1: Field,
    out2: Field,
    out0_value: u64,
    out1_value: u64,
    out2_value: u64,
) {
    assert(out0 == out0);
    assert(out1 == out1);
    assert(out2 == out2);
    let _ = (out0_value as Field) + (out1_value as Field) + (out2_value as Field);
}

/// Statement: "Value is conserved (and asset rules hold)."
///
/// Intended statement (Stage-1 single-asset):
/// `input_amount == out0_amount + out1_amount (+ fee)`.
///
/// Multi-asset will later be done via alpha tags.
fn prove_balance_conservation(
    _note_amount: u64,
    _out0_value: u64,
    _out1_value: u64,
    _out2_value: u64,
) {
    // Stage-0: no-op (will be enforced later).
    assert(true);
}

/// 2.10 Transaction binding (placeholder)
/// Implemented in `masp_common`.

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

struct TransferPublic {
    anchor: Field,
    input_commitment: Field,
    nullifier: Field,
    output_commitments: [Field; 3],
    tx_binding: Field,
}

struct TransferPrivate {
    note: Note,
    nk: Field,
    out_values: [u64; 3],
}

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    input_commitment: pub Field,
    nullifier: pub Field,
    output_commitment_0: pub Field, // recipient
    output_commitment_1: pub Field, // change (0 if no change)
    output_commitment_2: pub Field, // fee (0 if no fee)
    tx_binding: pub Field,
    // Private inputs for the spent note (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
    // Private inputs for output notes (simplified for stage 0)
    // In production, each output would have full note fields
    out0_value: u64,
    out1_value: u64,
    out2_value: u64,
) {
    // Keep `main` as a readable audit trail. We immediately pack parameters into
    // small structs so the rest of the circuit reads like protocol statements.

    let public = TransferPublic {
        anchor,
        input_commitment,
        nullifier,
        output_commitments: [output_commitment_0, output_commitment_1, output_commitment_2],
        tx_binding,
    };

    let private = TransferPrivate {
        note: Note {
            asset_id: note_asset_id,
            amount: note_amount,
            recipient: note_recipient,
            diversifier_index: note_diversifier_index,
            nullifier_nonce: note_nullifier_nonce,
            note_randomness,
        },
        nk,
        out_values: [out0_value, out1_value, out2_value],
    };

    // Protocol narrative (Stage-0 scaffolding):
    //
    // - "This note is a member of the commitment set for this anchor"
    //   (verified externally via MerklePath in mocks or Light validity proof in production).
    prove_membership_externally_verified(public.anchor, public.input_commitment);
    //
    // - "I know the note plaintext that hashes to the commitment"
    prove_note_preimage_hashes_to_commitment(
        public.input_commitment,
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
    check_ownership_authorization();
    //
    // - "Outputs are well-formed and balance is conserved"
    prove_output_commitments_well_formed(
        public.output_commitments[0],
        public.output_commitments[1],
        public.output_commitments[2],
        private.out_values[0],
        private.out_values[1],
        private.out_values[2],
    );
    prove_output_nullifier_nonce_derivation();
    prove_balance_conservation(
        private.note.amount,
        private.out_values[0],
        private.out_values[1],
        private.out_values[2],
    );
    //
    // - "This proof is bound to the intended transaction"
    prove_tx_binding(public.tx_binding);
}

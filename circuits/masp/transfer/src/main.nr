// MASP Transfer Circuit (Orchard-style Action) - Stage 0 Scaffold
//
// Goal: production-shaped public/private input layout + working compile/execute/prove pipeline.
// This is NOT the final circuit. Constraints are intentionally minimal and will be replaced
// statement-by-statement per `docs/circuit-security-requirements.md`.
//
// Output structure (up to 3 outputs):
// - output_commitment_0: recipient note (required)
// - output_commitment_1: change note (optional, 0 if unused)
// - output_commitment_2: fee note (optional, 0 if unused)

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    nullifier: pub Field,
    output_commitment_0: pub Field, // recipient
    output_commitment_1: pub Field, // change (0 if no change)
    output_commitment_2: pub Field, // fee (0 if no fee)
    tx_binding: pub Field,
    // Private inputs for the spent note (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
    // Private inputs for output notes (simplified for stage 0)
    // In production, each output would have full note fields
    out0_value: u64,
    out1_value: u64,
    out2_value: u64,
) {
    // Stage-0 constraints: intentionally *do not* enforce any real statements yet.
    //
    // This keeps the circuit "production-shaped" (inputs match intended protocol),
    // while letting us validate the toolchain loop:
    // compile -> witness -> prove -> verify.
    //
    // Real constraints will be implemented statement-by-statement per
    // `docs/circuit-security-requirements.md`.
    //
    // Touch all public inputs so witness plumbing is exercised.
    assert(anchor == anchor);
    assert(nullifier == nullifier);
    assert(output_commitment_0 == output_commitment_0);
    assert(output_commitment_1 == output_commitment_1);
    assert(output_commitment_2 == output_commitment_2);
    assert(tx_binding == tx_binding);

    // Touch private inputs
    let amount_f: Field = note_amount as Field;
    let _ = note_asset_id + amount_f + note_recipient + note_nullifier_nonce + note_randomness + nk;

    // Touch output values (stage 0: no balance check yet)
    let out0_f: Field = out0_value as Field;
    let out1_f: Field = out1_value as Field;
    let out2_f: Field = out2_value as Field;
    let _ = out0_f + out1_f + out2_f;
}

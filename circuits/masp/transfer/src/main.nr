// MASP Transfer Circuit (Orchard-style Action) - Stage 0 Scaffold
//
// Goal: production-shaped public/private input layout + working compile/execute/prove pipeline.
// This is NOT the final circuit. Constraints are intentionally minimal and will be replaced
// statement-by-statement per `docs/circuit-security-requirements.md`.

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    nullifier: pub Field,
    output_commitment: pub Field,
    tx_binding: pub Field,
    // Private inputs (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
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
    // Touch all inputs so witness plumbing is exercised.
    assert(anchor == anchor);
    assert(nullifier == nullifier);
    assert(output_commitment == output_commitment);
    assert(tx_binding == tx_binding);

    let amount_f: Field = note_amount as Field;
    let _ = note_asset_id + amount_f + note_recipient + note_nullifier_nonce + note_randomness + nk;
}

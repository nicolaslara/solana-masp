// MASP Unshield Circuit (Withdraw) — Stage 0 Scaffold
//
// Goal: production-shaped input layout + working compile/execute/prove pipeline.
// Constraints are intentionally minimal and will be replaced per the circuit security doc.

fn main(
    // Public inputs (production-shaped)
    anchor: pub Field,
    nullifier: pub Field,
    public_amount: pub u64,
    public_recipient: pub Field,

    // Private inputs (production-shaped; mostly unused in stage 0)
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_nullifier_nonce: Field,
    note_randomness: Field,
    nk: Field,
) {
    // Stage-0 constraints: ensure the withdrawn amount and recipient match the note.
    assert(public_amount == note_amount);
    assert(public_recipient == note_recipient);

    // Touch other public inputs.
    assert(anchor == anchor);
    assert(nullifier == nullifier);

    // Tie in the remaining private fields so witness plumbing is exercised.
    let _ = note_asset_id + note_nullifier_nonce + note_randomness + nk;
}



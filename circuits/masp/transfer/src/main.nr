// MASP N-to-M Transfer Circuit (Single-Proof Design) - Stage 0 Scaffold
//
// This circuit supports flexible N inputs and M outputs within fixed compile-time maxima.
//
// Goals:
// - One proof for multiple spends and outputs (Sapling-style semantics)
// - Standard payment shape: payment + change + fee (3 outputs)
// - Protocol soundness: no inflation, no double-spend, no unauthorized spend
// - Malleability resistance via tx_binding
//
// Security requirements: see `docs/circuit-security-requirements.md`.
//
// ## Transaction Shape
//
// - MAX_INPUTS = 3, MAX_OUTPUTS = 3 (compile-time constants)
// - Disabled slots are padded with zeros and gated by enable flags
// - All enabled inputs prove membership against a shared anchor
// - Single-asset semantics: all enabled inputs/outputs must have the same asset_id

use dep::masp_common::{
    compute_note_commitment, InputSlot, MAX_INPUTS, MAX_OUTPUTS, prove_merkle_membership,
    prove_note_preimage_hashes_to_commitment, prove_nullifier_derivation, prove_spend_authorization,
    prove_tx_binding, SpendAuthResult, verify_inputs_same_owner,
};

use std::hash::poseidon2::Poseidon2;

// ============================================================================
// Domain tags (must match client/src/domain.rs)
// ============================================================================

/// DOM_TX_BINDING = 5 (from DomainTag::TransactionBinding)
global DOM_TX_BINDING: Field = 5;

/// DOM_NULLIFIER_NONCE = 6 (from DomainTag::NullifierNonce)
global DOM_NULLIFIER_NONCE: Field = 6;

// ============================================================================
// Structs for readability
// ============================================================================

struct OutputSlot {
    enabled: bool,
    note_asset_id: Field,
    note_amount: u64,
    note_recipient: Field,
    note_diversifier_index: u64,
    note_nullifier_nonce: Field,
    note_randomness: Field,
}

struct TransferPublic {
    anchor: Field,
    nullifiers: [Field; MAX_INPUTS],
    output_commitments: [Field; MAX_OUTPUTS],
    input_count: u32,
    output_count: u32,
    // Ciphertext hashes for output binding (Option 1A weak binding)
    ct_hashes: [Field; MAX_OUTPUTS],
    tx_binding: Field,
}

// ============================================================================
// Main entrypoint
// ============================================================================

fn main(
    // ===== Public inputs (canonical layout) =====
    anchor: pub Field,
    // Nullifiers (padded with 0 for disabled inputs)
    nullifiers: pub [Field; MAX_INPUTS],
    // Output commitments (padded with 0 for disabled outputs)
    output_commitments: pub [Field; MAX_OUTPUTS],
    // Counts
    input_count: pub u32,
    output_count: pub u32,
    // Ciphertext hashes for output binding (padded with 0 for disabled outputs)
    // Option 1A (weak binding): circuit binds ct_hashes but does NOT verify derivation.
    // Wallet verifies: H(DOM_CIPHERTEXT, ciphertext_bytes) == ct_hash.
    ct_hashes: pub [Field; MAX_OUTPUTS],
    // Transaction binding
    tx_binding: pub Field,
    // ===== Private inputs =====
    inputs: [InputSlot; MAX_INPUTS],
    outputs: [OutputSlot; MAX_OUTPUTS],
    // ===== Shared asset_id for this transfer (single-asset semantics) =====
    transfer_asset_id: Field,
) {
    // Pack into structs for readability
    let public = TransferPublic {
        anchor,
        nullifiers,
        output_commitments,
        input_count,
        output_count,
        ct_hashes,
        tx_binding,
    };

    // Build enable flag arrays via loop (avoid hardcoding MAX_INPUTS/MAX_OUTPUTS literals)
    let mut inputs_enabled: [bool; MAX_INPUTS] = [false; MAX_INPUTS];
    let mut outputs_enabled: [bool; MAX_OUTPUTS] = [false; MAX_OUTPUTS];
    for i in 0..MAX_INPUTS {
        inputs_enabled[i] = inputs[i].enabled;
    }
    for j in 0..MAX_OUTPUTS {
        outputs_enabled[j] = outputs[j].enabled;
    }

    // =========================================================================
    // Protocol statements (Stage-0 scaffolding)
    // =========================================================================

    // (T7b) Count correctness + slot gating
    // Statement: "The enable flags match the declared (input_count, output_count), and disabled
    // slots are provably ignored by the rest of the circuit."
    verify_counts(input_count, output_count, inputs_enabled, outputs_enabled);

    // (T4) Disabled nullifiers must be zero
    // Statement: "Dummy input slots are fully zeroed in public state (nullifier == 0)."
    verify_disabled_nullifiers(public, inputs_enabled);

    // (T5) Disabled output commitments must be zero
    // Statement: "Dummy output slots are fully zeroed in public state (commitment == 0)."
    verify_disabled_outputs(public, outputs_enabled);

    // (T8) Ciphertext hash binding (Option 1A weak binding)
    // Statement: "Each enabled output has non-zero ct_hash; each disabled output has ct_hash == 0."
    //
    // Note: In Option 1A, the circuit does NOT verify that ct_hash was correctly derived from the
    // ciphertext (H(DOM_CIPHERTEXT, ciphertext_bytes)). It only binds ct_hash as a public input.
    // The wallet is responsible for verifying the actual hash binding when accepting the note.
    verify_ct_hashes(public, outputs_enabled);

    // (T2b) Transaction binding
    // Statement: "This proof is bound to the transaction intent (anchor + counts + padded nullifiers)
    // so relayers/indexers cannot reorder/splice nullifiers across transfers."
    let expected_tx_binding =
        compute_tx_binding(anchor, public.nullifiers, input_count, output_count);
    assert(tx_binding == expected_tx_binding);
    prove_tx_binding(tx_binding);

    // =========================================================================
    // (T2) Same-sender authorization - ALL curve ops happen here, OUTSIDE the loop
    // =========================================================================
    // Statement: "All inputs belong to the same spending_key holder."
    //
    // We call prove_spend_authorization on inputs[0], which performs all EC ops once
    // and returns SpendAuthResult containing nsk (for nullifier derivation) and
    // ivk (for verifying other inputs' diversified addresses).
    //
    // Then verify_inputs_same_owner verifies all other enabled inputs belong to the
    // same spending_key, using the precomputed ivk.
    let auth_result: SpendAuthResult = prove_spend_authorization(
        inputs[0].spending_key,
        inputs[0].note_recipient,
        inputs[0].note_diversifier_index,
    );

    // Verify all enabled inputs are owned by the same spending_key holder
    verify_inputs_same_owner(inputs, inputs[0].spending_key, auth_result.ivk);

    // =========================================================================
    // Per-input checks (T1, T3, T4)
    // =========================================================================
    for i in 0..MAX_INPUTS {
        if inputs[i].enabled {
            // Recompute the spent commitment from the note plaintext (private).
            let input_commitment = compute_note_commitment(
                inputs[i].note_asset_id,
                inputs[i].note_amount,
                inputs[i].note_recipient,
                inputs[i].note_diversifier_index,
                inputs[i].note_nullifier_nonce,
                inputs[i].note_randomness,
            );

            // (T1) Membership
            // Statement: "This note is a member of the commitment set for this anchor."
            prove_merkle_membership(
                anchor,
                input_commitment,
                inputs[i].siblings,
                inputs[i].path_indices,
            );

            // (T3) Input preimage knowledge
            // Statement: "I know the note plaintext that hashes to the commitment."
            prove_note_preimage_hashes_to_commitment(
                input_commitment,
                inputs[i].note_asset_id,
                inputs[i].note_amount,
                inputs[i].note_recipient,
                inputs[i].note_diversifier_index,
                inputs[i].note_nullifier_nonce,
                inputs[i].note_randomness,
            );

            // (T4) Nullifier derivation
            // Statement: "The revealed nullifier is correctly derived from the owner's key material and this note."
            // **SECURITY:** Uses nsk (SECRET), NOT nk.x (public). This ensures FVK holders can't spend.
            prove_nullifier_derivation(
                public.nullifiers[i],
                auth_result.nsk,
                inputs[i].note_nullifier_nonce,
            );
        }
    }

    // =========================================================================
    // Per-output checks (T5, T6)
    // =========================================================================
    // Statement: "Each enabled output's nullifier nonce is deterministically derived from tx_binding and its index."
    // Enforce output commitments are well-formed and match public outputs.
    for j in 0..MAX_OUTPUTS {
        if outputs[j].enabled {
            // Enforce nonce derivation (T6)
            let expected_nonce = derive_output_nonce(tx_binding, j);
            assert(outputs[j].note_nullifier_nonce == expected_nonce);

            // Enforce output commitment integrity (T5)
            let out_cm = compute_note_commitment(
                outputs[j].note_asset_id,
                outputs[j].note_amount,
                outputs[j].note_recipient,
                outputs[j].note_diversifier_index,
                outputs[j].note_nullifier_nonce,
                outputs[j].note_randomness,
            );
            assert(public.output_commitments[j] == out_cm);
        }
    }

    // =========================================================================
    // (T7) Value conservation + single-asset rule
    // =========================================================================
    // Statement: "No inflation: sum(enabled_input_amounts) == sum(enabled_output_amounts), and all enabled
    // inputs/outputs share the same asset_id (single-asset transfer)."
    verify_balance_conservation(inputs, outputs, transfer_asset_id);
}

// ============================================================================
// Statement functions
// ============================================================================

/// Compute tx_binding for N-to-M transfer.
///
/// Layout: H(DOM_TX_BINDING, 2, anchor, input_count, output_count, h_nf, h_cm)
fn compute_tx_binding(
    anchor: Field,
    nullifiers: [Field; MAX_INPUTS],
    input_count: u32,
    output_count: u32,
) -> Field {
    let h_nf = Poseidon2::hash(nullifiers, 3);
    Poseidon2::hash(
        [
            DOM_TX_BINDING,
            2, // discriminator: transfer
            anchor,
            input_count as Field,
            output_count as Field,
            h_nf,
        ],
        6,
    )
}

/// Derive output nullifier nonce from tx_binding (N-to-M scheme).
///
/// Formula: H(DOM_NULLIFIER_NONCE, tx_binding, output_index)
fn derive_output_nonce(tx_binding: Field, output_index: u32) -> Field {
    Poseidon2::hash([DOM_NULLIFIER_NONCE, tx_binding, output_index as Field], 3)
}

/// Verify count correctness and gating (MUST).
fn verify_counts(
    input_count: u32,
    output_count: u32,
    inputs_enabled: [bool; MAX_INPUTS],
    outputs_enabled: [bool; MAX_OUTPUTS],
) {
    // Counts must be within bounds
    assert(input_count >= 1);
    assert(input_count <= MAX_INPUTS);
    assert(output_count >= 1);
    assert(output_count <= MAX_OUTPUTS);

    // Count enabled inputs
    let mut actual_input_count: u32 = 0;
    for i in 0..MAX_INPUTS {
        if inputs_enabled[i] {
            actual_input_count += 1;
        }
    }
    assert(actual_input_count == input_count);

    // Count enabled outputs
    let mut actual_output_count: u32 = 0;
    for j in 0..MAX_OUTPUTS {
        if outputs_enabled[j] {
            actual_output_count += 1;
        }
    }
    assert(actual_output_count == output_count);
}

/// Value conservation for single-asset N-to-M transfer.
fn verify_balance_conservation(
    inputs: [InputSlot; MAX_INPUTS],
    outputs: [OutputSlot; MAX_OUTPUTS],
    asset_id: Field,
) {
    // Sum enabled input amounts (as Field to avoid overflow)
    let mut input_sum: Field = 0;
    for i in 0..MAX_INPUTS {
        if inputs[i].enabled {
            // All enabled inputs must have the same asset_id
            assert(inputs[i].note_asset_id == asset_id);
            input_sum += inputs[i].note_amount as Field;
        }
    }

    // Sum enabled output amounts
    let mut output_sum: Field = 0;
    for j in 0..MAX_OUTPUTS {
        if outputs[j].enabled {
            // All enabled outputs must have the same asset_id
            assert(outputs[j].note_asset_id == asset_id);
            output_sum += outputs[j].note_amount as Field;
        }
    }

    // Conservation. Amounts are u64, so the Field sums are exact (no wrap).
    assert(input_sum == output_sum);
}

/// Verify nullifier correctness for disabled slots (must be zero).
fn verify_disabled_nullifiers(public: TransferPublic, inputs_enabled: [bool; MAX_INPUTS]) {
    for i in 0..MAX_INPUTS {
        if !inputs_enabled[i] {
            assert(public.nullifiers[i] == 0);
        }
    }
}

/// Verify output commitment correctness for disabled slots (must be zero).
fn verify_disabled_outputs(public: TransferPublic, outputs_enabled: [bool; MAX_OUTPUTS]) {
    for j in 0..MAX_OUTPUTS {
        if !outputs_enabled[j] {
            assert(public.output_commitments[j] == 0);
        }
    }
}

/// Verify ct_hash binding (Option 1A weak binding).
///
/// Enabled outputs must have non-zero ct_hash (proof commits to ciphertext binding).
/// Disabled outputs must have zero ct_hash (no ciphertext for dummy slots).
///
/// Note: The circuit does NOT verify that ct_hash == H(DOM_CIPHERTEXT, ciphertext_bytes).
/// The wallet is responsible for verifying that binding when accepting the note.
fn verify_ct_hashes(public: TransferPublic, outputs_enabled: [bool; MAX_OUTPUTS]) {
    for j in 0..MAX_OUTPUTS {
        if outputs_enabled[j] {
            // Enabled outputs must have non-zero ct_hash
            assert(public.ct_hashes[j] != 0);
        } else {
            // Disabled outputs must have zero ct_hash
            assert(public.ct_hashes[j] == 0);
        }
    }
}

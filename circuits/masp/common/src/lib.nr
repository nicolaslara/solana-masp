// Re-export constants
pub mod constants;
pub use constants::{MAX_INPUTS, MAX_OUTPUTS, MERKLE_DEPTH};

// Re-export everything from statements module for use by other circuits
pub mod statements;
pub use statements::{
    check_public_withdraw_binding_single_asset, compute_note_commitment, compute_nullifier,
    DOM_ASSET_ID, DOM_AUTH_SECRET, DOM_IVK, DOM_MERKLE_NODE, DOM_NOTE_COMMITMENT, DOM_NULLIFIER,
    DOM_NULLIFIER_NONCE, DOM_NULLIFIER_SECRET, DOM_TX_BINDING, InputSlot, merkle_hash,
    prove_asset_id_binding, prove_balance_conservation_single_asset,
    prove_membership_externally_verified, prove_merkle_membership,
    prove_note_preimage_hashes_to_commitment, prove_nullifier_derivation, prove_spend_authorization,
    prove_tx_binding, SpendAuthResult, verify_inputs_same_owner,
};

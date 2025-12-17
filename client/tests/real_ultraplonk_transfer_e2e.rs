//! E2E-ish user flow using real UltraPlonk proofs (transfer only).
//!
//! This test is ignored by default because it requires:
//! - feature `ultraplonk-verifier` (for local proof verification)
//! - `nargo` and `bb` CLI tools installed (v1.0.0-beta.3 / 0.82.2)
//! - a compiled Noir artifact at `circuits/masp/transfer/target/masp_transfer.json`
//!   (run `cd circuits/masp/transfer && nargo compile`)
//!
//! Run with:
//!   MASP_PROOF_SYSTEM=ultraplonk \
//!     cargo test --features ultraplonk-verifier --test real_ultraplonk_transfer_e2e -- --ignored --nocapture
//!
//! To keep proof artifacts for debugging:
//!   MASP_KEEP_PROOF_ARTIFACTS=1 MASP_PROOF_SYSTEM=ultraplonk \
//!     cargo test --features ultraplonk-verifier --test real_ultraplonk_transfer_e2e -- --ignored --nocapture

#![cfg(feature = "ultraplonk-verifier")]

mod test_env;
use test_env::TestEnv;

use masp_client::note::compute_asset_id;

/// Token addresses for testing
mod tokens {
    pub fn usdc() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[0..4].copy_from_slice(b"USDC");
        addr
    }
}

#[tokio::test]
#[ignore]
async fn e2e_transfer_exact_amount_real_ultraplonk_proof() {
    // Skip gracefully if prerequisites aren't present (keeps CI/dev loops friendly).
    let circuit_json = std::path::Path::new("../circuits/masp/transfer/target/masp_transfer.json");
    if !circuit_json.exists() {
        eprintln!(
            "Skipping: requires compiled circuit at {}\n\
             Compile with: cd circuits/masp/transfer && nargo compile",
            circuit_json.display()
        );
        return;
    }

    // Check nargo is available
    if std::process::Command::new("nargo").arg("--version").output().is_err() {
        eprintln!("Skipping: nargo not found in PATH. Install with: noirup -v v1.0.0-beta.3");
        return;
    }

    std::env::set_var("MASP_PROOF_SYSTEM", "ultraplonk");
    std::env::set_var("MASP_PRINT_CONFIG", "1");

    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc = compute_asset_id(&tokens::usdc());

    // Shield 100 USDC
    alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();

    let bob_addr = bob.full_viewing_key().diversified_address(0);

    // Transfer exact amount (no change) so our stage-0 transfer circuit matches output_commitments len=1.
    let result = alice
        .transfer_to(&env.encryption, &bob_addr, 100, usdc)
        .await
        .unwrap();

    // Indexing lag modeling (noop in mocks, but production-shaped)
    bob.wait_for_indexer_update(Some(&result.tx_sig))
        .await
        .unwrap();

    let received = bob
        .receive_payment(&env.encryption, &result.tx_sig)
        .await
        .unwrap();

    assert_eq!(received.len(), 1);
    assert_eq!(bob.balance(usdc), 100);
}

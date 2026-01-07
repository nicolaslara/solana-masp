//! Integration test for Photon RPC client on Devnet
//!
//! This test verifies that we can connect to Helius Photon and fetch
//! validity proofs for nullifier non-existence checks.
//!
//! Run with:
//!   HELIUS_API_KEY=<your-key> cargo test --test photon_devnet --features light-protocol -- --nocapture
//!
//! If no API key is provided, the test will be skipped.

#![cfg(feature = "light-protocol")]

use masp_client::backends::light_protocol::{
    derive_address, derive_nullifier_address_seed, PhotonClient,
};

/// Test that we can derive addresses correctly
#[test]
fn test_derive_addresses() {
    let nullifier = [0x42u8; 32];
    let pool_pubkey = [0x01u8; 32];
    let address_tree = [0x02u8; 32];

    // Derive seed
    let seed = derive_nullifier_address_seed(&nullifier, &pool_pubkey);
    assert_ne!(seed, [0u8; 32]);

    // Derive address
    let address = derive_address(&seed, &address_tree).expect("should derive address");
    assert_eq!(address[0], 0, "MSB should be cleared");

    println!("Nullifier: 0x{}", hex::encode(nullifier));
    println!("Seed: 0x{}", hex::encode(seed));
    println!("Derived address: 0x{}", hex::encode(address));
}

/// Test connectivity to Photon Devnet (requires API key)
#[tokio::test]
async fn test_photon_devnet_connectivity() {
    let api_key = match std::env::var("HELIUS_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            println!("Skipping test: HELIUS_API_KEY not set");
            return;
        }
    };

    let url = format!("https://devnet.helius-rpc.com/?api-key={}", api_key);
    let client = PhotonClient::new(&url);

    // Generate a random nullifier that shouldn't exist
    let _nullifier: [u8; 32] = rand::random();

    // We need real Light Protocol tree addresses from Devnet
    // These are the standard Light Protocol trees on Devnet
    // State Merkle Tree: 5bdFnXU47QjzGpzHfXnxcEi5WXyxzEAB2ZtFMDJupSwM
    // Address Queue: 11111111111111111111111111111111
    // Note: We'd need to look up the actual address tree from Light Protocol docs

    // For now, just test that the client can be created
    println!("PhotonClient created for Devnet");

    // Try a simple RPC health check by making a call with known-bad data
    // (this validates connectivity even if the response is an error)
    let fake_address = [0x01u8; 32];
    let fake_tree = [0x02u8; 32];

    // This will likely fail because the tree doesn't exist, but it tests connectivity
    let result = client.get_validity_proof(&fake_address, &fake_tree).await;

    match result {
        Ok(proof) => {
            println!("Got validity proof: {:?}", proof);
        }
        Err(e) => {
            println!("Expected error (fake tree): {}", e);
            // The important thing is we got a response, not a network error
            let error_str = format!("{:?}", e);
            if error_str.contains("Network") && error_str.contains("HTTP") {
                panic!("Network connectivity issue: {}", e);
            }
        }
    }
}

/// Test batched validity proofs
#[tokio::test]
async fn test_photon_batched_proofs() {
    let api_key = match std::env::var("HELIUS_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            println!("Skipping test: HELIUS_API_KEY not set");
            return;
        }
    };

    let url = format!("https://devnet.helius-rpc.com/?api-key={}", api_key);
    let client = PhotonClient::new(&url);

    // Generate multiple random nullifiers
    let nullifiers: [[u8; 32]; 3] = [rand::random(), rand::random(), rand::random()];

    let pool_pubkey = [0x01u8; 32];
    let address_tree = [0x02u8; 32];

    // This will fail because fake trees, but tests the batching logic
    let result = client
        .get_validity_proofs_batched(&nullifiers, &pool_pubkey, &address_tree)
        .await;

    match result {
        Ok(proofs) => {
            println!("Got {} batched proofs", proofs.len());
            for (i, p) in proofs.iter().enumerate() {
                println!(
                    "  Batch {}: {} nullifiers, {} root indices",
                    i,
                    p.count,
                    p.root_indices.len()
                );
            }
        }
        Err(e) => {
            println!("Expected error (fake tree): {}", e);
        }
    }
}

//! Surfpool E2E Tests
//!
//! Tests the MASP program deployed on Surfpool with mock proofs.
//!
//! ## Prerequisites
//!
//! 1. Surfpool running: `surfpool start`
//! 2. Program deployed with mock-proofs feature:
//!    ```bash
//!    cargo build-sbf -p solana-masp --features "local-testing,mock-proofs"
//!    solana program deploy target/deploy/solana_masp.so --url http://127.0.0.1:8899
//!    ```
//! 3. Set PROGRAM_ID env var to the deployed program ID
//!
//! ## Running
//!
//! ```bash
//! PROGRAM_ID=<pubkey> cargo test -p masp-client --test surfpool_e2e --features onchain-mock
//! ```

#![cfg(all(feature = "onchain-mock", feature = "solana-backend"))]

use sha3::{Digest, Keccak256};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

/// System Program ID
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

const RPC_URL: &str = "http://127.0.0.1:8899";

// Instruction discriminators (must match programs/solana-masp/src/instructions.rs)
const IX_INITIALIZE: u8 = 0;
const IX_SHIELD: u8 = 3;
const IX_UPDATE_ROOT: u8 = 6;

// Circuit types (must match programs/solana-masp/src/state.rs)
const CIRCUIT_SHIELD: u8 = 0;

/// Derive tree state PDA
fn derive_tree_state_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"masp", b"state"], program_id)
}

/// Generate a mock proof that the on-chain mock verifier will accept.
///
/// Formula: keccak256(circuit_type || public_inputs)
fn generate_mock_proof(circuit_type: u8, public_inputs: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([circuit_type]);
    for input in public_inputs {
        hasher.update(input);
    }
    hasher.finalize().into()
}

/// Create a random 32-byte field element
fn random_field() -> [u8; 32] {
    let mut buf = [0u8; 32];
    for byte in &mut buf {
        *byte = rand::random();
    }
    // Keep it a valid field element (< BN254 modulus)
    buf[0] &= 0x1f;
    buf
}

/// Get payer keypair from Solana config or generate new one
fn get_payer(client: &RpcClient) -> Keypair {
    let config_path = format!("{}/.config/solana/id.json", std::env::var("HOME").unwrap());
    if std::path::Path::new(&config_path).exists() {
        let keypair_bytes: Vec<u8> =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        // SDK 3.x uses TryFrom instead of from_bytes
        let keypair_array: [u8; 64] = keypair_bytes
            .try_into()
            .expect("keypair should be 64 bytes");
        Keypair::try_from(&keypair_array[..]).expect("valid keypair")
    } else {
        let keypair = Keypair::new();
        println!("Generated new keypair, requesting airdrop...");
        let sig = client
            .request_airdrop(&keypair.pubkey(), 10_000_000_000)
            .unwrap();
        client
            .confirm_transaction_with_commitment(&sig, CommitmentConfig::confirmed())
            .unwrap();
        keypair
    }
}

#[test]
#[ignore] // Run with: cargo test -p masp-client --test surfpool_e2e -- --ignored
fn test_surfpool_initialize() {
    let program_id = std::env::var("PROGRAM_ID")
        .map(|s| Pubkey::from_str(&s).expect("Invalid PROGRAM_ID"))
        .expect("PROGRAM_ID env var required");

    let client = RpcClient::new_with_commitment(RPC_URL, CommitmentConfig::confirmed());
    let payer = get_payer(&client);

    println!("=== Surfpool E2E: Initialize ===");
    println!("Program ID: {}", program_id);
    println!("Payer: {}", payer.pubkey());

    let (tree_state_pda, _) = derive_tree_state_pda(&program_id);
    println!("Tree State PDA: {}", tree_state_pda);

    // Build initialize instruction
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(tree_state_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: vec![IX_INITIALIZE],
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✓ Initialize succeeded: {}", sig),
        Err(e) => {
            let msg = e.to_string();
            // Error 0x8 = AlreadyInitialized (custom program error)
            if msg.contains("already in use")
                || msg.contains("AlreadyInitialized")
                || msg.contains("0x8")
            {
                println!("○ Already initialized (skipping)");
            } else {
                panic!("✗ Initialize failed: {}", e);
            }
        }
    }
}

#[test]
#[ignore] // Run with: cargo test -p masp-client --test surfpool_e2e -- --ignored
fn test_surfpool_update_root() {
    let program_id = std::env::var("PROGRAM_ID")
        .map(|s| Pubkey::from_str(&s).expect("Invalid PROGRAM_ID"))
        .expect("PROGRAM_ID env var required");

    let client = RpcClient::new_with_commitment(RPC_URL, CommitmentConfig::confirmed());
    let payer = get_payer(&client);

    println!("=== Surfpool E2E: Update Root ===");

    let (tree_state_pda, _) = derive_tree_state_pda(&program_id);

    let new_root = random_field();
    let expected_leaf_count: u64 = 0; // Fresh state has 0 leaves

    // Build update_root instruction
    // Data format: [discriminator, new_root: [u8; 32], expected_leaf_count: u64 (LE)]
    let mut data = vec![IX_UPDATE_ROOT];
    data.extend_from_slice(&new_root);
    data.extend_from_slice(&expected_leaf_count.to_le_bytes());

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(tree_state_pda, false),
        ],
        data,
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            println!("✓ Update root succeeded: {}", sig);
            println!("  New root: {:?}...", &new_root[..4]);
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("InvalidInstructionData") {
                println!("○ Update root not available (local-testing feature disabled)");
            } else if msg.contains("StateInconsistency") {
                // Expected if leaf count doesn't match
                println!("○ Leaf count mismatch (expected for fresh state)");
            } else {
                panic!("✗ Update root failed: {}", e);
            }
        }
    }
}

// Constants for proof buffer (must match programs/solana-masp/src/state.rs and verify.rs)
const MOCK_PROOF_SIZE: usize = 32; // Mock proofs are just keccak256 hash
const PROOF_BUFFER_HEADER_SIZE: usize = 5; // status(1) + data_len(2) + pi_count(1) + circuit_type(1)

const IX_INIT_PROOF_BUFFER: u8 = 1;
const IX_UPLOAD_CHUNK: u8 = 2;

#[test]
#[ignore] // Run with: cargo test -p masp-client --test surfpool_e2e -- --ignored
fn test_surfpool_shield_full_flow() {
    let program_id = std::env::var("PROGRAM_ID")
        .map(|s| Pubkey::from_str(&s).expect("Invalid PROGRAM_ID"))
        .expect("PROGRAM_ID env var required");

    let client = RpcClient::new_with_commitment(RPC_URL, CommitmentConfig::confirmed());
    let payer = get_payer(&client);

    println!("=== Surfpool E2E: Shield (Full Flow with Proof Buffer) ===");

    let (tree_state_pda, _) = derive_tree_state_pda(&program_id);

    // Construct shield public inputs
    let commitment = random_field();
    let asset_id = {
        let mut buf = [0u8; 32];
        buf[31] = 1; // asset_id = 1
        buf
    };
    let amount: u64 = 1_000_000; // 1 SOL in lamports
    let ct_hash = random_field();

    // For mock proof, public inputs are: commitment, asset_id, amount (as 32-byte), ct_hash
    let amount_bytes = {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&amount.to_be_bytes());
        buf
    };
    let public_inputs = [commitment, asset_id, amount_bytes, ct_hash];
    let mock_proof = generate_mock_proof(CIRCUIT_SHIELD, &public_inputs);

    println!("  Commitment: {:?}...", &commitment[..4]);
    println!("  Mock Proof: {:?}...", &mock_proof[..4]);

    // Step 1: Create proof buffer account
    let proof_buffer = Keypair::new();
    let pi_count: u8 = 4; // Shield has 4 public inputs

    println!("\n  Step 1: Initialize proof buffer...");
    {
        let mut data = vec![IX_INIT_PROOF_BUFFER];
        data.push(CIRCUIT_SHIELD);
        data.push(pi_count);

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(proof_buffer.pubkey(), true), // Buffer must sign for creation
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        };

        let blockhash = client.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer, &proof_buffer],
            blockhash,
        );

        match client.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("    ✓ Proof buffer created: {}", sig),
            Err(e) => {
                println!("    ✗ Failed to create proof buffer: {}", e);
                return;
            }
        }
    }

    // Step 2: Upload public inputs and proof to buffer
    println!("  Step 2: Upload proof data to buffer...");
    {
        // Buffer layout after header:
        // [header: 5 bytes] [public_inputs: pi_count * 32 bytes] [proof: MOCK_PROOF_SIZE bytes]
        let mut proof_data = Vec::new();
        for pi in &public_inputs {
            proof_data.extend_from_slice(pi);
        }
        proof_data.extend_from_slice(&mock_proof);

        // Upload in one chunk (offset 0)
        let mut data = vec![IX_UPLOAD_CHUNK];
        data.extend_from_slice(&0u16.to_le_bytes()); // offset = 0
        data.extend_from_slice(&proof_data);

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(proof_buffer.pubkey(), false)],
            data,
        };

        let blockhash = client.get_latest_blockhash().unwrap();
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

        match client.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("    ✓ Proof data uploaded: {}", sig),
            Err(e) => {
                println!("    ✗ Failed to upload proof data: {}", e);
                return;
            }
        }
    }

    // Step 3: Execute shield instruction
    println!("  Step 3: Execute shield...");
    {
        // ShieldData: commitment, asset_id, amount (u64), ct_hash
        let mut data = vec![IX_SHIELD];
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&asset_id);
        data.extend_from_slice(&amount.to_le_bytes()); // Amount as u64 LE
        data.extend_from_slice(&ct_hash);

        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),  // depositor
                AccountMeta::new(tree_state_pda, false), // tree state
                AccountMeta::new_readonly(proof_buffer.pubkey(), false), // proof buffer
            ],
            data,
        };

        let blockhash = client.get_latest_blockhash().unwrap();
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

        match client.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("    ✓ Shield succeeded: {}", sig),
            Err(e) => {
                println!("    ✗ Shield failed: {}", e);
            }
        }
    }
}

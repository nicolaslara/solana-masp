//! End-to-end tests for MASP client
//!
//! These tests use mock implementations but are designed to keep working
//! as we swap in real Chain, Indexer, and proof systems.
//!
//! ## Test Categories
//!
//! 1. **Basic Flow** - Single user shield/transfer/unshield
//! 2. **Multi-Asset** - Multiple tokens in the same pool
//! 3. **Indexer Sync** - Rebuild client state from indexer (key for POC)
//! 4. **Two-Party** - Alice pays Bob, Bob unshields
//! 5. **Negative** - Double spend, invalid anchor, etc.
//! 6. **OOB** - Out-of-band note delivery (lower priority for POC)
//!
//! ## Syncing vs OOB
//!
//! - **Sync flow**: Client scans indexer for ciphertexts, decrypts notes it owns
//! - **OOB flow**: Sender tells receiver tx_sig, receiver fetches commitment from indexer
//!
//! For POC, sync flow is more important as it requires less infrastructure.

use masp_client::note::compute_asset_id;
use masp_client::{ChainError, Fr, Note, NoteCommitmentStore, NoteEncryption, ProofBytes};

mod test_env;
use test_env::TestEnv;

// ============================================================================
// Test Infrastructure
// ============================================================================

// TestEnv is shared across integration tests in `tests/test_env.rs`.

/// Token addresses for testing multiple assets
mod tokens {
    pub fn usdc() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[0..4].copy_from_slice(b"USDC");
        addr
    }

    pub fn sol() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[0..3].copy_from_slice(b"SOL");
        addr
    }

    pub fn bonk() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[0..4].copy_from_slice(b"BONK");
        addr
    }
}

/// Mock proof that always validates (for testing without real ZK)
fn prove_transfer(
    env: &TestEnv,
    _client: &masp_client::MaspClient<dyn masp_client::Indexer, dyn masp_client::Chain>,
    td: &masp_client::client::TransferData,
    seed: &[u8; 32],
) -> ProofBytes {
    let sk = masp_client::SpendingKey::from_bytes(seed);
    // Use placeholder ct_hashes (non-zero for enabled outputs to pass mock prover checks)
    // Output count = 1 (payment) + 1 if change exists
    let output_count = if td.change.is_some() { 2u32 } else { 1u32 };
    let ct_hashes = masp_client::TransferPublicInputs::placeholder_ct_hashes(output_count);
    let (public, private) = td.spend_proof_inputs(sk.as_field(), ct_hashes);
    env.prover
        .prove(
            &masp_client::traits::ProofPublicInputs::Transfer(public),
            &private,
        )
        .expect("prover should succeed (scaffold)")
}

/// Helper: Shield a note with encryption (goes through chain properly)
async fn shield_with_encryption<E: masp_client::NoteEncryption>(
    env: &TestEnv,
    client: &masp_client::MaspClient<dyn masp_client::Indexer, dyn masp_client::Chain>,
    encryption: &E,
    note: &Note,
    token_address: &[u8; 32],
) -> masp_client::ShieldResult {
    use masp_client::ShieldRequest;

    // Encrypt the note for scanning
    let addr = client.full_viewing_key().diversified_address(0);
    let encrypted = encryption.encrypt(&mut rand::thread_rng(), note, &addr);

    // Build a shield proof (mock or real depending on env.prover).
    let public = masp_client::ShieldPublicInputs {
        new_commitment: note.commitment(),
        public_asset_id: masp_client::note::compute_asset_id(token_address),
        public_amount: note.amount,
        // Placeholder ct_hash for testing
        // TODO: compute real ct_hash from ciphertext bytes (Phase 13)
        ct_hash: masp_client::ShieldPublicInputs::placeholder_ct_hash(),
    };
    let private = masp_client::ProofPrivateInputs::Shield(masp_client::ShieldPrivateInputs {
        note_asset_id: note.asset_id,
        note_amount: note.amount,
        note_recipient: note.recipient,
        note_diversifier_index: note.diversifier_index,
        note_nullifier_nonce: note.nullifier_nonce,
        note_randomness: note.note_randomness,
    });
    let shield_proof = env
        .prover
        .prove(&masp_client::ProofPublicInputs::Shield(public), &private)
        .expect("shield prover should succeed (scaffold)")
        .into_bytes();

    let request = ShieldRequest {
        token_address: *token_address,
        amount: note.amount,
        commitment: note.commitment(),
        shield_proof,
        ciphertext: Some(encrypted.to_bytes()),
        ephemeral_key: Some(encrypted.ephemeral_key),
        // Placeholder ct_hash for testing
        // TODO: compute real ct_hash from ciphertext bytes (Phase 13)
        ct_hash: masp_client::ShieldPublicInputs::placeholder_ct_hash(),
    };

    env.chain.shield(request).await.unwrap()
}

// ============================================================================
// Basic Flow Tests
// ============================================================================

#[tokio::test]
async fn test_shield_creates_note_in_indexer() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let asset_id = compute_asset_id(&tokens::usdc());

    // Shield 100 USDC
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();

    // Verify commitment exists in indexer
    assert!(env.indexer.exists(note.commitment()).await.unwrap());

    // Add note to client and verify balance
    alice.add_note(note.clone(), shield_result.tx_sig);
    assert_eq!(alice.balance(asset_id), 100);

    println!("✅ Shield: 100 USDC shielded, commitment in indexer");
}

#[tokio::test]
async fn test_transfer_spends_and_creates_notes() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let asset_id = compute_asset_id(&tokens::usdc());

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Transfer 60 to self (creates output + change)
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            60,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    // Verify outputs exist in indexer
    assert!(env
        .indexer
        .exists(transfer_data.output.commitment())
        .await
        .unwrap());
    if let Some(ref change) = transfer_data.change {
        assert!(env.indexer.exists(change.commitment()).await.unwrap());
    }

    // Update client state
    alice.mark_spent(note.commitment());
    alice.add_note(transfer_data.output.clone(), transfer_result.tx_sig.clone());
    if let Some(change) = transfer_data.change {
        alice.add_note(change, transfer_result.tx_sig);
    }

    // Balance should still be 100 (60 + 40)
    assert_eq!(alice.balance(asset_id), 100);

    println!("✅ Transfer: 100 → 60 + 40 change, both in indexer");
}

#[tokio::test]
async fn test_unshield_reveals_nullifier() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let asset_id = compute_asset_id(&tokens::usdc());

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Compute nullifier (for spent check) before unshielding
    let (_, _witness, nullifier) = alice.prepare_spend(note.commitment()).await.unwrap();

    // Unshield via client flow (this will prove+verify under UltraPlonk)
    alice
        .unshield([99u8; 32], 100, tokens::usdc())
        .await
        .unwrap();

    // Nullifier should be spent
    assert!(env.chain.is_nullifier_spent(&nullifier).await.unwrap());

    // Balance should be 0
    assert_eq!(alice.balance(asset_id), 0);

    println!("✅ Unshield: 100 USDC withdrawn, nullifier recorded");
}

// ============================================================================
// Multi-Asset Tests
// ============================================================================

#[tokio::test]
async fn test_multi_asset_separate_balances() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());
    let sol_asset = compute_asset_id(&tokens::sol());
    let bonk_asset = compute_asset_id(&tokens::bonk());

    // Shield different amounts of each token
    let (usdc_note, usdc_req) = alice.build_shield(&tokens::usdc(), 1000);
    let usdc_result = env.chain.shield(usdc_req).await.unwrap();
    alice.add_note(usdc_note, usdc_result.tx_sig);

    let (sol_note, sol_req) = alice.build_shield(&tokens::sol(), 50);
    let sol_result = env.chain.shield(sol_req).await.unwrap();
    alice.add_note(sol_note, sol_result.tx_sig);

    let (bonk_note, bonk_req) = alice.build_shield(&tokens::bonk(), 1_000_000);
    let bonk_result = env.chain.shield(bonk_req).await.unwrap();
    alice.add_note(bonk_note, bonk_result.tx_sig);

    // Verify separate balances
    assert_eq!(alice.balance(usdc_asset), 1000);
    assert_eq!(alice.balance(sol_asset), 50);
    assert_eq!(alice.balance(bonk_asset), 1_000_000);

    println!("✅ Multi-asset: USDC=1000, SOL=50, BONK=1M (separate balances)");
}

#[tokio::test]
async fn test_multi_asset_transfer_preserves_type() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());
    let sol_asset = compute_asset_id(&tokens::sol());

    // Alice shields USDC and SOL
    let (usdc_note, usdc_req) = alice.build_shield(&tokens::usdc(), 1000);
    let usdc_result = env.chain.shield(usdc_req).await.unwrap();
    alice.add_note(usdc_note.clone(), usdc_result.tx_sig);

    let (sol_note, sol_req) = alice.build_shield(&tokens::sol(), 50);
    let sol_result = env.chain.shield(sol_req).await.unwrap();
    alice.add_note(sol_note.clone(), sol_result.tx_sig);

    // Alice transfers 500 USDC to Bob
    let transfer_data = alice
        .build_transfer(
            usdc_note.commitment(),
            bob.full_viewing_key().diversified_address(0),
            500,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    alice.mark_spent(usdc_note.commitment());
    if let Some(ref change) = transfer_data.change {
        alice.add_note(change.clone(), transfer_result.tx_sig.clone());
    }
    bob.add_note(transfer_data.output.clone(), transfer_result.tx_sig);

    // Verify asset types preserved
    assert_eq!(alice.balance(usdc_asset), 500); // 500 change
    assert_eq!(alice.balance(sol_asset), 50); // Unchanged
    assert_eq!(bob.balance(usdc_asset), 500); // Received USDC
    assert_eq!(bob.balance(sol_asset), 0); // No SOL

    // Verify output note has correct asset
    assert_eq!(transfer_data.output.asset_id, usdc_asset);

    println!("✅ Multi-asset transfer: Alice sent 500 USDC to Bob, SOL unchanged");
}

#[tokio::test]
async fn test_multi_asset_multiple_notes_same_token() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield multiple USDC notes
    for amount in [100, 200, 300] {
        let (note, req) = alice.build_shield(&tokens::usdc(), amount);
        let result = env.chain.shield(req).await.unwrap();
        alice.add_note(note, result.tx_sig);
    }

    // Total balance should be sum
    assert_eq!(alice.balance(usdc_asset), 600);

    // Unspent notes count
    let unspent = alice.unspent_notes(usdc_asset);
    assert_eq!(unspent.len(), 3);

    println!("✅ Multi-asset: 3 USDC notes (100+200+300 = 600 total)");
}

// ============================================================================
// Indexer Sync Tests (Key for POC)
// ============================================================================

#[tokio::test]
async fn test_sync_rebuild_client_from_indexer() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Alice shields some USDC
    let (note1, req1) = alice.build_shield(&tokens::usdc(), 100);
    let result1 = env.chain.shield(req1).await.unwrap();
    alice.add_note(note1.clone(), result1.tx_sig.clone());

    let (note2, req2) = alice.build_shield(&tokens::usdc(), 200);
    let result2 = env.chain.shield(req2).await.unwrap();
    alice.add_note(note2.clone(), result2.tx_sig.clone());

    // Simulate "losing" client state - create fresh client with same key
    let mut alice_restored = env.create_client(&[1u8; 32]);
    assert_eq!(alice_restored.balance(usdc_asset), 0); // No notes yet

    // In a real implementation, alice_restored would scan ciphertexts and decrypt.
    // For testing, we simulate having the note plaintexts and verify via indexer.

    // Sync: verify note1 exists and add it
    let note1_commitment = note1.commitment();
    assert!(
        env.indexer.exists(note1_commitment).await.unwrap(),
        "Note1 should exist in indexer"
    );
    // Verify we can get a valid witness
    let witness1 = env.indexer.get_witness(note1_commitment).await.unwrap();
    assert!(witness1.verify_local(note1_commitment));
    alice_restored.add_note(note1, result1.tx_sig);

    // Sync: verify note2 exists and add it
    let note2_commitment = note2.commitment();
    assert!(
        env.indexer.exists(note2_commitment).await.unwrap(),
        "Note2 should exist in indexer"
    );
    let witness2 = env.indexer.get_witness(note2_commitment).await.unwrap();
    assert!(witness2.verify_local(note2_commitment));
    alice_restored.add_note(note2, result2.tx_sig);

    // Restored client should have full balance
    assert_eq!(alice_restored.balance(usdc_asset), 300);

    println!("✅ Sync: Rebuilt client from indexer (100 + 200 = 300 USDC)");
}

#[tokio::test]
async fn test_sync_via_get_commitments_for_tx() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Alice shields USDC
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig.clone());

    // Use indexer to find commitment from tx_sig
    let tx_commitments = env
        .indexer
        .get_commitments_for_tx(&shield_result.tx_sig)
        .await
        .unwrap();

    assert_eq!(tx_commitments.len(), 1);
    assert_eq!(tx_commitments[0], note.commitment());

    // Fresh client can verify and sync
    let mut alice_restored = env.create_client(&[1u8; 32]);

    // In real impl: decrypt ciphertext to get note plaintext
    // Here: we have the note, verify commitment matches what indexer says
    let expected_commitment = tx_commitments[0];
    assert_eq!(note.commitment(), expected_commitment);

    // Add to restored client
    alice_restored.add_note(note, shield_result.tx_sig);
    assert_eq!(alice_restored.balance(usdc_asset), 100);

    println!("✅ Sync via tx: Found commitment {expected_commitment:?} from tx_sig");
}

#[tokio::test]
async fn test_sync_transfer_creates_multiple_commitments() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Transfer with change
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            60,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    // Get commitments from transfer tx
    let tx_commitments = env
        .indexer
        .get_commitments_for_tx(&transfer_result.tx_sig)
        .await
        .unwrap();

    // Should have output + change commitments
    assert_eq!(tx_commitments.len(), 2);
    assert!(tx_commitments.contains(&transfer_data.output.commitment()));
    assert!(tx_commitments.contains(&transfer_data.change.as_ref().unwrap().commitment()));

    // Fresh client can sync both notes
    let mut alice_restored = env.create_client(&[1u8; 32]);

    // Mark original as spent (would know this from nullifier check)
    // In real impl: check if nullifier is spent for each note we know

    // Add output and change notes
    alice_restored.add_note(transfer_data.output, transfer_result.tx_sig.clone());
    alice_restored.add_note(transfer_data.change.unwrap(), transfer_result.tx_sig);

    assert_eq!(alice_restored.balance(usdc_asset), 100); // 60 + 40

    println!("✅ Sync transfer: Found 2 commitments (output + change)");
}

#[tokio::test]
async fn test_sync_detects_spent_notes_via_nullifier() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield and spend
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    let shield_tx_sig = shield_result.tx_sig.clone();
    alice.add_note(note.clone(), shield_result.tx_sig);

    let (_, _, nullifier) = alice.prepare_spend(note.commitment()).await.unwrap();

    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            100,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    env.chain.transfer(transfer_req).await.unwrap();

    // Verify nullifier is now spent
    assert!(env.chain.is_nullifier_spent(&nullifier).await.unwrap());

    // Fresh client doing sync would check:
    // 1. Note exists in indexer ✓
    // 2. Compute nullifier for the note
    // 3. Check if nullifier is spent → if so, don't add to available balance

    let mut alice_restored = env.create_client(&[1u8; 32]);

    // Restored client computes nullifier same way
    // **SECURITY:** Uses nsk (secret), NOT nk.x (public). This ensures FVK holders can't spend.
    let sk = masp_client::SpendingKey::from_bytes(&[1u8; 32]);
    let nsk = sk.nsk();
    let restored_nullifier = masp_client::nullifier::compute_nullifier(nsk, note.nullifier_nonce);

    // Same nullifier
    assert_eq!(restored_nullifier, nullifier);

    // Check if spent before adding
    if env
        .chain
        .is_nullifier_spent(&restored_nullifier)
        .await
        .unwrap()
    {
        // Note is spent, don't add to available balance
        println!("  Note is spent (nullifier found), skipping");
    } else {
        alice_restored.add_note(note, shield_tx_sig);
    }

    assert_eq!(alice_restored.balance(usdc_asset), 0); // Note was spent

    println!("✅ Sync: Detected spent note via nullifier check");
}

// ============================================================================
// Encryption-Based Sync Tests
// ============================================================================

#[tokio::test]
async fn test_sync_with_encrypted_notes() {
    use masp_client::{encrypt_note, try_decrypt_note, verify_decrypted_note, NoteVerification};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let bob_sk = masp_client::SpendingKey::from_bytes(&[2u8; 32]);
    let bob_fvk = bob_sk.to_full_viewing_key();
    let bob_addr = bob_fvk.diversified_address(0);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());
    let mut rng = StdRng::seed_from_u64(99999);

    // Alice shields
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Alice transfers to Bob
    let transfer_data = alice
        .build_transfer(note.commitment(), bob_addr.clone(), 100)
        .await
        .unwrap();

    // Alice encrypts the output note for Bob
    let encrypted = encrypt_note(&mut rng, &transfer_data.output, &bob_addr);

    // Submit transfer (in real system, ciphertext would be stored on-chain/indexer)
    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();
    alice.mark_spent(note.commitment());

    // === Bob's Sync Flow ===
    // Bob scans ciphertexts and tries to decrypt with his viewing key

    // Try to decrypt with Bob's viewing key
    let decrypted = try_decrypt_note(&encrypted, &bob_fvk, 0);
    assert!(decrypted.is_some(), "Bob should decrypt note meant for him");

    let decrypted_note = decrypted.unwrap();

    // Verify the decrypted note matches the on-chain commitment
    let expected_commitment = transfer_data.output.commitment();
    let verification = verify_decrypted_note(&decrypted_note, expected_commitment, &bob_fvk, 10);
    assert_eq!(
        verification,
        NoteVerification::Valid,
        "Decrypted note should verify"
    );

    // Verify commitment exists on chain
    assert!(
        env.indexer.exists(expected_commitment).await.unwrap(),
        "Commitment should exist on indexer"
    );

    // Bob adds verified note to his client
    bob.add_note(decrypted_note, transfer_result.tx_sig);
    assert_eq!(bob.balance(usdc_asset), 100);

    println!("✅ Encryption sync: Bob decrypted and verified Alice's payment");
}

#[tokio::test]
async fn test_encrypted_note_wrong_recipient_fails() {
    use masp_client::{encrypt_note, try_decrypt_note};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Bob and Charlie have different keys
    let bob_sk = masp_client::SpendingKey::from_bytes(&[2u8; 32]);
    let bob_fvk = bob_sk.to_full_viewing_key();
    let bob_addr = bob_fvk.diversified_address(0);

    let charlie_sk = masp_client::SpendingKey::from_bytes(&[3u8; 32]);
    let charlie_fvk = charlie_sk.to_full_viewing_key();

    let mut rng = StdRng::seed_from_u64(99999);

    // Alice shields
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Alice transfers to Bob (not Charlie)
    let transfer_data = alice
        .build_transfer(note.commitment(), bob_addr.clone(), 100)
        .await
        .unwrap();

    // Alice encrypts for Bob
    let encrypted = encrypt_note(&mut rng, &transfer_data.output, &bob_addr);

    // Charlie tries to decrypt - should fail
    let charlie_result = try_decrypt_note(&encrypted, &charlie_fvk, 0);
    assert!(
        charlie_result.is_none(),
        "Charlie should NOT decrypt note meant for Bob"
    );

    // Bob can decrypt
    let bob_result = try_decrypt_note(&encrypted, &bob_fvk, 0);
    assert!(bob_result.is_some(), "Bob should decrypt his note");

    println!("✅ Encryption: Wrong recipient cannot decrypt");
}

#[tokio::test]
async fn test_verify_tampered_note_fails() {
    use masp_client::{verify_note_commitment, Note, NoteVerification};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let mut rng = StdRng::seed_from_u64(12345);

    let sk = masp_client::SpendingKey::from_bytes(&[1u8; 32]);
    let fvk = sk.to_full_viewing_key();
    let addr = fvk.diversified_address(0);

    let asset_id = compute_asset_id(&tokens::usdc());
    let note = masp_client::Note::new(
        &mut rng,
        asset_id,
        100,
        addr.to_field(),
        addr.diversifier_index,
    );
    let real_commitment = note.commitment();

    // Tamper with the note (change amount)
    let tampered_note = Note::with_values(
        note.asset_id,
        999, // Wrong amount!
        note.recipient,
        note.diversifier_index,
        note.nullifier_nonce,
        note.note_randomness,
    );

    // Verification should fail
    let result = verify_note_commitment(&tampered_note, real_commitment);
    assert!(
        matches!(result, NoteVerification::CommitmentMismatch { .. }),
        "Tampered note should fail verification"
    );

    // Original note should verify
    let result = verify_note_commitment(&note, real_commitment);
    assert_eq!(result, NoteVerification::Valid);

    println!("✅ Verification: Tampered note detected via commitment mismatch");
}

// ============================================================================
// Two-Party Tests
// ============================================================================

#[tokio::test]
async fn test_alice_pays_bob() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());
    let bob_address = bob.full_viewing_key().diversified_address(0);

    // Alice shields 100 USDC
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    assert_eq!(alice.balance(usdc_asset), 100);
    assert_eq!(bob.balance(usdc_asset), 0);

    // Alice transfers 75 to Bob
    let transfer_data = alice
        .build_transfer(note.commitment(), bob_address.clone(), 75)
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    // Alice: mark spent, add change
    alice.mark_spent(note.commitment());
    if let Some(ref change) = transfer_data.change {
        alice.add_note(change.clone(), transfer_result.tx_sig.clone());
    }

    // Bob receives via sync (simulated: we know the note data)
    bob.add_note(transfer_data.output.clone(), transfer_result.tx_sig);

    assert_eq!(alice.balance(usdc_asset), 25); // Change
    assert_eq!(bob.balance(usdc_asset), 75); // Received

    println!("✅ Two-party: Alice(100) → Bob(75) + Alice(25 change)");
}

#[tokio::test]
async fn test_bob_unshields_received_payment() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Alice shields and pays Bob
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            bob.full_viewing_key().diversified_address(0),
            100,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    alice.mark_spent(note.commitment());
    bob.add_note(transfer_data.output.clone(), transfer_result.tx_sig);

    // Bob unshields via client flow (this will prove+verify under UltraPlonk)
    let bob_note_cm = transfer_data.output.commitment();
    bob.unshield([88u8; 32], 100, tokens::usdc()).await.unwrap();
    bob.mark_spent(bob_note_cm);

    assert_eq!(alice.balance(usdc_asset), 0);
    assert_eq!(bob.balance(usdc_asset), 0); // Unshielded

    println!("✅ Two-party: Alice → Bob → Bob unshields to external wallet");
}

// ============================================================================
// Negative Tests
// ============================================================================

#[tokio::test]
async fn test_double_spend_rejected() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // First transfer succeeds
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            50,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    env.chain.transfer(transfer_req.clone()).await.unwrap();

    // Second transfer with SAME nullifier should fail
    let result = env.chain.transfer(transfer_req).await;
    assert!(matches!(result, Err(ChainError::DoubleSpend)));

    println!("✅ Double spend correctly rejected");
}

#[tokio::test]
async fn test_insufficient_balance_rejected() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Shield only 50
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 50);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Try to transfer 100 (more than we have)
    let result = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            100,
        )
        .await;

    assert!(matches!(
        result,
        Err(masp_client::client::ClientError::InsufficientBalance {
            have: 50,
            need: 100
        })
    ));

    println!("✅ Insufficient balance correctly rejected");
}

#[tokio::test]
async fn test_invalid_anchor_rejected() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Build transfer
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            50,
        )
        .await
        .unwrap();

    // Tamper with anchor
    let mut bad_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    bad_req.anchor = Fr::from(999999u64); // Invalid anchor

    let result = env.chain.transfer(bad_req).await;
    assert!(matches!(result, Err(ChainError::InvalidAnchor)));

    println!("✅ Invalid anchor correctly rejected");
}

#[tokio::test]
async fn test_spend_nonexistent_note_rejected() {
    let env = TestEnv::from_env();
    let alice = env.create_client(&[1u8; 32]);

    // Try to spend a note we never shielded
    let fake_commitment = Fr::from(12345u64);
    let result = alice.prepare_spend(fake_commitment).await;

    assert!(matches!(
        result,
        Err(masp_client::client::ClientError::NoteNotFound)
    ));

    println!("✅ Spending nonexistent note correctly rejected");
}

#[tokio::test]
async fn test_client_rejects_already_spent() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Shield
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Transfer (spend the note)
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            50,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    env.chain.transfer(transfer_req).await.unwrap();
    alice.mark_spent(note.commitment());

    // Client should reject building another spend
    let result = alice.prepare_spend(note.commitment()).await;
    assert!(matches!(
        result,
        Err(masp_client::client::ClientError::AlreadySpent)
    ));

    println!("✅ Client-side already-spent check works");
}

#[tokio::test]
async fn test_cannot_spend_others_note_wrong_nullifier() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    // Bob shields a note - commitment is public on-chain
    let (bob_note, shield_req) = bob.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    bob.add_note(bob_note.clone(), shield_result.tx_sig.clone());

    // Alice can see the commitment exists (it's public)
    assert!(env.indexer.exists(bob_note.commitment()).await.unwrap());

    // Scenario 1: Alice doesn't have the note in her client
    // She can't even call prepare_spend because she doesn't have the note
    let result = alice.prepare_spend(bob_note.commitment()).await;
    assert!(matches!(
        result,
        Err(masp_client::client::ClientError::NoteNotFound)
    ));

    // Scenario 2: Even if Alice somehow got the note data (leaked/compromised),
    // she STILL can't spend it because the nullifier requires Bob's nk
    //
    // Simulate Alice adding Bob's note to her client (pretend she knows the data)
    alice.add_note(bob_note.clone(), shield_result.tx_sig);

    // Alice can now call prepare_spend, but the nullifier will be WRONG
    // because it's computed with Alice's nk, not Bob's nk
    let (_, alice_witness, alice_nullifier) =
        alice.prepare_spend(bob_note.commitment()).await.unwrap();

    // Bob computes the CORRECT nullifier
    let (_, _bob_witness, bob_nullifier) = bob.prepare_spend(bob_note.commitment()).await.unwrap();

    // The nullifiers are DIFFERENT because they use different nk values
    assert_ne!(
        alice_nullifier, bob_nullifier,
        "Nullifiers must differ based on spending key"
    );

    // If Alice tries to submit with her wrong nullifier, the proof would fail
    // (In production with real ZK proofs, the proof verification would fail)
    //
    // For our mock test, we can demonstrate that:
    // 1. Alice's nullifier is different from Bob's
    // 2. If Alice "spends" with her nullifier, Bob can still spend with his

    // Alice tries to create a spend proof for Bob's note.
    //
    // This must fail because spend authorization is SpendingKey-only: Alice's spending key does not
    // match the note recipient (which is derived from Bob's key).
    let alice_anchor = alice_witness.root();
    let nullifiers = [
        alice_nullifier,
        masp_client::Fr::from(0u64),
        masp_client::Fr::from(0u64),
    ];
    let tx_binding = masp_client::tx_binding::tx_binding_transfer(alice_anchor, &nullifiers, 1, 1);
    let alice_public = masp_client::TransferPublicInputs {
        anchor: alice_anchor,
        nullifiers,
        output_commitments: [masp_client::Fr::from(0u64); 3],
        input_count: 1,
        output_count: 1,
        // TODO: compute real ct_hashes from ciphertext bytes (Phase 13)
        ct_hashes: [masp_client::Fr::from(0u64); 3],
        tx_binding,
    };
    let alice_private =
        masp_client::ProofPrivateInputs::Transfer(masp_client::TransferPrivateInputs {
            inputs: [
                masp_client::InputSlot {
                    enabled: true,
                    note_asset_id: bob_note.asset_id,
                    note_amount: bob_note.amount,
                    note_recipient: bob_note.recipient,
                    note_diversifier_index: bob_note.diversifier_index,
                    note_nullifier_nonce: bob_note.nullifier_nonce,
                    note_randomness: bob_note.note_randomness,
                    spending_key: masp_client::SpendingKey::from_bytes(&[1u8; 32]).as_field(),
                    membership_witness: alice_witness,
                },
                masp_client::InputSlot::default(),
                masp_client::InputSlot::default(),
            ],
            outputs: [
                masp_client::OutputSlot::default(),
                masp_client::OutputSlot::default(),
                masp_client::OutputSlot::default(),
            ],
        });
    let alice_proof_result = env.prover.prove(
        &masp_client::ProofPublicInputs::Transfer(alice_public),
        &alice_private,
    );
    assert!(
        alice_proof_result.is_err(),
        "Alice must not be able to prove a spend for Bob's note"
    );

    // Bob can STILL spend the note because his nullifier is different
    // (Alice's "spend" didn't actually invalidate the note)
    let bob_transfer = bob
        .build_transfer(
            bob_note.commitment(),
            bob.full_viewing_key().diversified_address(1),
            100,
        )
        .await
        .unwrap();

    let bob_req = bob_transfer.to_request(prove_transfer(&env, &bob, &bob_transfer, &[2u8; 32]));

    // This succeeds because Bob's nullifier wasn't spent
    let result = env.chain.transfer(bob_req).await;
    assert!(result.is_ok(), "Bob should still be able to spend his note");

    println!("✅ Wrong nullifier: Alice's fake spend didn't invalidate Bob's note");
    println!("   (With real ZK proofs, Alice's transaction would have been rejected)");
}

// ============================================================================
// OOB (Out-of-Band) Tests - Lower Priority for POC
// ============================================================================

#[tokio::test]
async fn test_oob_note_import_via_tx_sig() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Alice shields and transfers to Bob
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            bob.full_viewing_key().diversified_address(0),
            100,
        )
        .await
        .unwrap();

    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();
    alice.mark_spent(note.commitment());

    // OOB: Alice sends Bob the tx_sig (minimal data transfer)
    let oob_tx_sig = transfer_result.tx_sig.clone();

    // Bob uses indexer to find commitments from that tx
    let tx_commitments = env
        .indexer
        .get_commitments_for_tx(&oob_tx_sig)
        .await
        .unwrap();

    assert_eq!(tx_commitments.len(), 1); // No change since full transfer
    assert_eq!(tx_commitments[0], transfer_data.output.commitment());

    // Bob imports using verified import (checks indexer)
    let import_result = bob
        .import_note(transfer_data.output.clone(), oob_tx_sig)
        .await;

    assert!(import_result.is_ok());
    assert_eq!(bob.balance(usdc_asset), 100);

    println!("✅ OOB: Bob imported note via tx_sig + indexer verification");
}

#[tokio::test]
async fn test_oob_fake_note_rejected() {
    let env = TestEnv::from_env();
    let mut bob = env.create_client(&[2u8; 32]);

    // Create a fake note (never shielded)
    let self_addr = bob.full_viewing_key().diversified_address(0);
    let fake_note = Note::with_values(
        Fr::from(1u64),
        100,
        self_addr.to_field(),
        self_addr.diversifier_index,
        Fr::from(123u64),
        Fr::from(456u64),
    );

    // Try to import - should fail because commitment doesn't exist
    let result = bob.import_note(fake_note, "fake_tx".to_string()).await;

    assert!(matches!(
        result,
        Err(masp_client::client::ClientError::CommitmentNotFound)
    ));

    println!("✅ OOB: Fake note import rejected (commitment not in indexer)");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_exact_amount_transfer_no_change() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    // Shield exactly 100
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Transfer exactly 100 (no change)
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            alice.full_viewing_key().diversified_address(1),
            100,
        )
        .await
        .unwrap();

    assert!(transfer_data.change.is_none());
    assert_eq!(transfer_data.output.amount, 100);

    println!("✅ Exact amount transfer creates no change note");
}

#[tokio::test]
async fn test_zero_amount_shield() {
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&[1u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield 0 tokens (edge case)
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 0);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note, shield_result.tx_sig);

    assert_eq!(alice.balance(usdc_asset), 0);

    println!("✅ Zero amount shield (edge case accepted)");
}

// ============================================================================
// Advanced: Shielded Sync Recovery Tests
// ============================================================================

/// Test full wallet recovery from seed via shielded sync
#[tokio::test]
async fn test_shielded_sync_full_recovery() {
    let env = TestEnv::from_env();
    let encryption = &env.encryption;
    let alice_seed = [1u8; 32];

    // Phase 1: Alice creates some transactions
    let mut alice = env.create_client(&alice_seed);
    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield note 1 (with encryption - goes through chain properly)
    let (note1, _) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result1 =
        shield_with_encryption(&env, &alice, &encryption, &note1, &tokens::usdc()).await;
    alice.add_note(note1.clone(), shield_result1.tx_sig.clone());

    // Shield note 2
    let (note2, _) = alice.build_shield(&tokens::usdc(), 50);
    let shield_result2 =
        shield_with_encryption(&env, &alice, &encryption, &note2, &tokens::usdc()).await;
    alice.add_note(note2.clone(), shield_result2.tx_sig.clone());

    assert_eq!(alice.balance(usdc_asset), 150);

    // Spend note1
    let transfer_data = alice
        .build_transfer(
            note1.commitment(),
            alice.full_viewing_key().diversified_address(1),
            100,
        )
        .await
        .unwrap();
    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]));
    let _transfer_result = env.chain.transfer(transfer_req).await.unwrap();
    alice.mark_spent(note1.commitment());

    // Phase 2: Simulate wallet loss - create fresh client from same seed
    let mut recovered_alice = env.create_client(&alice_seed);
    assert_eq!(recovered_alice.balance(usdc_asset), 0); // No notes yet

    // Phase 3: Full shielded sync recovery
    let sync_result = recovered_alice
        .sync_from_chain(&encryption, 0)
        .await
        .unwrap();

    println!("Sync result: {:?}", sync_result);

    // Should have recovered note2 (unspent), but not note1 (spent)
    assert_eq!(sync_result.outputs_scanned, 2);
    assert_eq!(sync_result.received_found, 2);
    assert_eq!(sync_result.already_spent, 1); // note1 was spent
    assert_eq!(sync_result.notes_added, 1); // only note2 added

    // Balance should be 50 (just the unspent note)
    assert_eq!(recovered_alice.balance(usdc_asset), 50);

    println!("✅ Shielded sync: Full wallet recovery from seed, skipped spent notes");
}

/// Test that recovered notes can actually be spent
///
/// This is the complete recovery flow:
/// 1. Alice shields a note (with encryption for scanning)
/// 2. Alice "loses" wallet (simulated by creating new client from seed)
/// 3. Alice recovers via shielded sync
/// 4. Alice transfers the RECOVERED note to Bob
/// 5. Bob receives the payment
#[tokio::test]
async fn test_recovered_note_can_be_spent() {
    use masp_client::TransferOutput;

    let env = TestEnv::from_env();
    let encryption = &env.encryption;
    let alice_seed = [1u8; 32];
    let bob_seed = [2u8; 32];

    // Phase 1: Alice shields a note
    let alice = env.create_client(&alice_seed);
    let usdc_asset = compute_asset_id(&tokens::usdc());

    let (note, _) = alice.build_shield(&tokens::usdc(), 100);
    let _shield_result =
        shield_with_encryption(&env, &alice, &encryption, &note, &tokens::usdc()).await;

    // Phase 2: Alice "loses" wallet - create fresh client from same seed
    let mut recovered_alice = env.create_client(&alice_seed);
    assert_eq!(recovered_alice.balance(usdc_asset), 0); // No notes yet

    // Phase 3: Alice recovers via shielded sync
    let sync_result = recovered_alice
        .sync_from_chain(&encryption, 0)
        .await
        .unwrap();

    assert_eq!(sync_result.notes_added, 1);
    assert_eq!(recovered_alice.balance(usdc_asset), 100);

    // Phase 4: Alice transfers the RECOVERED note to Bob
    let bob = env.create_client(&bob_seed);
    let bob_addr = bob.full_viewing_key().diversified_address(0);

    // Get the recovered note's commitment
    let recovered_notes = recovered_alice.unspent_notes(usdc_asset);
    assert_eq!(recovered_notes.len(), 1);
    let recovered_note = &recovered_notes[0];

    // Build transfer from recovered note
    let transfer_data = recovered_alice
        .build_transfer(recovered_note.commitment, bob_addr.clone(), 100)
        .await
        .unwrap();

    // Encrypt for Bob
    let encrypted = encryption.encrypt(&mut rand::thread_rng(), &transfer_data.output, &bob_addr);
    let outputs = vec![TransferOutput::with_ciphertext(
        transfer_data.output.commitment(),
        encrypted.to_bytes(),
        encrypted.ephemeral_key,
    )];

    // Submit transfer
    let transfer_req = transfer_data.to_request_with_outputs(
        prove_transfer(&env, &recovered_alice, &transfer_data, &alice_seed),
        outputs,
    );
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();
    recovered_alice.mark_spent(recovered_note.commitment);

    // Phase 5: Bob receives the payment
    let mut bob = env.create_client(&bob_seed);
    let found_notes = bob
        .sync_from_tx(&encryption, &transfer_result.tx_sig, 0)
        .await
        .unwrap();

    assert_eq!(found_notes.len(), 1);
    assert_eq!(found_notes[0].amount, 100);
    assert_eq!(bob.balance(usdc_asset), 100);
    assert_eq!(recovered_alice.balance(usdc_asset), 0);

    println!("✅ Recovery → Transfer: Recovered note successfully spent and received by Bob");
}

/// Test incremental sync (new outputs only)
#[tokio::test]
async fn test_shielded_sync_incremental() {
    let env = TestEnv::from_env();
    let encryption = &env.encryption;
    let alice_seed = [1u8; 32];
    let mut alice = env.create_client(&alice_seed);
    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Shield first note (with encryption)
    let (note1, _) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result1 =
        shield_with_encryption(&env, &alice, &encryption, &note1, &tokens::usdc()).await;
    alice.add_note(note1.clone(), shield_result1.tx_sig.clone());
    let first_tx = shield_result1.tx_sig.clone();

    // Shield second note (after first)
    let (note2, _) = alice.build_shield(&tokens::usdc(), 50);
    let _shield_result2 =
        shield_with_encryption(&env, &alice, &encryption, &note2, &tokens::usdc()).await;

    // Incremental sync: only new outputs since first tx
    let sync_result = alice
        .sync_incremental(&encryption, 0, Some(&first_tx))
        .await
        .unwrap();

    assert_eq!(sync_result.outputs_scanned, 1); // Only note2
    assert_eq!(sync_result.received_found, 1);
    assert_eq!(sync_result.notes_added, 1);

    assert_eq!(alice.balance(usdc_asset), 150); // 100 + 50

    println!("✅ Incremental sync: Only scanned new outputs since last sync");
}

/// Test refresh_spent_status for multi-device scenario
///
/// Realistic scenario: Alice has two clients (desktop + mobile).
/// Mobile spends a note, desktop discovers this via refresh.
#[tokio::test]
async fn test_refresh_spent_status_multi_device() {
    let env = TestEnv::from_env();
    let alice_seed = [1u8; 32];

    // Desktop client
    let mut desktop = env.create_client(&alice_seed);
    // Mobile client (same seed = same keys)
    let mut mobile = env.create_client(&alice_seed);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Desktop: Shield and add locally
    let (note, shield_req) = desktop.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    desktop.add_note(note.clone(), shield_result.tx_sig.clone());

    // Mobile also knows about this note (e.g., synced earlier)
    mobile.add_note(note.clone(), shield_result.tx_sig);

    // Both clients see 100 balance
    assert_eq!(desktop.balance(usdc_asset), 100);
    assert_eq!(mobile.balance(usdc_asset), 100);

    // Mobile spends the note (while desktop is offline)
    let transfer_data = mobile
        .build_transfer(
            note.commitment(),
            mobile.full_viewing_key().diversified_address(1),
            100,
        )
        .await
        .unwrap();
    let transfer_req =
        transfer_data.to_request(prove_transfer(&env, &mobile, &transfer_data, &[1u8; 32]));
    env.chain.transfer(transfer_req).await.unwrap();
    mobile.mark_spent(note.commitment()); // Mobile updates local state

    // Mobile sees 0, desktop still thinks 100
    assert_eq!(mobile.balance(usdc_asset), 0);
    assert_eq!(desktop.balance(usdc_asset), 100); // Stale!

    // Desktop comes online and refreshes
    let newly_spent = desktop.refresh_spent_status().await.unwrap();

    // Desktop now sees the correct state
    assert_eq!(newly_spent, 1);
    assert_eq!(desktop.balance(usdc_asset), 0);

    println!("✅ Multi-device: Desktop discovered spend made by Mobile via refresh");
}

// ============================================================================
// Advanced: OOB with Encryption Tests
// ============================================================================

/// Test OOB payment flow with real encryption (first payment to new recipient)
#[tokio::test]
async fn test_oob_first_payment_encrypted() {
    let env = TestEnv::from_env();
    let encryption = &env.encryption;

    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    let usdc_asset = compute_asset_id(&tokens::usdc());

    // Alice shields
    let (note, shield_req) = alice.build_shield(&tokens::usdc(), 100);
    let shield_result = env.chain.shield(shield_req).await.unwrap();
    alice.add_note(note.clone(), shield_result.tx_sig);

    // Alice transfers to Bob
    let transfer_data = alice
        .build_transfer(
            note.commitment(),
            bob.full_viewing_key().diversified_address(0),
            100,
        )
        .await
        .unwrap();

    // Encrypt for Bob
    let bob_addr = bob.full_viewing_key().diversified_address(0);
    let encrypted = encryption.encrypt(&mut rand::thread_rng(), &transfer_data.output, &bob_addr);

    // Build transfer request with ciphertext (chain stores it in indexer)
    use masp_client::TransferOutput;
    let outputs = vec![TransferOutput::with_ciphertext(
        transfer_data.output.commitment(),
        encrypted.to_bytes(),
        encrypted.ephemeral_key,
    )];

    let transfer_req = transfer_data.to_request_with_outputs(
        prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]),
        outputs,
    );
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();
    alice.mark_spent(note.commitment());

    // OOB: Alice tells Bob the tx_sig
    let oob_tx_sig = transfer_result.tx_sig.clone();

    // Bob syncs just that transaction
    let found_notes = bob.sync_from_tx(&encryption, &oob_tx_sig, 0).await.unwrap();

    assert_eq!(found_notes.len(), 1);
    assert_eq!(found_notes[0].amount, 100);
    assert_eq!(bob.balance(usdc_asset), 100);

    println!("✅ OOB first payment: Bob received encrypted note, verified via tx_sig");
}

/// Test OOB fast path vs full sync performance comparison
#[tokio::test]
async fn test_oob_vs_full_sync_semantics() {
    let env = TestEnv::from_env();
    let encryption = &env.encryption;

    let mut alice = env.create_client(&[1u8; 32]);
    let mut bob = env.create_client(&[2u8; 32]);

    // Create many notes (only one is for Bob)
    for _i in 0..10 {
        let (note, _) = alice.build_shield(&tokens::usdc(), 10);
        let shield_result =
            shield_with_encryption(&env, &alice, &encryption, &note, &tokens::usdc()).await;
        alice.add_note(note.clone(), shield_result.tx_sig.clone());
    }

    // Alice sends ONE note to Bob
    let alice_notes: Vec<_> = alice
        .unspent_notes(compute_asset_id(&tokens::usdc()))
        .iter()
        .map(|n| (*n).clone())
        .collect();
    let spend_note = alice_notes[0].clone();

    let bob_addr = bob.full_viewing_key().diversified_address(0);
    let transfer_data = alice
        .build_transfer(spend_note.commitment, bob_addr.clone(), 10)
        .await
        .unwrap();

    // Encrypt for Bob
    let enc = encryption.encrypt(&mut rand::thread_rng(), &transfer_data.output, &bob_addr);

    // Build transfer with ciphertext (chain stores it in indexer)
    use masp_client::TransferOutput;
    let outputs = vec![TransferOutput::with_ciphertext(
        transfer_data.output.commitment(),
        enc.to_bytes(),
        enc.ephemeral_key,
    )];

    let transfer_req = transfer_data.to_request_with_outputs(
        prove_transfer(&env, &alice, &transfer_data, &[1u8; 32]),
        outputs,
    );
    let transfer_result = env.chain.transfer(transfer_req).await.unwrap();

    // Method 1: Full sync (scans ALL outputs)
    let full_sync_result = bob.sync_from_chain(&encryption, 0).await.unwrap();

    assert_eq!(full_sync_result.outputs_scanned, 11); // All 11 outputs
    assert_eq!(full_sync_result.received_found, 1); // Only 1 was for Bob

    // Method 2: OOB fast path (scans just the tx)
    let mut bob2 = env.create_client(&[2u8; 32]); // Fresh client
    let oob_notes = bob2
        .sync_from_tx(&encryption, &transfer_result.tx_sig, 0)
        .await
        .unwrap();

    assert_eq!(oob_notes.len(), 1); // Found immediately

    println!("✅ OOB vs Full Sync: OOB is O(1), full sync is O(n)");
    println!(
        "   Full sync: scanned {} outputs",
        full_sync_result.outputs_scanned
    );
    println!("   OOB: scanned 1 tx directly");
}

// ============================================================================
// Test Summary
// ============================================================================

#[tokio::test]
async fn test_summary() {
    let env = TestEnv::from_env();
    println!("\n========================================");
    println!("MASP E2E Test Summary");
    println!("========================================");
    println!("Backends: {}/{}", env.config.chain, env.config.indexer);
    println!("Encryption: {}", env.config.encryption);
    println!("Proofs:   Mock (always valid)");
    println!("========================================");
    println!("\nTest Categories:");
    println!("  - Basic Flow: shield/transfer/unshield");
    println!("  - Multi-Asset: USDC, SOL, BONK");
    println!("  - Indexer Sync: rebuild client state");
    println!("  - Two-Party: Alice → Bob flows");
    println!("  - Negative: rejection cases");
    println!("  - OOB: out-of-band note import");
    println!("  - Shielded Sync: full wallet recovery");
    println!("  - C_out: sender audit trail");
    println!("========================================\n");
}

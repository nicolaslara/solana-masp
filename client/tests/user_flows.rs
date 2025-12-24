//! User Flow Tests
//!
//! These tests demonstrate real user scenarios using only the public client API.
//! Each test represents a complete user journey, not internal mechanics.
//!
//! ## Philosophy
//!
//! - Tests should read like user stories
//! - Only use public client methods (shield, transfer_to, unshield, recover, receive_payment)
//! - Avoid internal methods (add_note, mark_spent, build_transfer)
//! - One clear way to do each operation
//! - Each test is independent (sets up its own state)
//!
//! ## Flows (ordered by typical user journey)
//!
//! - **Shield**: Onboard by depositing tokens
//! - **Transfer**: Send to another user
//! - **Unshield**: Withdraw back to public
//! - **OOB Payment**: First payment (needs address exchange)
//! - **Multi-asset**: Manage portfolio of tokens
//! - **Recovery**: Recover wallet from seed
//! - **Recovery → Spend**: Prove recovered funds work
//! - **Multi-device**: Sync between devices (⚠️ future design)
//!
//! ## Design Notes
//!
//! ### Current OOB Limitations
//!
//! Currently, OOB requires liveness of both sender and recipient for EVERY transfer:
//! 1. Bob shares address with Alice (OOB)
//! 2. Alice sends payment
//! 3. Alice tells Bob the tx_sig (OOB) ← Required for each payment!
//! 4. Bob calls `receive_payment()` to discover the note
//!
//! ### Future: Tag-Based Discovery (Milestone 7)
//!
//! With tags, OOB is only needed for the FIRST payment between two parties:
//! 1. Bob shares address + long-term public key with Alice (OOB, once)
//! 2. Shared secret established via DH
//! 3. All subsequent payments use deterministic tags
//! 4. Bob can discover payments via tag lookup (no OOB needed)
//!
//! See `tasks.md` Milestone 7 and `docs/payment-discovery-analysis.md`.
//!
//! ### Multi-device Sync
//!
//! True multi-device sync (where devices stay in sync without recovery) is not
//! yet designed. The current `flow_multidevice_sync` test demonstrates recovery
//! as a workaround. Real multi-device will likely build on tag-based discovery.
//!
//! ## Backend Configuration
//!
//! Tests can run with different backends via environment variables:
//!
//! ```bash
//! # Default: all mocks
//! cargo test --test user_flows
//!
//! # Show backend configuration
//! MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
//!
//! # With Solana chain (scaffold - uses mock internally for now)
//! MASP_CHAIN=surfpool MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
//!
//! # With Light Protocol indexer (scaffold - uses mock internally for now)
//! MASP_INDEXER=light MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
//! ```
//!
//! **Note:** Scaffolds currently use mock implementations internally. As real
//! backends are implemented, tests will automatically use them.
//!
//! See `src/backends/config.rs` for all options.

use masp_client::note::compute_asset_id;
mod test_env;
use test_env::TestEnv;

#[path = "program_deploy.rs"]
mod program_deploy;

// ============================================================================
// Test Setup
// ============================================================================

/// Ensure program is deployed before tests run.
/// Called at the start of each test - idempotent via OnceLock.
fn setup() {
    // Only relevant for Solana backends
    if std::env::var("MASP_CHAIN").is_ok_and(|c| c == "surfpool" || c.starts_with("http")) {
        let _program_id = program_deploy::ensure_program_deployed();
    }
}

/// Token addresses for testing
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
}

/// Generate a deterministic seed from a string identifier.
///
/// Use this to create unique user seeds per test, preventing interference
/// when tests run in batch against the same program.
///
/// # Example
/// ```ignore
/// let alice = env.create_client(&seed("flow_shield_alice"));
/// let bob = env.create_client(&seed("flow_shield_bob"));
/// ```
fn seed(id: &str) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(id.as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

// ============================================================================
// Shield - Onboard by depositing tokens
// ============================================================================

/// User deposits tokens and has a spendable balance
#[tokio::test]
async fn flow_shield_deposit_tokens() {
    setup();
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&seed("flow_shield_alice"));

    let usdc = compute_asset_id(&tokens::usdc());

    // Alice has no balance initially
    assert_eq!(alice.balance(usdc), 0);

    // Alice deposits 100 USDC
    let (note, result) = alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();

    // Now Alice has 100 USDC in the pool
    assert_eq!(alice.balance(usdc), 100);
    assert_eq!(note.amount, 100);
    println!("✅ Shield: Alice deposited 100 USDC, tx={}", result.tx_sig);
}

// ============================================================================
// Transfer - Send to another user
// ============================================================================

/// User sends tokens to another user
#[tokio::test]
async fn flow_transfer_send_to_recipient() {
    setup();
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&seed("flow_transfer_alice"));
    let bob = env.create_client(&seed("flow_transfer_bob"));

    let usdc = compute_asset_id(&tokens::usdc());

    // Alice deposits 100 USDC first
    alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();
    assert_eq!(alice.balance(usdc), 100);

    // Alice sends 60 USDC to Bob
    let bob_addr = bob.full_viewing_key().diversified_address(0);
    let result = alice
        .transfer_to(&env.encryption, &bob_addr, 60, usdc)
        .await
        .unwrap();

    // Alice now has 40 USDC (change)
    assert_eq!(alice.balance(usdc), 40);

    println!(
        "✅ Transfer: Alice sent 60 USDC to Bob, tx={}",
        result.tx_sig
    );
    println!("   Alice's remaining balance: {} USDC", alice.balance(usdc));
}

// ============================================================================
// Unshield - Withdraw to public address
// ============================================================================

/// User withdraws tokens from pool to public address
#[tokio::test]
async fn flow_unshield_withdraw() {
    setup();
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&seed("flow_unshield_alice"));

    let usdc = compute_asset_id(&tokens::usdc());

    // Alice deposits 100 USDC first
    alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();
    assert_eq!(alice.balance(usdc), 100);

    // Alice withdraws to her public address
    let alice_public_address = [42u8; 32]; // Her Solana public key
    let result = alice
        .unshield(alice_public_address, 100, tokens::usdc())
        .await
        .unwrap();

    // Pool balance is now 0
    assert_eq!(alice.balance(usdc), 0);

    println!("✅ Unshield: Alice withdrew 100 USDC to public address");
    println!("   tx={}", result.tx_sig);
}

// ============================================================================
// OOB Payment - First payment to new recipient
// ============================================================================

/// Alice pays Bob for the first time (needs OOB address exchange)
///
/// ⚠️ **Current limitation:** This flow requires OOB communication for EVERY payment.
/// Both parties must be online: Alice to send tx_sig, Bob to receive it.
///
/// **Future (Milestone 7):** With tag-based discovery, OOB is only needed for the
/// first payment to establish a shared secret. Subsequent payments use deterministic
/// tags that Bob can discover without Alice's help.
#[tokio::test]
async fn flow_oob_first_payment() {
    setup();
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&seed("flow_oob_alice"));
    let mut bob = env.create_client(&seed("flow_oob_bob"));

    let usdc = compute_asset_id(&tokens::usdc());

    // Step 1: Alice deposits tokens
    alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();

    // Step 2: Bob shares his address with Alice (OOB - e.g., QR code, message)
    // FUTURE: This will also include Bob's long-term public key for tag derivation
    let bob_addr = bob.full_viewing_key().diversified_address(0);

    // Step 3: Alice sends payment
    let result = alice
        .transfer_to(&env.encryption, &bob_addr, 100, usdc)
        .await
        .unwrap();

    // Step 4: Alice tells Bob the tx_sig (OOB - e.g., message, notification)
    // FUTURE: With tags, this step is only needed for the FIRST payment.
    // Subsequent payments: Bob discovers via tag lookup, no OOB needed.
    let tx_sig = result.tx_sig.clone();

    // In production, indexing may lag behind confirmation. Model that here.
    bob.wait_for_indexer_update(Some(&tx_sig)).await.unwrap();

    // Step 5: Bob receives the payment
    let received = bob.receive_payment(&env.encryption, &tx_sig).await.unwrap();

    assert_eq!(received.len(), 1);
    assert_eq!(received[0].amount, 100);
    assert_eq!(bob.balance(usdc), 100);

    println!("✅ OOB Payment: Alice → Bob, 100 USDC");
    println!("   Bob verified payment via tx_sig={}", tx_sig);
}

// ============================================================================
// Multi-asset - Handle different tokens
// ============================================================================

/// User manages multiple token types
#[tokio::test]
async fn flow_multiasset_portfolio() {
    setup();
    let env = TestEnv::from_env();
    let mut alice = env.create_client(&seed("flow_multiasset_alice"));

    let usdc = compute_asset_id(&tokens::usdc());
    let sol = compute_asset_id(&tokens::sol());

    // Alice deposits both USDC and SOL
    alice
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();
    alice
        .shield(&env.encryption, &tokens::sol(), 50)
        .await
        .unwrap();

    assert_eq!(alice.balance(usdc), 100);
    assert_eq!(alice.balance(sol), 50);

    // Alice sends some USDC (SOL unaffected)
    let bob = env.create_client(&seed("flow_multiasset_bob"));
    let bob_addr = bob.full_viewing_key().diversified_address(0);
    alice
        .transfer_to(&env.encryption, &bob_addr, 30, usdc)
        .await
        .unwrap();

    assert_eq!(alice.balance(usdc), 70); // USDC reduced
    assert_eq!(alice.balance(sol), 50); // SOL unchanged

    println!(
        "✅ Multi-asset: USDC={}, SOL={}",
        alice.balance(usdc),
        alice.balance(sol)
    );
}

// ============================================================================
// Recovery - Recover wallet from seed
// ============================================================================

/// User loses wallet and recovers from seed
#[tokio::test]
async fn flow_recovery_from_seed() {
    setup();
    let env = TestEnv::from_env();
    // Use unique seed to avoid conflicts with other tests sharing state
    let alice_seed = seed("flow_recovery_from_seed_alice");

    let usdc = compute_asset_id(&tokens::usdc());

    // Alice deposits some tokens
    {
        let mut alice = env.create_client(&alice_seed);
        alice
            .shield(&env.encryption, &tokens::usdc(), 100)
            .await
            .unwrap();
        alice
            .shield(&env.encryption, &tokens::usdc(), 50)
            .await
            .unwrap();
        assert_eq!(alice.balance(usdc), 150);
    }

    // Alice "loses" her wallet (client is dropped)
    // She creates a new client from the same seed
    let mut recovered_alice = env.create_client(&alice_seed);
    assert_eq!(recovered_alice.balance(usdc), 0); // No notes yet

    // Alice recovers her wallet
    let sync_result = recovered_alice.recover(&env.encryption).await.unwrap();

    // She has her full balance back
    assert_eq!(recovered_alice.balance(usdc), 150);
    assert_eq!(sync_result.notes_added, 2);

    println!(
        "✅ Recovery: Alice recovered {} USDC from seed",
        recovered_alice.balance(usdc)
    );
}

// ============================================================================
// Recovery then Spend - Prove recovered funds work
// ============================================================================

/// Recovered wallet can spend notes
#[tokio::test]
async fn flow_recovery_then_spend() {
    setup();
    let env = TestEnv::from_env();
    // Use unique seed to avoid conflicts with other tests sharing state
    let alice_seed = seed("flow_recovery_then_spend_alice");
    let bob = env.create_client(&seed("flow_recovery_then_spend_bob"));

    let usdc = compute_asset_id(&tokens::usdc());

    // Alice deposits tokens
    {
        let mut alice = env.create_client(&alice_seed);
        alice
            .shield(&env.encryption, &tokens::usdc(), 100)
            .await
            .unwrap();
    }

    // Alice recovers from seed
    let mut recovered_alice = env.create_client(&alice_seed);
    recovered_alice.recover(&env.encryption).await.unwrap();
    assert_eq!(recovered_alice.balance(usdc), 100);

    // Alice can spend recovered notes
    let bob_addr = bob.full_viewing_key().diversified_address(0);
    let result = recovered_alice
        .transfer_to(&env.encryption, &bob_addr, 100, usdc)
        .await
        .unwrap();

    assert_eq!(recovered_alice.balance(usdc), 0);
    println!(
        "✅ Recovery → Spend: Sent recovered funds, tx={}",
        result.tx_sig
    );
}

// ============================================================================
// Multi-device - Sync between devices (⚠️ Future Design)
// ============================================================================

/// User has multiple devices that need to stay in sync
///
/// ⚠️ **Not yet designed:** True multi-device sync is a future feature that will
/// likely build on tag-based discovery (Milestone 7). This test demonstrates
/// the current workaround: using `recover()` to do a full wallet rescan.
///
/// **Current approach:** Each device is essentially an independent wallet that
/// can recover from the same seed. There's no real-time sync; devices must
/// manually trigger recovery to see changes from other devices.
///
/// **Future design considerations:**
/// - Push notifications when new notes arrive (requires infrastructure)
/// - Incremental sync via tag streams (after Milestone 7)
/// - Conflict resolution for concurrent spends
#[tokio::test]
async fn flow_multidevice_sync() {
    setup();
    let env = TestEnv::from_env();
    // Use unique seed to avoid conflicts with other tests sharing state
    let alice_seed = seed("flow_multidevice_alice");

    let usdc = compute_asset_id(&tokens::usdc());

    // Desktop shields some funds
    let mut desktop = env.create_client(&alice_seed);
    desktop
        .shield(&env.encryption, &tokens::usdc(), 100)
        .await
        .unwrap();

    // Mobile has the same seed but hasn't synced yet
    let mut mobile = env.create_client(&alice_seed);
    assert_eq!(mobile.balance(usdc), 0);

    // Mobile syncs
    mobile.recover(&env.encryption).await.unwrap();
    assert_eq!(mobile.balance(usdc), 100);

    // Mobile spends some funds (creates change note)
    let bob = env.create_client(&seed("flow_multidevice_bob"));
    let bob_addr = bob.full_viewing_key().diversified_address(0);
    mobile
        .transfer_to(&env.encryption, &bob_addr, 60, usdc)
        .await
        .unwrap();
    assert_eq!(mobile.balance(usdc), 40);

    // In production, the indexer may lag behind chain confirmation.
    // Model that here: a device syncing later should conceptually "wait for indexer update"
    // before attempting to rescan.
    desktop.wait_for_indexer_update(None).await.unwrap();

    // Desktop still thinks it has 100 (stale state - doesn't know about spend OR change)
    assert_eq!(desktop.balance(usdc), 100);

    // Desktop does a full sync to discover:
    // 1. Original note is spent
    // 2. New change note exists
    // Note: recover() adds notes, so we need a fresh client to demonstrate
    let mut desktop_synced = env.create_client(&alice_seed);
    desktop_synced.recover(&env.encryption).await.unwrap();

    // Now desktop sees the correct balance (just the change note)
    assert_eq!(desktop_synced.balance(usdc), 40);

    println!("✅ Multi-device: Mobile spent, Desktop synced via recovery");
    println!(
        "   Both devices now show {} USDC",
        desktop_synced.balance(usdc)
    );
}

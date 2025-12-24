//! Auto-deploy helper for Solana MASP program tests.
//!
//! This module provides automatic build and deploy functionality:
//! - Checks if the .so needs rebuilding (source newer than binary)
//! - Builds with `cargo build-sbf` if needed
//! - Deploys to the configured RPC endpoint
//! - Stores the program ID for test use
//!
//! Usage: Call `ensure_program_deployed()` at the start of test setup.

use masp_client::backends::config::ChainBackend;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

/// Stores the deployed program ID (set once per test suite)
static DEPLOYED_PROGRAM_ID: OnceLock<String> = OnceLock::new();

/// Get the RPC URL for the current chain configuration.
/// Uses the canonical `ChainBackend` from the client library.
pub fn rpc_url_for_chain() -> Option<String> {
    ChainBackend::from_env_or_default()
        .rpc_url()
        .map(|s| s.to_string())
}

/// Path to file that stores the features used for last build
fn features_cache_path() -> std::path::PathBuf {
    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    // solana-masp is a workspace member, so .so goes to workspace target/deploy/
    Path::new(&workspace_root).join("target/deploy/.masp_features")
}

/// Check if we need to rebuild due to feature change
fn features_changed(features: &str) -> bool {
    let cache_path = features_cache_path();
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        if cached.trim() == features {
            return false;
        }
        println!(
            "📦 Features changed ({} → {}), will rebuild",
            cached.trim(),
            features
        );
        return true;
    }
    // No cache file, probably first build
    false
}

/// Save the features used for this build
fn save_features(features: &str) {
    let cache_path = features_cache_path();
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(cache_path, features);
}

/// Check if the .so needs to be rebuilt (any source file newer than .so)
fn needs_rebuild(so_path: &Path) -> bool {
    let features = program_features();

    if !so_path.exists() {
        println!("📦 Program .so not found, will build");
        return true;
    }

    // Check if features changed
    if features_changed(&features) {
        return true;
    }

    let so_modified = match so_path.metadata().and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true,
    };

    // Check if any Rust source file in the program is newer
    let program_src = Path::new("programs/solana-masp/src");
    let cargo_toml = Path::new("programs/solana-masp/Cargo.toml");

    // Check Cargo.toml
    if let Ok(meta) = cargo_toml.metadata() {
        if let Ok(modified) = meta.modified() {
            if modified > so_modified {
                println!("📦 Cargo.toml newer than .so, will rebuild");
                return true;
            }
        }
    }

    // Check all .rs files in src/
    if program_src.exists() {
        for entry in walkdir(program_src) {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified > so_modified {
                        println!(
                            "📦 Source file {} newer than .so, will rebuild",
                            entry.display()
                        );
                        return true;
                    }
                }
            }
        }
    }

    println!("✅ Program .so is up-to-date");
    false
}

/// Simple directory walker (no external deps)
fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path));
            } else if path.extension().map_or(false, |e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Determine program features based on proof system configuration
fn program_features() -> String {
    use masp_client::backends::config::ProofSystemBackend;

    let proof_system = ProofSystemBackend::from_env_or_default();

    let mut features = match proof_system {
        ProofSystemBackend::Mock => {
            // Mock proofs use Keccak256 - needs mock-proofs feature
            "local-testing,mock-proofs".to_string()
        }
        ProofSystemBackend::UltraPlonk => {
            // Real UltraPlonk proofs - need ultraplonk feature, NO mock-proofs
            "local-testing,ultraplonk".to_string()
        }
        ProofSystemBackend::Groth16 => {
            // Real Groth16 proofs - need groth16 feature, NO mock-proofs
            "local-testing,groth16".to_string()
        }
    };

    // Add simple-onchain-store if enabled via env var
    if std::env::var("MASP_SIMPLE_STORE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        features.push_str(",simple-onchain-store");
    }

    features
}

/// Build the MASP program with cargo build-sbf
fn build_program() -> Result<(), String> {
    let features = program_features();
    println!("🔨 Building MASP program with features: {}", features);

    // Build from the program directory to avoid workspace issues with cargo-build-sbf
    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    let program_dir = format!("{}/programs/solana-masp", workspace_root);

    let output = Command::new("cargo")
        .args(["build-sbf", "--features", &features])
        .current_dir(&program_dir)
        .output()
        .map_err(|e| format!("Failed to run cargo build-sbf: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Build failed:\n{}", stderr));
    }

    // Save features so we know what was built
    save_features(&features);

    println!("✅ MASP program build complete");
    Ok(())
}

/// Build the verifier program (required for UltraPlonk CPI)
fn build_verifier() -> Result<(), String> {
    println!("🔨 Building masp-verifier program...");

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    let verifier_dir = format!("{}/programs/masp-verifier", workspace_root);

    let output = Command::new("cargo")
        .args(["build-sbf"])
        .current_dir(&verifier_dir)
        .output()
        .map_err(|e| format!("Failed to run cargo build-sbf for verifier: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Verifier build failed:\n{}", stderr));
    }

    println!("✅ Verifier program build complete");
    Ok(())
}

/// Deploy the verifier program and return its program ID
fn deploy_verifier(rpc_url: &str) -> Result<String, String> {
    println!("🚀 Deploying masp-verifier to {}...", rpc_url);

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    // When built from program directory, output goes to programs/masp-verifier/target/deploy/
    let so_path = format!(
        "{}/programs/masp-verifier/target/deploy/masp_verifier.so",
        workspace_root
    );

    // Check if .so exists
    if !Path::new(&so_path).exists() {
        build_verifier()?;
    }

    // Generate a new keypair for verifier deployment
    let keypair_path = "/tmp/masp_verifier_deploy.json";
    let keygen_output = Command::new("solana-keygen")
        .args(["new", "--no-passphrase", "-o", keypair_path, "--force"])
        .output()
        .map_err(|e| format!("Failed to run solana-keygen: {}", e))?;

    if !keygen_output.status.success() {
        return Err("Failed to generate verifier keypair".to_string());
    }

    // Deploy
    let output = Command::new("solana")
        .args([
            "program",
            "deploy",
            &so_path,
            "--url",
            rpc_url,
            "--program-id",
            keypair_path,
        ])
        .output()
        .map_err(|e| format!("Failed to deploy verifier: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Verifier deploy failed:\n{}", stderr));
    }

    // Parse program ID from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("Program Id:") {
            if let Some(id) = line.split(':').nth(1) {
                let verifier_id = id.trim().to_string();
                println!("✅ Verifier deployed: {}", verifier_id);
                return Ok(verifier_id);
            }
        }
    }

    Err("Could not parse verifier program ID from deploy output".to_string())
}

// =============================================================================
// Mock Commitment Store
// =============================================================================

/// Build the mock commitment store program
fn build_mock_store() -> Result<(), String> {
    println!("🔨 Building simple-onchain-store program...");

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    let store_dir = format!("{}/programs/simple-onchain-store", workspace_root);

    let output = Command::new("cargo")
        .args(["build-sbf"])
        .current_dir(&store_dir)
        .output()
        .map_err(|e| format!("Failed to run cargo build-sbf for mock store: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Mock store build failed:\n{}", stderr));
    }

    println!("✅ Mock commitment store build complete");
    Ok(())
}

/// Deploy the mock commitment store with fixed keypair and return its program ID
fn deploy_mock_store(rpc_url: &str) -> Result<String, String> {
    println!("🚀 Deploying simple-onchain-store to {}...", rpc_url);

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    let so_path = format!(
        "{}/programs/simple-onchain-store/target/deploy/mock_commitment_store.so",
        workspace_root
    );
    // Use the fixed keypair so the ID is deterministic
    let keypair_path = format!(
        "{}/programs/simple-onchain-store/mock-store-keypair.json",
        workspace_root
    );

    // Check if .so exists
    if !Path::new(&so_path).exists() {
        build_mock_store()?;
    }

    // Deploy with fixed keypair
    let output = Command::new("solana")
        .args([
            "program",
            "deploy",
            &so_path,
            "--url",
            rpc_url,
            "--program-id",
            &keypair_path,
        ])
        .output()
        .map_err(|e| format!("Failed to deploy mock store: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If already deployed, that's OK - the keypair is fixed
        if stderr.contains("already in use") {
            println!("✅ Mock store already deployed (using fixed keypair)");
            return Ok("9QnviXVA1YyeaL9raJU7AaP2i6hkXvgB7vw5j9KvrxZc".to_string());
        }
        return Err(format!("Mock store deploy failed:\n{}", stderr));
    }

    // Parse program ID from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("Program Id:") {
            if let Some(id) = line.split(':').nth(1) {
                let store_id = id.trim().to_string();
                println!("✅ Mock store deployed: {}", store_id);
                return Ok(store_id);
            }
        }
    }

    Err("Could not parse mock store program ID from deploy output".to_string())
}

/// Check if we need the mock commitment store
fn needs_mock_store() -> bool {
    // Check if MASP_SIMPLE_STORE=1 or the program has simple-onchain-store feature
    std::env::var("MASP_SIMPLE_STORE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
        || program_features().contains("simple-onchain-store")
}

/// Initialize the mock commitment store (call after deploy)
#[cfg(feature = "solana-backend")]
fn initialize_mock_store(rpc_url: &str, store_id: &str) -> Result<(), String> {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signer::Signer,
        transaction::Transaction,
    };
    use std::str::FromStr;

    // System program ID
    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]);

    println!("📦 Initializing mock commitment store...");

    let store_program_id =
        Pubkey::from_str(store_id).map_err(|e| format!("Invalid store ID: {}", e))?;

    // Derive the store state PDA
    let (store_state_pda, _bump) =
        Pubkey::find_program_address(&[b"mock_store", b"state"], &store_program_id);

    // Load payer keypair (same logic as SolanaChain)
    let payer = load_payer_for_tests().map_err(|e| format!("Failed to load payer: {}", e))?;

    let rpc_client = RpcClient::new(rpc_url.to_string());

    // Check if already initialized
    match rpc_client.get_account(&store_state_pda) {
        Ok(account) if !account.data.is_empty() => {
            println!("✅ Mock store already initialized");
            return Ok(());
        }
        _ => {}
    }

    // Build Initialize instruction
    // Discriminator: 0
    let data = vec![0u8];
    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(store_state_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let ix = Instruction {
        program_id: store_program_id,
        accounts,
        data,
    };

    // Send transaction
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(|e| format!("Failed to get blockhash: {}", e))?;

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    rpc_client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| format!("Failed to initialize mock store: {}", e))?;

    println!("✅ Mock store initialized");
    Ok(())
}

/// Load payer keypair for tests (same logic as SolanaChain)
#[cfg(feature = "solana-backend")]
fn load_payer_for_tests() -> Result<solana_sdk::signature::Keypair, String> {
    // Try MASP_PAYER_KEYPAIR env var first
    if let Ok(path) = std::env::var("MASP_PAYER_KEYPAIR") {
        return load_keypair_from_file_for_tests(&path);
    }

    // Fall back to default Solana CLI keypair
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let default_path = format!("{}/.config/solana/id.json", home);

    if std::path::Path::new(&default_path).exists() {
        return load_keypair_from_file_for_tests(&default_path);
    }

    Err("No payer keypair found. Set MASP_PAYER_KEYPAIR or run `solana-keygen new`".to_string())
}

#[cfg(feature = "solana-backend")]
fn load_keypair_from_file_for_tests(path: &str) -> Result<solana_sdk::signature::Keypair, String> {
    use solana_sdk::signature::Keypair;

    let file_content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read keypair file: {}", e))?;

    let bytes: Vec<u8> = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse keypair JSON: {}", e))?;

    // Solana SDK 3.x uses TryFrom<&[u8]> instead of from_bytes
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| format!("Failed to create keypair from bytes: {}", e))
}

/// Stub for when solana-backend is not enabled
#[cfg(not(feature = "solana-backend"))]
fn initialize_mock_store(_rpc_url: &str, _store_id: &str) -> Result<(), String> {
    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Check if we need the verifier program (UltraPlonk uses CPI)
fn needs_verifier() -> bool {
    use masp_client::backends::config::ProofSystemBackend;
    matches!(
        ProofSystemBackend::from_env_or_default(),
        ProofSystemBackend::UltraPlonk
    )
}

/// Deploy the program and return the program ID
fn deploy_program(rpc_url: &str) -> Result<String, String> {
    println!("🚀 Deploying MASP program to {}...", rpc_url);

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
    // solana-masp is a workspace member, so .so goes to workspace target/deploy/
    let so_path = format!("{}/target/deploy/solana_masp.so", workspace_root);

    // Generate a new keypair for this deployment
    let keypair_path = "/tmp/masp_auto_deploy.json";
    let keygen_output = Command::new("solana-keygen")
        .args(["new", "--no-passphrase", "-o", keypair_path, "--force"])
        .output()
        .map_err(|e| format!("Failed to run solana-keygen: {}", e))?;

    if !keygen_output.status.success() {
        return Err("Failed to generate keypair".to_string());
    }

    // Deploy
    let output = Command::new("solana")
        .args([
            "program",
            "deploy",
            &so_path,
            "--url",
            rpc_url,
            "--program-id",
            keypair_path,
        ])
        .output()
        .map_err(|e| format!("Failed to run solana program deploy: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Deploy failed:\n{}", stderr));
    }

    // Parse program ID from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("Program Id:") {
            if let Some(id) = line.split(':').nth(1) {
                let program_id = id.trim().to_string();
                println!("✅ Deployed: {}", program_id);
                return Ok(program_id);
            }
        }
    }

    Err("Could not parse program ID from deploy output".to_string())
}

/// Ensure the program is deployed, building if necessary.
/// Returns the program ID.
///
/// This is idempotent - only deploys once per test suite.
/// For UltraPlonk, also deploys the verifier program and sets MASP_VERIFIER_ID.
pub fn ensure_program_deployed() -> &'static str {
    DEPLOYED_PROGRAM_ID.get_or_init(|| {
        // Check if program ID was provided externally
        if let Ok(id) = std::env::var("MASP_PROGRAM_ID") {
            if !id.is_empty() {
                println!("📋 Using provided MASP_PROGRAM_ID: {}", id);
                return id;
            }
        }

        let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
        // solana-masp is a workspace member, so .so goes to workspace target/deploy/
        let so_path = Path::new(&workspace_root).join("target/deploy/solana_masp.so");

        // Build if needed
        if needs_rebuild(&so_path) {
            if let Err(e) = build_program() {
                panic!("Failed to build program: {}", e);
            }
        }

        // Deploy - only if we have a real chain backend
        let rpc_url = rpc_url_for_chain().expect(
            "Cannot auto-deploy to mock chain - set MASP_CHAIN=surfpool or provide MASP_PROGRAM_ID",
        );

        // For UltraPlonk, deploy verifier first (MASP program CPIs to it)
        if needs_verifier() {
            // Check if verifier ID was provided externally
            if std::env::var("MASP_VERIFIER_ID").map_or(true, |v| v.is_empty()) {
                match deploy_verifier(&rpc_url) {
                    Ok(verifier_id) => {
                        std::env::set_var("MASP_VERIFIER_ID", &verifier_id);
                        println!("📋 Set MASP_VERIFIER_ID={}", verifier_id);
                    }
                    Err(e) => panic!("Failed to deploy verifier: {}", e),
                }
            } else {
                println!(
                    "📋 Using provided MASP_VERIFIER_ID: {}",
                    std::env::var("MASP_VERIFIER_ID").unwrap()
                );
            }
        }

        // Deploy mock commitment store if needed
        if needs_mock_store() {
            match deploy_mock_store(&rpc_url) {
                Ok(store_id) => {
                    std::env::set_var("MASP_SIMPLE_STORE", "1");
                    println!("📋 Mock store deployed, set MASP_SIMPLE_STORE=1");
                    // Initialize the store
                    if let Err(e) = initialize_mock_store(&rpc_url, &store_id) {
                        println!("⚠️  Mock store initialization warning: {}", e);
                    }
                }
                Err(e) => panic!("Failed to deploy mock store: {}", e),
            }
        }

        match deploy_program(&rpc_url) {
            Ok(id) => {
                // Also set env var so other parts of the test can see it
                std::env::set_var("MASP_PROGRAM_ID", &id);
                id
            }
            Err(e) => panic!("Failed to deploy program: {}", e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_url_for_chain() {
        // Mock (default) - no RPC URL
        std::env::remove_var("MASP_CHAIN");
        assert_eq!(rpc_url_for_chain(), None);

        // Surfpool
        std::env::set_var("MASP_CHAIN", "surfpool");
        assert_eq!(
            rpc_url_for_chain(),
            Some("http://127.0.0.1:8899".to_string())
        );

        // Custom URL
        std::env::set_var("MASP_CHAIN", "http://custom:1234");
        assert_eq!(rpc_url_for_chain(), Some("http://custom:1234".to_string()));

        // Clean up
        std::env::remove_var("MASP_CHAIN");
    }
}

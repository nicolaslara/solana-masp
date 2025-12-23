//! Program deployment helper for tests
//!
//! Automatically builds and deploys the MASP program when needed.
//!
//! ## Usage
//!
//! ```ignore
//! // Call before creating SolanaChain
//! ensure_program_deployed("http://127.0.0.1:8899")?;
//!
//! // Now SolanaChain will pick up the MASP_PROGRAM_ID
//! let chain = SolanaChain::surfpool(IndexerMode::LocalSync(store))?;
//! ```
//!
//! ## Behavior
//!
//! 1. If `MASP_PROGRAM_ID` is set → do nothing (use existing)
//! 2. If `.so` is missing or stale → rebuild with `cargo build-sbf`
//! 3. Deploy to the configured RPC endpoint
//! 4. Set `MASP_PROGRAM_ID` env var for subsequent use
//!
//! ## Environment Variables
//!
//! - `MASP_PROGRAM_ID` - Skip build/deploy, use this program ID
//! - `MASP_SKIP_BUILD` - Skip rebuild check (use existing .so)
//! - `MASP_PROGRAM_FEATURES` - Override build features (default: "local-testing,mock-proofs")

#![allow(dead_code)]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Once;
use std::time::SystemTime;

/// Error type for program deployment
#[derive(Debug)]
pub enum DeployError {
    BuildFailed(String),
    DeployFailed(String),
    IoError(String),
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeployError::BuildFailed(msg) => write!(f, "Build failed: {}", msg),
            DeployError::DeployFailed(msg) => write!(f, "Deploy failed: {}", msg),
            DeployError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for DeployError {}

/// Paths relative to client/ directory (where tests run from)
/// Note: cargo build-sbf outputs to workspace root's target/deploy/, not the crate's target/
const PROGRAM_DIR: &str = "../programs/solana-masp";
const SO_PATH: &str = "../target/deploy/solana_masp.so";
const SRC_DIR: &str = "../programs/solana-masp/src";

/// Default features for local testing
const DEFAULT_FEATURES: &str = "local-testing,mock-proofs";

/// Ensure deployment only happens once per test run
static DEPLOY_ONCE: Once = Once::new();
/// Mutex to store deployment result (or error message)
static DEPLOY_RESULT: std::sync::Mutex<Option<Result<String, String>>> =
    std::sync::Mutex::new(None);

/// Ensure the MASP program is deployed and MASP_PROGRAM_ID is set.
///
/// This is idempotent - multiple calls will reuse the same deployment.
/// Safe to call from multiple tests (uses Once for synchronization).
pub fn ensure_program_deployed(rpc_url: &str) -> Result<String, DeployError> {
    // Fast path: already have a program ID
    if let Ok(id) = std::env::var("MASP_PROGRAM_ID") {
        return Ok(id);
    }

    // Slow path: need to build/deploy (synchronized)
    // Only one thread will actually do the work
    DEPLOY_ONCE.call_once(|| {
        let result = match do_ensure_deployed(rpc_url) {
            Ok(id) => {
                // Set env var for SolanaChain to pick up
                std::env::set_var("MASP_PROGRAM_ID", &id);
                Ok(id)
            }
            Err(e) => Err(e.to_string()),
        };
        *DEPLOY_RESULT.lock().unwrap() = Some(result);
    });

    // Read result from static storage
    let guard = DEPLOY_RESULT.lock().unwrap();
    match guard.as_ref() {
        Some(Ok(id)) => Ok(id.clone()),
        Some(Err(msg)) => Err(DeployError::DeployFailed(msg.clone())),
        None => {
            // This shouldn't happen if DEPLOY_ONCE worked correctly
            // But check env var as fallback
            std::env::var("MASP_PROGRAM_ID")
                .map_err(|_| DeployError::DeployFailed("Deployment state lost".into()))
        }
    }
}

/// Internal: actually do the build/deploy work
fn do_ensure_deployed(rpc_url: &str) -> Result<String, DeployError> {
    let so_path = Path::new(SO_PATH);
    let src_dir = Path::new(SRC_DIR);

    // Check if rebuild needed (unless MASP_SKIP_BUILD is set)
    let skip_build = std::env::var("MASP_SKIP_BUILD").is_ok();

    if !skip_build && needs_rebuild(so_path, src_dir) {
        build_program()?;
    } else if !so_path.exists() {
        return Err(DeployError::BuildFailed(format!(
            "{} not found. Run: cd programs/solana-masp && cargo build-sbf --features {}",
            SO_PATH, DEFAULT_FEATURES
        )));
    }

    // Deploy using solana CLI
    deploy_program(rpc_url, so_path)
}

/// Check if the .so needs to be rebuilt.
fn needs_rebuild(so_path: &Path, src_dir: &Path) -> bool {
    let so_mtime = match so_path.metadata().and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => {
            println!("📦 Program .so not found, will build");
            return true;
        }
    };

    // Check Cargo.toml
    let cargo_path = Path::new(PROGRAM_DIR).join("Cargo.toml");
    if is_newer_than(&cargo_path, so_mtime) {
        println!("📦 Cargo.toml changed, will rebuild");
        return true;
    }

    // Check all .rs files in src/
    if let Ok(entries) = fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension() == Some(std::ffi::OsStr::new("rs"))
                && is_newer_than(&path, so_mtime)
            {
                println!("📦 {} changed, will rebuild", path.display());
                return true;
            }
        }
    }

    println!("✅ Program .so is up-to-date");
    false
}

/// Check if a file is newer than the given time.
fn is_newer_than(path: &Path, reference: SystemTime) -> bool {
    path.metadata()
        .and_then(|m| m.modified())
        .map(|t| t > reference)
        .unwrap_or(false)
}

/// Build the MASP program using cargo build-sbf.
fn build_program() -> Result<(), DeployError> {
    let features =
        std::env::var("MASP_PROGRAM_FEATURES").unwrap_or_else(|_| DEFAULT_FEATURES.to_string());

    println!("🔨 Building MASP program with features: {}", features);
    println!("   (This may take a minute...)");

    let status = Command::new("cargo")
        .args(["build-sbf", "--features", &features])
        .current_dir(PROGRAM_DIR)
        .status()
        .map_err(|e| DeployError::BuildFailed(format!("Failed to run cargo: {}", e)))?;

    if !status.success() {
        return Err(DeployError::BuildFailed(format!(
            "cargo build-sbf exited with status: {}",
            status
        )));
    }

    println!("   ✅ Build complete");
    Ok(())
}

/// Deploy the program using solana CLI.
fn deploy_program(rpc_url: &str, so_path: &Path) -> Result<String, DeployError> {
    println!("🚀 Deploying MASP program to {}...", rpc_url);

    // Get program size for info
    if let Ok(metadata) = so_path.metadata() {
        println!("   Program size: {} bytes", metadata.len());
    }

    // Use solana CLI for deployment
    let home = std::env::var("HOME").unwrap_or_default();
    let keypair_path = format!("{}/.config/solana/id.json", home);

    let output = Command::new("solana")
        .args([
            "program",
            "deploy",
            so_path.to_str().unwrap(),
            "--url",
            rpc_url,
            "--keypair",
            &keypair_path,
        ])
        .output()
        .map_err(|e| DeployError::DeployFailed(format!("Failed to run solana CLI: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DeployError::DeployFailed(format!(
            "solana program deploy failed: {}",
            stderr
        )));
    }

    // Parse program ID from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let program_id = parse_program_id_from_output(&stdout)?;

    println!("   ✅ Deployed: {}", program_id);
    Ok(program_id)
}

/// Parse program ID from `solana program deploy` output.
fn parse_program_id_from_output(output: &str) -> Result<String, DeployError> {
    // Output format: "Program Id: <base58>"
    for line in output.lines() {
        if line.contains("Program Id:") {
            if let Some(id_str) = line.split(':').nth(1) {
                return Ok(id_str.trim().to_string());
            }
        }
    }

    Err(DeployError::DeployFailed(format!(
        "Could not parse program ID from output: {}",
        output
    )))
}

/// Get the RPC URL for a given chain backend name.
///
/// Returns a static string for known chains, or the input for custom URLs.
pub fn rpc_url_for_chain(chain: &str) -> &str {
    match chain {
        "surfpool" => "http://127.0.0.1:8899",
        "devnet" => "https://api.devnet.solana.com",
        "testnet" => "https://api.testnet.solana.com",
        "mainnet" => "https://api.mainnet-beta.solana.com",
        _ => chain, // Assume it's a custom URL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_rebuild_missing_so() {
        let so_path = Path::new("/nonexistent/path.so");
        let src_dir = Path::new("../programs/solana-masp/src");
        assert!(needs_rebuild(so_path, src_dir));
    }

    #[test]
    fn test_parse_program_id() {
        let output = "Program Id: 7nS2E6vqFxJHeLuCFh5NdqXqYXB7wpGvDePEwEGP2rab\n";
        let result = parse_program_id_from_output(output);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "7nS2E6vqFxJHeLuCFh5NdqXqYXB7wpGvDePEwEGP2rab"
        );
    }

    #[test]
    fn test_rpc_url_for_chain() {
        assert_eq!(rpc_url_for_chain("surfpool"), "http://127.0.0.1:8899");
        assert_eq!(rpc_url_for_chain("devnet"), "https://api.devnet.solana.com");
        assert_eq!(
            rpc_url_for_chain("http://custom:8899"),
            "http://custom:8899"
        );
    }
}

//! Auto-deploy helper for Solana MASP program tests.
//!
//! This module provides automatic build and deploy functionality:
//! - Checks if the .so needs rebuilding (source newer than binary)
//! - Builds with `cargo build-sbf` if needed
//! - Deploys to the configured RPC endpoint
//! - Stores the program ID for test use
//!
//! Usage: Call `ensure_program_deployed()` at the start of test setup.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

/// Stores the deployed program ID (set once per test suite)
static DEPLOYED_PROGRAM_ID: OnceLock<String> = OnceLock::new();

/// Get the RPC URL for the current chain configuration
pub fn rpc_url_for_chain() -> String {
    match std::env::var("MASP_CHAIN").as_deref() {
        Ok("surfpool") => "http://127.0.0.1:8899".to_string(),
        Ok("devnet") => "https://api.devnet.solana.com".to_string(),
        Ok(url) if url.starts_with("http") => url.to_string(),
        _ => "http://127.0.0.1:8899".to_string(), // Default to local
    }
}

/// Check if the .so needs to be rebuilt (any source file newer than .so)
fn needs_rebuild(so_path: &Path) -> bool {
    if !so_path.exists() {
        println!("📦 Program .so not found, will build");
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

/// Build the program with cargo build-sbf
fn build_program() -> Result<(), String> {
    println!("🔨 Building MASP program...");

    let output = Command::new("cargo")
        .args([
            "build-sbf",
            "-p",
            "solana-masp",
            "--features",
            "local-testing,mock-proofs",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/client", ""))
        .output()
        .map_err(|e| format!("Failed to run cargo build-sbf: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Build failed:\n{}", stderr));
    }

    println!("✅ Build complete");
    Ok(())
}

/// Deploy the program and return the program ID
fn deploy_program(rpc_url: &str) -> Result<String, String> {
    println!("🚀 Deploying MASP program to {}...", rpc_url);

    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/client", "");
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
        let so_path = Path::new(&workspace_root).join("target/deploy/solana_masp.so");

        // Build if needed
        if needs_rebuild(&so_path) {
            if let Err(e) = build_program() {
                panic!("Failed to build program: {}", e);
            }
        }

        // Deploy
        let rpc_url = rpc_url_for_chain();
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
        // Default
        std::env::remove_var("MASP_CHAIN");
        assert_eq!(rpc_url_for_chain(), "http://127.0.0.1:8899");

        // Surfpool
        std::env::set_var("MASP_CHAIN", "surfpool");
        assert_eq!(rpc_url_for_chain(), "http://127.0.0.1:8899");

        // Custom URL
        std::env::set_var("MASP_CHAIN", "http://custom:1234");
        assert_eq!(rpc_url_for_chain(), "http://custom:1234");
    }
}

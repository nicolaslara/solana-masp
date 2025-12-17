//! UltraPlonk pipeline smoke test for our MASP Noir circuits.
//!
//! This test is intentionally ignored by default because it requires external tooling:
//! - `nargo` (Noir)
//! - `bb` (Barretenberg, UltraPlonk OLD_API)
//!
//! It validates the *production-shaped* development loop we care about:
//! compile circuit → generate witness → generate proof + vk → convert vk → verify proof.

#![cfg(feature = "ultraplonk-verifier")]

use std::path::PathBuf;
use std::process::Command;

use masp_client::traits::ProofSystemError;
use ultraplonk_core::vk_convert::BbVk;

fn tool_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("command failed: {cmd:?}"));
    }
    Ok(())
}

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).expect("failed to read file")
}

#[tokio::test]
#[ignore]
async fn ultraplonk_pipeline_masp_transfer_stage0() -> Result<(), ProofSystemError> {
    if !tool_exists("nargo") || !tool_exists("bb") {
        eprintln!("Skipping: requires `nargo` + `bb` on PATH");
        return Ok(());
    }

    let circuit_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("circuits")
        .join("masp")
        .join("transfer");

    // 1) Compile + witness
    run(Command::new("sh")
        .arg("-lc")
        .arg("nargo compile")
        .current_dir(&circuit_dir))
    .map_err(|e| ProofSystemError::NotImplemented(e))?;
    run(Command::new("sh")
        .arg("-lc")
        .arg("nargo execute")
        .current_dir(&circuit_dir))
    .map_err(|e| ProofSystemError::NotImplemented(e))?;

    let target = circuit_dir.join("target");
    let circuit_json = target.join("masp_transfer.json");
    let witness = target.join("witness.gz");
    let vk_bb = target.join("vk.bin");
    let proof_bin = target.join("proof.bin");
    let vk_onchain = target.join("vk_onchain.bin");

    // 2) Generate VK + proof (UltraPlonk OLD_API)
    run(Command::new("sh")
        .arg("-lc")
        .arg(format!(
            "bb OLD_API write_vk -b {} -o {}",
            circuit_json.display(),
            vk_bb.display()
        ))
        .current_dir(&circuit_dir))
    .map_err(|e| ProofSystemError::NotImplemented(e))?;

    run(Command::new("sh")
        .arg("-lc")
        .arg(format!(
            "bb OLD_API prove -b {} -w {} -o {}",
            circuit_json.display(),
            witness.display(),
            proof_bin.display()
        ))
        .current_dir(&circuit_dir))
    .map_err(|e| ProofSystemError::NotImplemented(e))?;

    // 3) Convert VK to on-chain bytes format that ultraplonk-core verifier expects
    let vk_bb_bytes = read(&vk_bb);
    let vk = BbVk::from_bb_bytes(&vk_bb_bytes)
        .map_err(|_| ProofSystemError::NotImplemented("failed to parse bb vk".to_string()))?;
    let vk_onchain_bytes = vk.to_onchain_bytes();
    std::fs::write(&vk_onchain, &vk_onchain_bytes)
        .map_err(|e| ProofSystemError::NotImplemented(e.to_string()))?;

    // 4) Verify proof
    // bb `prove` output format: [public_inputs (num_inputs*32 bytes)][proof_bytes]
    let proof_with_pi = read(&proof_bin);
    let num_inputs = vk.num_inputs as usize;
    let pi_len = num_inputs * 32;
    if proof_with_pi.len() <= pi_len {
        return Err(ProofSystemError::InvalidPublicInputs);
    }

    let mut public_inputs = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        let mut fr = [0u8; 32];
        fr.copy_from_slice(&proof_with_pi[i * 32..(i + 1) * 32]);
        public_inputs.push(fr);
    }
    let proof_only = &proof_with_pi[pi_len..];

    let ok = ultraplonk_core::verifier::verify_bytes(&vk_onchain_bytes, proof_only, &public_inputs)
        .map_err(|_| ProofSystemError::VerificationFailed)?;

    assert!(ok, "expected ultraplonk verification to succeed");
    Ok(())
}

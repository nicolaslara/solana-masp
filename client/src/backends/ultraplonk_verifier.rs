//! Local UltraPlonk verification via ultraplonk-core.
//!
//! This backend is behind the `ultraplonk-verifier` feature because it depends on ultraplonk-core
//! which in turn brings in solana-program (and its transitive deps).
//!
//! **Does NOT include noir_rs** to avoid base64ct version conflict.
//! Use `noir-rs-prover` feature separately for proving.

#![cfg(feature = "ultraplonk-verifier")]

use crate::traits::{
    ProofBytes, ProofPublicInputs, ProofSystemError, ProofVerifier, SpendPublicInputs,
    UnshieldPublicInputs,
};
use async_trait::async_trait;
use std::path::PathBuf;

use ark_ff::{BigInteger, PrimeField};
use ultraplonk_core::vk_convert::BbVk;

fn fr_to_be32(fr: crate::types::Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Local UltraPlonk verifier supporting multiple MASP circuits (transfer/unshield).
///
/// Reads `vk_bb.bin` from each circuit's `target/` directory.
pub struct NoirRsUltraPlonkVerifier {
    repo_root: PathBuf,
}

impl NoirRsUltraPlonkVerifier {
    pub fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = base.join(".."); // client/../ = solana-masp/
        Self { repo_root }
    }

    fn vk_bb_path(&self, circuit_dir: &str) -> PathBuf {
        self.repo_root
            .join("circuits")
            .join("masp")
            .join(circuit_dir)
            .join("target")
            .join("vk_bb.bin")
    }

    fn get_vk_onchain(&self, vk_bb_path: &PathBuf) -> Result<Vec<u8>, ProofSystemError> {
        // Wait for VK to be readable (handles parallel test race conditions)
        let mut attempts = 0;
        let vk_bb = loop {
            match std::fs::read(vk_bb_path) {
                Ok(bytes) if bytes.len() > 100 => break bytes, // VK should be ~1.7KB
                _ => {
                    attempts += 1;
                    if attempts > 50 {
                        return Err(ProofSystemError::NotImplemented(format!(
                            "timeout waiting for vk at {} (run prover once)",
                            vk_bb_path.display()
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };
        let vk = BbVk::from_bb_bytes(&vk_bb)
            .map_err(|_| ProofSystemError::NotImplemented("failed to parse bb vk".to_string()))?;
        // Use VK without G2_X - that's embedded as a constant in the verifier (STANDARD_G2_X)
        Ok(vk.to_onchain_bytes_without_g2())
    }
}

impl Default for NoirRsUltraPlonkVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofVerifier for NoirRsUltraPlonkVerifier {
    async fn verify_local(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        match public_inputs {
            ProofPublicInputs::Transfer(pi) => self.verify_transfer(pi, proof),
            ProofPublicInputs::Unshield(pi) => self.verify_unshield(pi, proof),
        }
    }

    async fn verify_on_chain(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // For now, same as local; on-chain would invoke CPI in the Solana program.
        self.verify_local(public_inputs, proof).await
    }

    fn system_name(&self) -> &'static str {
        "ultraplonk(ultraplonk-core)"
    }
}

impl NoirRsUltraPlonkVerifier {
    fn verify_transfer(
        &self,
        public_inputs: &SpendPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        let num_outputs = public_inputs.output_commitments.len();
        if num_outputs == 0 || num_outputs > 3 {
            return Err(ProofSystemError::InvalidPublicInputs);
        }

        let vk_onchain = self.get_vk_onchain(&self.vk_bb_path("transfer"))?;

        // Pad output commitments to 3 (use 0 for unused slots)
        let zero = crate::types::Fr::from(0u64);
        let out0 = public_inputs
            .output_commitments
            .first()
            .copied()
            .unwrap_or(zero);
        let out1 = public_inputs
            .output_commitments
            .get(1)
            .copied()
            .unwrap_or(zero);
        let out2 = public_inputs
            .output_commitments
            .get(2)
            .copied()
            .unwrap_or(zero);

        // Order must match transfer circuit: anchor, nullifier, out0, out1, out2, tx_binding
        let pis: Vec<[u8; 32]> = vec![
            fr_to_be32(public_inputs.anchor),
            fr_to_be32(public_inputs.nullifier),
            fr_to_be32(out0),
            fr_to_be32(out1),
            fr_to_be32(out2),
            fr_to_be32(public_inputs.tx_binding),
        ];

        ultraplonk_core::verifier::verify_bytes(&vk_onchain, proof.as_bytes(), &pis)
            .map_err(|_| ProofSystemError::VerificationFailed)
    }

    fn verify_unshield(
        &self,
        public_inputs: &UnshieldPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        let vk_onchain = self.get_vk_onchain(&self.vk_bb_path("unshield"))?;

        // Order must match unshield circuit: anchor, nullifier, public_amount, public_recipient, public_asset_id
        let pis: Vec<[u8; 32]> = vec![
            fr_to_be32(public_inputs.anchor),
            fr_to_be32(public_inputs.nullifier),
            fr_to_be32(crate::types::Fr::from(public_inputs.public_amount)),
            fr_to_be32(public_inputs.public_recipient),
            fr_to_be32(public_inputs.public_asset_id),
        ];

        ultraplonk_core::verifier::verify_bytes(&vk_onchain, proof.as_bytes(), &pis)
            .map_err(|_| ProofSystemError::VerificationFailed)
    }
}

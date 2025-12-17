//! Proof system backends (scaffold)
//!
//! This is the backend layer for **spend proofs** (client-side proving) and
//! spend proof verification (chain-side or local).
//!
//! ## Status: SCAFFOLD
//!
//! Today these implementations delegate to `MockSpendProver` / `MockProofVerifier`
//! so the plumbing can be exercised via env vars while we integrate real proving.
//!
//! ## Target implementations
//!
//! - UltraPlonk (Noir + bb) via `../solana-ultraplonk-verifier/`
//! - Groth16 (Noir backend) via `../noir-solana-groth16/`
//!
//! In production:
//! - Prover runs off-chain (wallet / relayer).
//! - Verifier runs on-chain (Solana program), but we keep a local verifier for
//!   fast iteration and to validate the end-to-end flow in tests.

use crate::proofs::{MockProofVerifier, MockSpendProver};
use crate::traits::{
    ProofBytes, ProofPublicInputs, ProofSystemError, ProofVerifier, SpendPrivateInputs, SpendProver,
};
use async_trait::async_trait;

// Re-export the config enum for convenience.
pub use crate::backends::config::ProofSystemBackend as ProofSystem;

/// UltraPlonk prover scaffold (delegates to mock today)
pub struct UltraPlonkProverScaffold {
    inner: MockSpendProver,
}

impl Default for UltraPlonkProverScaffold {
    fn default() -> Self {
        Self {
            inner: MockSpendProver,
        }
    }
}

impl SpendProver for UltraPlonkProverScaffold {
    fn prove(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        // TODO: integrate Noir + bb proving flow
        self.inner.prove(public_inputs, private_inputs)
    }

    fn system_name(&self) -> &'static str {
        "ultraplonk(scaffold)"
    }
}

/// Groth16 prover scaffold (delegates to mock today)
pub struct Groth16ProverScaffold {
    inner: MockSpendProver,
}

impl Default for Groth16ProverScaffold {
    fn default() -> Self {
        Self {
            inner: MockSpendProver,
        }
    }
}

impl SpendProver for Groth16ProverScaffold {
    fn prove(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        // TODO: integrate Noir Groth16 proving flow
        self.inner.prove(public_inputs, private_inputs)
    }

    fn system_name(&self) -> &'static str {
        "groth16(scaffold)"
    }
}

/// UltraPlonk verifier scaffold (delegates to mock today)
pub struct UltraPlonkVerifierScaffold {
    inner: MockProofVerifier,
}

impl Default for UltraPlonkVerifierScaffold {
    fn default() -> Self {
        Self {
            inner: MockProofVerifier,
        }
    }
}

#[async_trait]
impl ProofVerifier for UltraPlonkVerifierScaffold {
    async fn verify_local(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // TODO: integrate local verifier against vk + proof
        self.inner.verify_local(public_inputs, proof).await
    }

    async fn verify_on_chain(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // Scaffold: pretend we call a Solana program / CPI.
        // Later: build + simulate transaction with verifier instruction.
        self.verify_local(public_inputs, proof).await
    }

    fn system_name(&self) -> &'static str {
        "ultraplonk(scaffold)"
    }
}

/// UltraPlonk verifier (local via ultraplonk-core, uses cached bb vk from prover).
/// Feature-gated separately from the prover to avoid dependency conflicts.
#[cfg(feature = "ultraplonk-verifier")]
pub type UltraPlonkVerifierNoirRs = crate::backends::ultraplonk_verifier::NoirRsUltraPlonkVerifier;

/// Groth16 verifier scaffold (delegates to mock today)
pub struct Groth16VerifierScaffold {
    inner: MockProofVerifier,
}

impl Default for Groth16VerifierScaffold {
    fn default() -> Self {
        Self {
            inner: MockProofVerifier,
        }
    }
}

#[async_trait]
impl ProofVerifier for Groth16VerifierScaffold {
    async fn verify_local(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // TODO: integrate local groth16 verification
        self.inner.verify_local(public_inputs, proof).await
    }

    async fn verify_on_chain(
        &self,
        public_inputs: &ProofPublicInputs,
        proof: &ProofBytes,
    ) -> Result<bool, ProofSystemError> {
        // Scaffold: pretend we call a Solana program / CPI.
        self.verify_local(public_inputs, proof).await
    }

    fn system_name(&self) -> &'static str {
        "groth16(scaffold)"
    }
}

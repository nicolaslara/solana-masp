//! Proof verification for MASP circuits
//!
//! This module supports multiple proof systems with proper namespacing.
//!
//! ## Supported Proof Systems
//!
//! - **UltraPlonk** (default): ~2KB proofs, ~500K-1M CU, no trusted setup per circuit
//! - **Groth16** (optional): ~192B proofs, ~81K CU, requires trusted setup per circuit
//! - **Mock** (local-testing only): 32B proofs, hash-based verification, for testing
//!
//! ## Architecture
//!
//! ```text
//! verify.rs (this file)
//!   ├── ProofSystem enum (UltraPlonk, Groth16)
//!   ├── verify_proof() - dispatches to appropriate backend
//!   ├── verify_shield/transfer/unshield() - circuit-specific wrappers
//!   │
//!   ├── ultraplonk/ (module)
//!   │   ├── VKs embedded at compile time
//!   │   ├── verify_ultraplonk() implementation
//!   │   └── PROOF_SIZE = 2144
//!   │
//!   └── groth16/ (module, feature-gated)
//!       ├── VKs embedded at compile time
//!       ├── verify_groth16() implementation
//!       └── PROOF_SIZE = 192
//! ```
//!
//! ## VK Embedding Strategy
//!
//! Verification keys are embedded at compile time via `include_bytes!`. This avoids:
//! - Runtime VK parsing overhead
//! - Account storage for VKs
//! - Potential for VK substitution attacks
//!
//! The tradeoff is that VKs are frozen at compile time. If circuits change,
//! the program must be redeployed.
//!
//! ## Configuration
//!
//! Proof system is selected at compile time via features:
//!
//! ```toml
//! [features]
//! default = ["ultraplonk"]
//! ultraplonk = []
//! groth16 = []
//! ```
//!
//! Only one proof system should be enabled at a time (though the code supports both).

use crate::error::MaspError;
use crate::state::CircuitType;
use solana_program::msg;

// =============================================================================
// Proof System Selection
// =============================================================================

/// Supported proof systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    /// UltraPlonk (Noir + bb)
    /// - ~2KB proofs (2144 bytes)
    /// - ~500K-1M CU for verification
    /// - No per-circuit trusted setup
    UltraPlonk,

    /// Groth16 (Noir + groth16-solana)
    /// - ~192B proofs
    /// - ~81K CU for verification
    /// - Requires per-circuit trusted setup
    Groth16,

    /// Mock (local-testing only)
    /// - 32B proofs (keccak256 hash of public inputs)
    /// - Tests program logic without real ZK verification
    /// - ⚠️ INSECURE - never use in production!
    #[cfg(feature = "local-testing")]
    Mock,
}

impl ProofSystem {
    /// Get the expected proof size in bytes
    pub const fn proof_size(&self) -> usize {
        match self {
            ProofSystem::UltraPlonk => ultraplonk::PROOF_SIZE,
            ProofSystem::Groth16 => groth16::PROOF_SIZE,
            #[cfg(feature = "local-testing")]
            ProofSystem::Mock => mock::PROOF_SIZE,
        }
    }
}

/// Currently configured proof system.
///
/// This is determined at compile time via features.
/// Priority: mock (if local-testing) > groth16 > ultraplonk (default)
///
/// ⚠️ When `local-testing` + `mock-proofs` are enabled, Mock is used.
/// This is for testing only - never enable both in production!
pub const CURRENT_PROOF_SYSTEM: ProofSystem = {
    // Mock takes priority when local-testing is enabled
    #[cfg(all(feature = "local-testing", feature = "mock-proofs"))]
    {
        ProofSystem::Mock
    }
    // Groth16 if explicitly enabled (and not mock)
    #[cfg(all(
        feature = "groth16",
        not(feature = "ultraplonk"),
        not(all(feature = "local-testing", feature = "mock-proofs"))
    ))]
    {
        ProofSystem::Groth16
    }
    // Default: UltraPlonk
    #[cfg(not(any(
        all(feature = "local-testing", feature = "mock-proofs"),
        all(feature = "groth16", not(feature = "ultraplonk"))
    )))]
    {
        ProofSystem::UltraPlonk
    }
};

// =============================================================================
// UltraPlonk Backend
// =============================================================================

pub mod ultraplonk {
    use super::*;

    /// UltraPlonk proof size in bytes
    pub const PROOF_SIZE: usize = 2144;

    /// Expected VK size in onchain format (without G2_X)
    pub const VK_SIZE: usize = 1632;

    /// Maximum public inputs per circuit
    pub const MAX_PUBLIC_INPUTS: usize = 16;

    // VK embedding (TODO: Generate via build.rs)
    //
    // Example build.rs pattern:
    // ```rust
    // let vk_bb = fs::read("../../circuits/masp/shield/target/vk.bin")?;
    // let vk = BbVk::from_bb_bytes(&vk_bb)?;
    // let vk_onchain = vk.to_onchain_bytes_without_g2();
    // fs::write(out_dir.join("ultraplonk_vk_shield.bin"), vk_onchain)?;
    // ```

    #[cfg(feature = "ultraplonk-real-vks")]
    mod vks {
        pub const VK_SHIELD: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/ultraplonk_vk_shield.bin"));
        pub const VK_TRANSFER: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/ultraplonk_vk_transfer.bin"));
        pub const VK_UNSHIELD: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/ultraplonk_vk_unshield.bin"));
    }

    /// Verify an UltraPlonk proof
    pub fn verify(
        circuit_type: CircuitType,
        public_inputs: &[[u8; 32]],
        proof_bytes: &[u8],
    ) -> Result<(), MaspError> {
        // Validate proof size
        if proof_bytes.len() != PROOF_SIZE {
            msg!(
                "UltraPlonk: Invalid proof size: {} (expected {})",
                proof_bytes.len(),
                PROOF_SIZE
            );
            return Err(MaspError::InvalidProofData);
        }

        // Validate public inputs count
        if public_inputs.len() > MAX_PUBLIC_INPUTS {
            msg!(
                "UltraPlonk: Too many public inputs: {} (max {})",
                public_inputs.len(),
                MAX_PUBLIC_INPUTS
            );
            return Err(MaspError::InvalidPublicInputs);
        }

        // TODO: Once VKs are generated, use real verification:
        //
        // use ultraplonk_core::{verify, Proof, VerificationKey};
        //
        // let vk_bytes = match circuit_type {
        //     CircuitType::Shield => vks::VK_SHIELD,
        //     CircuitType::Transfer => vks::VK_TRANSFER,
        //     CircuitType::Unshield => vks::VK_UNSHIELD,
        // };
        //
        // let vk = VerificationKey::from_onchain_bytes(vk_bytes)
        //     .map_err(|_| MaspError::InvalidVk)?;
        // let proof = Proof::from_bytes(proof_bytes)
        //     .map_err(|_| MaspError::InvalidProofData)?;
        //
        // verify(&vk, &proof, public_inputs)
        //     .map_err(|_| MaspError::ProofVerificationFailed)?;

        // STUB: For now, always succeed to test program logic
        msg!(
            "STUB[UltraPlonk]: Proof verification for {:?} with {} public inputs",
            circuit_type,
            public_inputs.len()
        );

        Ok(())
    }
}

// =============================================================================
// Groth16 Backend
// =============================================================================

pub mod groth16 {
    use super::*;

    /// Groth16 proof size in bytes (A, B, C points in compressed form)
    pub const PROOF_SIZE: usize = 192;

    /// Groth16 VK size varies by circuit (depends on number of public inputs)
    /// This is a typical size for ~10 public inputs
    pub const VK_SIZE_TYPICAL: usize = 384;

    /// Maximum public inputs per circuit
    pub const MAX_PUBLIC_INPUTS: usize = 16;

    // VK embedding (TODO: Generate via build.rs)
    //
    // Example build.rs pattern:
    // ```rust
    // // Use groth16-solana format
    // let vk = read_vk_from_noir_build("circuits/masp/shield/target/vk.json")?;
    // fs::write(out_dir.join("groth16_vk_shield.bin"), vk.to_bytes())?;
    // ```

    #[cfg(feature = "groth16-real-vks")]
    mod vks {
        pub const VK_SHIELD: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/groth16_vk_shield.bin"));
        pub const VK_TRANSFER: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/groth16_vk_transfer.bin"));
        pub const VK_UNSHIELD: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/groth16_vk_unshield.bin"));
    }

    /// Verify a Groth16 proof
    pub fn verify(
        circuit_type: CircuitType,
        public_inputs: &[[u8; 32]],
        proof_bytes: &[u8],
    ) -> Result<(), MaspError> {
        // Validate proof size
        if proof_bytes.len() != PROOF_SIZE {
            msg!(
                "Groth16: Invalid proof size: {} (expected {})",
                proof_bytes.len(),
                PROOF_SIZE
            );
            return Err(MaspError::InvalidProofData);
        }

        // Validate public inputs count
        if public_inputs.len() > MAX_PUBLIC_INPUTS {
            msg!(
                "Groth16: Too many public inputs: {} (max {})",
                public_inputs.len(),
                MAX_PUBLIC_INPUTS
            );
            return Err(MaspError::InvalidPublicInputs);
        }

        // TODO: Once VKs are generated, use real verification:
        //
        // use groth16_solana::{verify_proof, Groth16Verifyingkey};
        //
        // let vk_bytes = match circuit_type {
        //     CircuitType::Shield => vks::VK_SHIELD,
        //     CircuitType::Transfer => vks::VK_TRANSFER,
        //     CircuitType::Unshield => vks::VK_UNSHIELD,
        // };
        //
        // let vk = Groth16Verifyingkey::from_bytes(vk_bytes)
        //     .map_err(|_| MaspError::InvalidVk)?;
        //
        // verify_proof(&vk, proof_bytes, public_inputs)
        //     .map_err(|_| MaspError::ProofVerificationFailed)?;

        // STUB: For now, always succeed to test program logic
        msg!(
            "STUB[Groth16]: Proof verification for {:?} with {} public inputs",
            circuit_type,
            public_inputs.len()
        );

        Ok(())
    }
}

// =============================================================================
// Mock Backend (local-testing only)
// =============================================================================

/// Mock proof system for testing
///
/// ⚠️ **FOR LOCAL TESTING ONLY - NEVER USE IN PRODUCTION**
///
/// This proof system mirrors the client's `MockSpendProver` / `MockProofVerifier`:
/// - Proof = keccak256(circuit_type || public_inputs)
/// - Verification = check if proof matches expected hash
///
/// This allows testing both success AND failure paths:
/// - Correct proofs (matching hash) → verification succeeds
/// - Wrong proofs (mismatched hash) → verification fails
#[cfg(feature = "local-testing")]
pub mod mock {
    use super::*;
    use solana_program::keccak;

    /// Mock proof size (32 bytes = keccak256 hash)
    pub const PROOF_SIZE: usize = 32;

    /// Compute the expected mock proof for given public inputs
    fn expected_proof(circuit_type: CircuitType, public_inputs: &[[u8; 32]]) -> [u8; 32] {
        // Create a buffer with circuit_type discriminator + all public inputs
        let mut data = Vec::with_capacity(1 + public_inputs.len() * 32);
        data.push(circuit_type as u8);
        for pi in public_inputs {
            data.extend_from_slice(pi);
        }
        keccak::hash(&data).to_bytes()
    }

    /// Verify a mock proof
    ///
    /// Returns Ok(()) if proof == keccak256(circuit_type || public_inputs)
    /// Returns Err(ProofVerificationFailed) otherwise
    pub fn verify(
        circuit_type: CircuitType,
        public_inputs: &[[u8; 32]],
        proof_bytes: &[u8],
    ) -> Result<(), MaspError> {
        // Validate proof size
        if proof_bytes.len() != PROOF_SIZE {
            msg!(
                "Mock: Invalid proof size: {} (expected {})",
                proof_bytes.len(),
                PROOF_SIZE
            );
            return Err(MaspError::InvalidProofData);
        }

        // Compute expected proof
        let expected = expected_proof(circuit_type, public_inputs);

        // Compare
        if proof_bytes != expected {
            msg!("Mock: Proof verification failed - hash mismatch");
            return Err(MaspError::ProofVerificationFailed);
        }

        msg!(
            "Mock: Proof verified for {:?} with {} public inputs",
            circuit_type,
            public_inputs.len()
        );
        Ok(())
    }

    /// Generate a valid mock proof for testing
    ///
    /// This is the on-chain equivalent of `MockSpendProver.prove()`.
    /// Useful for tests that construct proofs directly.
    pub fn generate_proof(circuit_type: CircuitType, public_inputs: &[[u8; 32]]) -> [u8; 32] {
        expected_proof(circuit_type, public_inputs)
    }
}

// =============================================================================
// Public API - Dispatches to configured backend
// =============================================================================

/// Verify a proof using the currently configured proof system
///
/// # Arguments
/// * `circuit_type` - Which circuit to verify against
/// * `public_inputs` - Public inputs as 32-byte big-endian field elements
/// * `proof_bytes` - Raw proof bytes (size depends on proof system)
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(MaspError)` if verification fails or inputs are invalid
pub fn verify_proof(
    circuit_type: CircuitType,
    public_inputs: &[[u8; 32]],
    proof_bytes: &[u8],
) -> Result<(), MaspError> {
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => ultraplonk::verify(circuit_type, public_inputs, proof_bytes),
        ProofSystem::Groth16 => groth16::verify(circuit_type, public_inputs, proof_bytes),
        #[cfg(feature = "local-testing")]
        ProofSystem::Mock => mock::verify(circuit_type, public_inputs, proof_bytes),
    }
}

/// Verify a proof with explicit proof system selection
///
/// Use this when you need to verify a proof from a specific system,
/// regardless of the compile-time default.
pub fn verify_proof_with_system(
    proof_system: ProofSystem,
    circuit_type: CircuitType,
    public_inputs: &[[u8; 32]],
    proof_bytes: &[u8],
) -> Result<(), MaspError> {
    match proof_system {
        ProofSystem::UltraPlonk => ultraplonk::verify(circuit_type, public_inputs, proof_bytes),
        ProofSystem::Groth16 => groth16::verify(circuit_type, public_inputs, proof_bytes),
        #[cfg(feature = "local-testing")]
        ProofSystem::Mock => mock::verify(circuit_type, public_inputs, proof_bytes),
    }
}

// =============================================================================
// Circuit-Specific Wrappers
// =============================================================================

/// Verify a Shield proof
///
/// Public inputs layout (4 fields):
/// - new_commitment: Field
/// - public_asset_id: Field
/// - public_amount: u64 (as Field)
/// - ct_hash: Field
pub fn verify_shield(
    new_commitment: &[u8; 32],
    public_asset_id: &[u8; 32],
    public_amount: u64,
    ct_hash: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), MaspError> {
    let mut amount_bytes = [0u8; 32];
    amount_bytes[24..32].copy_from_slice(&public_amount.to_be_bytes());

    let public_inputs = [*new_commitment, *public_asset_id, amount_bytes, *ct_hash];

    verify_proof(CircuitType::Shield, &public_inputs, proof_bytes)
}

/// Verify a Transfer proof
///
/// Public inputs layout (13 fields for MAX_INPUTS=3, MAX_OUTPUTS=3):
/// - anchor: Field
/// - nullifiers[3]: [Field; 3]
/// - output_commitments[3]: [Field; 3]
/// - input_count: u32 (as Field)
/// - output_count: u32 (as Field)
/// - ct_hashes[3]: [Field; 3]
/// - tx_binding: Field
pub fn verify_transfer(
    anchor: &[u8; 32],
    nullifiers: &[[u8; 32]; 3],
    output_commitments: &[[u8; 32]; 3],
    input_count: u32,
    output_count: u32,
    ct_hashes: &[[u8; 32]; 3],
    tx_binding: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), MaspError> {
    // Build public inputs in circuit order
    let mut public_inputs = Vec::with_capacity(13);

    // anchor
    public_inputs.push(*anchor);

    // nullifiers[3]
    for nf in nullifiers {
        public_inputs.push(*nf);
    }

    // output_commitments[3]
    for cm in output_commitments {
        public_inputs.push(*cm);
    }

    // input_count as Field
    let mut input_count_bytes = [0u8; 32];
    input_count_bytes[28..32].copy_from_slice(&input_count.to_be_bytes());
    public_inputs.push(input_count_bytes);

    // output_count as Field
    let mut output_count_bytes = [0u8; 32];
    output_count_bytes[28..32].copy_from_slice(&output_count.to_be_bytes());
    public_inputs.push(output_count_bytes);

    // ct_hashes[3]
    for ct in ct_hashes {
        public_inputs.push(*ct);
    }

    // tx_binding
    public_inputs.push(*tx_binding);

    verify_proof(CircuitType::Transfer, &public_inputs, proof_bytes)
}

/// Verify an Unshield proof
///
/// Public inputs layout (9 fields):
/// - anchor: Field
/// - nullifier: Field
/// - tx_binding: Field
/// - public_amount: u64 (as Field)
/// - public_recipient_limbs[4]: [u64; 4] (each as Field)
/// - public_asset_id: Field
pub fn verify_unshield(
    anchor: &[u8; 32],
    nullifier: &[u8; 32],
    tx_binding: &[u8; 32],
    public_amount: u64,
    public_recipient_limbs: &[u64; 4],
    public_asset_id: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), MaspError> {
    let mut public_inputs = Vec::with_capacity(9);

    // anchor
    public_inputs.push(*anchor);

    // nullifier
    public_inputs.push(*nullifier);

    // tx_binding
    public_inputs.push(*tx_binding);

    // public_amount as Field
    let mut amount_bytes = [0u8; 32];
    amount_bytes[24..32].copy_from_slice(&public_amount.to_be_bytes());
    public_inputs.push(amount_bytes);

    // public_recipient_limbs[4] - each u64 as Field
    for limb in public_recipient_limbs {
        let mut limb_bytes = [0u8; 32];
        limb_bytes[24..32].copy_from_slice(&limb.to_be_bytes());
        public_inputs.push(limb_bytes);
    }

    // public_asset_id
    public_inputs.push(*public_asset_id);

    verify_proof(CircuitType::Unshield, &public_inputs, proof_bytes)
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Get the expected proof size for the current proof system
pub const fn current_proof_size() -> usize {
    CURRENT_PROOF_SYSTEM.proof_size()
}

/// Get the proof system name as a string (for logging)
pub fn proof_system_name() -> &'static str {
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => "UltraPlonk",
        ProofSystem::Groth16 => "Groth16",
        #[cfg(feature = "local-testing")]
        ProofSystem::Mock => "Mock",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_sizes() {
        assert_eq!(ultraplonk::PROOF_SIZE, 2144);
        assert_eq!(groth16::PROOF_SIZE, 192);
    }

    #[test]
    #[cfg(not(all(feature = "local-testing", feature = "mock-proofs")))]
    fn test_current_proof_system() {
        // Default should be UltraPlonk (when mock-proofs not enabled)
        assert_eq!(CURRENT_PROOF_SYSTEM, ProofSystem::UltraPlonk);
        assert_eq!(current_proof_size(), 2144);
        assert_eq!(proof_system_name(), "UltraPlonk");
    }

    #[test]
    #[cfg(all(feature = "local-testing", feature = "mock-proofs"))]
    fn test_current_proof_system_mock() {
        // When mock-proofs is enabled, should be Mock
        assert_eq!(CURRENT_PROOF_SYSTEM, ProofSystem::Mock);
        assert_eq!(current_proof_size(), 32);
        assert_eq!(proof_system_name(), "Mock");
    }
}

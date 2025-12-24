//! Proof verification for MASP circuits
//!
//! This module supports multiple proof systems with a unified `verify_proof()` entrypoint.
//!
//! ## Supported Proof Systems
//!
//! - **UltraPlonk** (default): ~2KB proofs, ~500K-1M CU, no trusted setup per circuit
//!   - Verification via CPI to `masp-verifier` program
//! - **Groth16** (optional): ~192B proofs, ~81K CU, requires trusted setup per circuit
//! - **Mock** (local-testing only): 32B proofs, hash-based verification, for testing
//!
//! ## Architecture
//!
//! ```text
//! verify.rs (this file)
//!   ├── ProofSystem enum (UltraPlonk, Groth16, Mock)
//!   ├── verify_proof() - unified dispatcher for all proof systems
//!   │
//!   ├── ultraplonk/ (module)
//!   │   ├── verify() - CPI to masp-verifier program
//!   │   └── PROOF_SIZE = 2144
//!   │
//!   ├── groth16/ (module)
//!   │   ├── verify() implementation (TODO)
//!   │   └── PROOF_SIZE = 192
//!   │
//!   └── mock/ (module, local-testing only)
//!       ├── verify() - keccak256-based mock verification
//!       └── PROOF_SIZE = 32
//! ```
//!
//! ## UltraPlonk CPI Architecture
//!
//! UltraPlonk verification is done via CPI to a separate `masp-verifier` program.
//! This isolates the stack-heavy verification code and avoids stack overflow
//! in the MASP program. VKs are embedded in the verifier program, not here.
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

extern crate alloc;

use crate::error::MaspError;
use crate::state::CircuitType;
use solana_program::account_info::AccountInfo;
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

    // Note: VKs are embedded in the masp-verifier program, not here.
    // UltraPlonk verification is done via CPI to masp-verifier.

    /// Verify an UltraPlonk proof via CPI to masp-verifier program
    ///
    /// This approach isolates the stack-heavy verification into a separate
    /// program call, avoiding stack overflow in complex MASP program.
    ///
    /// The proof buffer must already be populated with:
    /// - Header: [status, circuit_type, proof_len_lo, proof_len_hi, pi_count]
    /// - Public inputs: pi_count * 32 bytes
    /// - Proof: 2144 bytes
    pub fn verify<'a>(
        verifier_program: &AccountInfo<'a>,
        payer: &AccountInfo<'a>,
        proof_buffer: &AccountInfo<'a>,
    ) -> solana_program::entrypoint::ProgramResult {
        use solana_program::program::invoke;

        msg!("UltraPlonk: CPI to verifier");

        // Build Verify instruction (discriminator = 2)
        let ix_data = [2u8]; // IX_VERIFY

        let ix = solana_program::instruction::Instruction {
            program_id: *verifier_program.key,
            accounts: vec![
                solana_program::instruction::AccountMeta::new_readonly(*payer.key, true),
                solana_program::instruction::AccountMeta::new_readonly(*proof_buffer.key, false),
            ],
            data: ix_data.to_vec(),
        };

        // For CPI, the called program must also be in the account_infos
        invoke(
            &ix,
            &[
                payer.clone(),
                proof_buffer.clone(),
                verifier_program.clone(),
            ],
        )?;

        msg!("UltraPlonk: CPI verification succeeded");
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

// =============================================================================
// Proof Source Abstraction
// =============================================================================

/// Source of proof data for verification
///
/// Different proof systems have different verification approaches:
/// - **UltraPlonk**: Proof + public inputs in buffer account, verified via CPI
/// - **Groth16/Mock**: Proof as raw bytes, verified inline
///
/// ## Security Model
///
/// For buffer mode (UltraPlonk), the public inputs are extracted from the buffer
/// using `inputs.rs` and used for BOTH state updates and verification. This means:
/// - No separate validation is needed (same bytes used everywhere)
/// - The proof verification implicitly validates the PIs
/// - If buffer PIs don't match what was used to generate the proof, verification fails
pub enum ProofSource<'a, 'info> {
    /// Proof in a buffer account (for CPI-based verification like UltraPlonk)
    ///
    /// Buffer format: [status, circuit_type, proof_len(2), pi_count, public_inputs..., proof...]
    ///
    /// Public inputs are extracted from the buffer via `inputs.rs` and used for
    /// state updates. The same buffer is passed to the verifier, so the PIs are
    /// implicitly validated by the proof verification.
    Buffer {
        /// The verifier program to CPI into
        verifier_program: &'a AccountInfo<'info>,
        /// Transaction payer/signer
        payer: &'a AccountInfo<'info>,
        /// Account containing proof data (includes PIs + proof)
        proof_buffer: &'a AccountInfo<'info>,
    },

    /// Proof as raw bytes (for inline verification like Groth16, Mock)
    Bytes {
        /// Which circuit to verify
        circuit_type: CircuitType,
        /// Public inputs as 32-byte big-endian field elements
        public_inputs: &'a [[u8; 32]],
        /// Raw proof bytes
        proof_bytes: &'a [u8],
    },
}

/// Verify a proof using the currently configured proof system
///
/// This is the unified entrypoint for all proof verification. It dispatches
/// to the appropriate backend based on `CURRENT_PROOF_SYSTEM`.
///
/// ## Security Model
///
/// For `ProofSource::Buffer`, the public inputs are extracted from the buffer
/// via `inputs.rs` and used for state updates. The same buffer is then passed
/// here for verification. Since the proof was generated for specific PIs, and
/// we use those same PIs for state updates, security is maintained:
/// - If attacker modifies buffer PIs → proof verification fails
/// - If attacker uses different buffer → wrong PIs used for state updates
///
/// # Arguments
/// * `source` - The proof source (buffer for CPI, or raw bytes for inline)
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(ProgramError)` if verification fails
#[inline(always)]
pub fn verify_proof(source: ProofSource) -> solana_program::entrypoint::ProgramResult {
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => match source {
            ProofSource::Buffer {
                verifier_program,
                payer,
                proof_buffer,
            } => {
                // CPI to verifier - PIs are in the buffer
                ultraplonk::verify(verifier_program, payer, proof_buffer)
            }
            ProofSource::Bytes { .. } => {
                msg!("Error: UltraPlonk requires ProofSource::Buffer");
                Err(solana_program::program_error::ProgramError::InvalidArgument)
            }
        },
        ProofSystem::Groth16 => match source {
            ProofSource::Bytes {
                circuit_type,
                public_inputs,
                proof_bytes,
            } => groth16::verify(circuit_type, public_inputs, proof_bytes)
                .map_err(|_| solana_program::program_error::ProgramError::InvalidAccountData),
            ProofSource::Buffer { .. } => {
                msg!("Error: Groth16 requires ProofSource::Bytes");
                Err(solana_program::program_error::ProgramError::InvalidArgument)
            }
        },
        #[cfg(feature = "local-testing")]
        ProofSystem::Mock => match source {
            ProofSource::Bytes {
                circuit_type,
                public_inputs,
                proof_bytes,
            } => mock::verify(circuit_type, public_inputs, proof_bytes)
                .map_err(|_| solana_program::program_error::ProgramError::InvalidAccountData),
            ProofSource::Buffer { .. } => {
                msg!("Error: Mock requires ProofSource::Bytes");
                Err(solana_program::program_error::ProgramError::InvalidArgument)
            }
        },
    }
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

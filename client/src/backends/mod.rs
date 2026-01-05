//! Backend implementations and configuration
//!
//! This module provides different backend implementations for the MASP client:
//!
//! ## Chains
//! - `MockChain` - In-memory mock for testing
//! - `SolanaChain` - Real Solana blockchain (Surfpool, testnet, mainnet)
//!
//! ## Indexers
//! - `MockStore` - In-memory mock for testing
//! - `LightIndexer` - Helius RPC with Light Protocol support
//!
//! ## Encryption
//! - `ChaChaPolyEncryption` - ChaCha20-Poly1305 (production default)
//! - `MockEncryption` - Fast mock for testing
//!
//! ## Proof Systems
//! - `mock` - Placeholder proofs (fast iteration)
//! - `ultraplonk` - Noir UltraPlonk (via solana-ultraplonk-verifier) [scaffold]
//! - `groth16` - Noir Groth16 (via noir-solana-groth16) [scaffold]
//!
//! ## Configuration
//!
//! Backends can be configured via environment variables:
//!
//! ```bash
//! # Chain backend
//! MASP_CHAIN=mock           # In-memory mock (default)
//! MASP_CHAIN=surfpool       # Local Surfpool (http://127.0.0.1:8899)
//! MASP_CHAIN=devnet         # Solana devnet
//! MASP_CHAIN=testnet        # Solana testnet
//! MASP_CHAIN=mainnet        # Solana mainnet-beta
//!
//! # Indexer backend
//! MASP_INDEXER=mock         # In-memory mock (default)
//! MASP_INDEXER=light        # Light Protocol via Helius
//!
//! # Encryption backend
//! MASP_ENCRYPTION=chacha    # ChaCha20-Poly1305 (default)
//! MASP_ENCRYPTION=mock      # Mock encryption (fast testing)
//!
//! # Proof system backend
//! MASP_PROOF_SYSTEM=mock        # Mock prover/verifier (default)
//! MASP_PROOF_SYSTEM=ultraplonk  # UltraPlonk (scaffold)
//! MASP_PROOF_SYSTEM=groth16     # Groth16 (scaffold)
//! ```

pub mod config;
pub mod light;
pub mod proof_system;
pub mod solana;

// CLI-based prover using nargo + bb (no dep conflicts, uses installed tools)
pub mod cli_ultraplonk;

// Light Protocol client (Photon RPC for validity proofs)
#[cfg(feature = "light-protocol")]
pub mod light_protocol;

// Verifier backend (ultraplonk-core) - feature-gated due to solana-program deps
#[cfg(feature = "ultraplonk-verifier")]
pub mod ultraplonk_verifier;

pub use cli_ultraplonk::{CircuitType, CliProofManager, CliUltraPlonkProver};
pub use config::ProofSystemBackend;
pub use config::{BackendConfig, ChainBackend, EncryptionBackend, IndexerBackend};
pub use light::LightIndexer;

#[cfg(feature = "solana-backend")]
pub use solana::{IndexerMode, SolanaChain};

#[cfg(feature = "light-protocol")]
pub use light_protocol::{PhotonClient, CompressedProof, ValidityProofResult, BatchedValidityProof};

#[cfg(feature = "ultraplonk-verifier")]
pub use ultraplonk_verifier::NoirRsUltraPlonkVerifier;

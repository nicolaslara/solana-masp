//! Backend implementations and configuration
//!
//! This module provides different backend implementations for the MASP client:
//!
//! ## Chains
//! - `MockChain` - In-memory mock for testing
//! - `SolanaChain` - Real Solana blockchain (Surfpool, testnet, mainnet)
//!
//! ## Indexers
//! - `MockNoteStore` - In-memory mock for testing
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

pub use config::{BackendConfig, ChainBackend, EncryptionBackend, IndexerBackend};
pub use light::LightIndexer;
pub use config::ProofSystemBackend;
pub use solana::SolanaChain;

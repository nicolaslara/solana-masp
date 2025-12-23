//! Shared test environment for integration tests
//!
//! Goal: run the same tests with different backend implementations configured
//! via environment variables.
//!
//! ## Chain/Indexer Synchronization
//!
//! In test mode, the chain and indexer share the same `Arc<MockNoteStore>`.
//! When the chain processes transactions (shield, transfer, unshield), it
//! updates the shared store directly. The indexer reads from the same store,
//! so changes are visible immediately without external synchronization.
//!
//! This is "Mode A: Local Indexer" from `knowledge.md`. See
//! `client/src/backends/solana.rs` for the full architecture documentation.
//!
//! ```text
//! let shared_store = Arc::new(MockNoteStore::new(MERKLE_DEPTH));
//! let chain = SolanaChain::surfpool(shared_store.clone(), ...);
//! let indexer: Arc<dyn Indexer> = shared_store; // Same Arc!
//! ```
//!
//! ## Backend Configuration
//!
//! Backends are configured with:
//! - `MASP_CHAIN`      (mock|surfpool|devnet|testnet|mainnet|<custom_url>)
//! - `MASP_INDEXER`    (mock|light)
//! - `MASP_ENCRYPTION` (chacha|mock)  // mock is INSECURE, only for tests
//! - `MASP_PRINT_CONFIG=1` to print selection

use masp_client::backends::proof_system::{Groth16ProverScaffold, Groth16VerifierScaffold};
use masp_client::backends::{LightIndexer, SolanaChain};
use masp_client::mock::{MockChain, MockChainOptions, MockNoteStore};
use masp_client::proofs::{MockProofVerifier, MockSpendProver};
use masp_client::{
    BackendConfig, ChaChaPolyEncryption, Chain, ChainBackend, EncryptionBackend, Indexer,
    IndexerBackend, MaspClient, MockEncryption, NoteEncryption, ProofSystemBackend, ProofVerifier,
    SpendProver, SpendingKey,
};
use std::sync::Arc;

/// Test environment using runtime-configurable backends.
///
/// We store trait objects for backends to allow runtime selection.
/// `MaspClient` supports this via `MaspClient<dyn Indexer, dyn Chain>`.
pub struct TestEnv {
    #[allow(dead_code)]
    pub config: BackendConfig,
    pub indexer: Arc<dyn Indexer>,
    pub chain: Arc<dyn Chain>,
    pub encryption: Arc<dyn NoteEncryption>,
    #[allow(dead_code)]
    pub prover: Arc<dyn SpendProver>,
    #[allow(dead_code)]
    pub verifier: Arc<dyn ProofVerifier>,
}

impl TestEnv {
    /// Construct environment from env vars (single entrypoint).
    ///
    /// Today, non-mock backends are scaffolds that delegate to mocks, but we
    /// still instantiate the selected types so plumbing stays correct.
    pub fn from_env() -> Self {
        let config = BackendConfig::from_env();

        // Avoid interleaved output: tests run in parallel. Print the config at most once.
        if std::env::var("MASP_PRINT_CONFIG").is_ok() {
            static PRINT_ONCE: std::sync::Once = std::sync::Once::new();
            PRINT_ONCE.call_once(|| config.print_config());
        }

        // ARCHITECTURE: Shared store for "Mode A: Local Indexer" synchronization.
        //
        // The chain and indexer share the same Arc<MockNoteStore>. When the chain
        // processes transactions (shield, transfer, unshield), it updates the store
        // directly. The indexer reads from the same store, so changes are visible
        // immediately without external synchronization.
        //
        // In production (Mode B), the chain would NOT hold the store, and an external
        // indexer (Helius/Light) would observe the ledger independently.
        //
        // See: knowledge.md "Architecture Decision: Chain/Indexer Synchronization"
        // See: client/src/backends/solana.rs for full architecture docs
        let shared_store = Arc::new(MockNoteStore::new(masp_client::MERKLE_DEPTH));

        fn ultraplonk_prover() -> Arc<dyn SpendProver> {
            // Use CLI-based prover that shells out to nargo + bb.
            // Requires: nargo and bb installed, circuit compiled.
            Arc::new(masp_client::backends::CliUltraPlonkProver::new())
        }

        fn ultraplonk_verifier() -> Arc<dyn ProofVerifier> {
            #[cfg(feature = "ultraplonk-verifier")]
            {
                Arc::new(masp_client::backends::NoirRsUltraPlonkVerifier::new())
            }
            #[cfg(not(feature = "ultraplonk-verifier"))]
            {
                panic!(
                    "UltraPlonk proof system selected, but the local verifier is not compiled in. \
Compile tests with: `cargo test --features ultraplonk-verifier ...`"
                );
            }
        }

        let prover: Arc<dyn SpendProver> = match config.proof_system {
            ProofSystemBackend::Mock => Arc::new(MockSpendProver),
            ProofSystemBackend::UltraPlonk => ultraplonk_prover(),
            ProofSystemBackend::Groth16 => Arc::new(Groth16ProverScaffold::default()),
        };

        let verifier: Arc<dyn ProofVerifier> = match config.proof_system {
            ProofSystemBackend::Mock => Arc::new(MockProofVerifier),
            ProofSystemBackend::UltraPlonk => ultraplonk_verifier(),
            ProofSystemBackend::Groth16 => Arc::new(Groth16VerifierScaffold::default()),
        };

        // Indexer selection
        let indexer: Arc<dyn Indexer> = match config.indexer {
            IndexerBackend::Mock => shared_store.clone(),
            IndexerBackend::Light => {
                Arc::new(LightIndexer::helius_with_mock_store(shared_store.clone()))
            }
        };

        // Chain selection
        let chain: Arc<dyn Chain> = match &config.chain {
            ChainBackend::Mock => Arc::new(MockChain::new_with_options(
                shared_store.clone(),
                100,
                MockChainOptions {
                    verifier: verifier.clone(),
                    verify_mode: config.proof_verify.clone(),
                },
            )),
            ChainBackend::Surfpool => Arc::new(SolanaChain::surfpool(
                shared_store.clone(),
                verifier.clone(),
                config.proof_verify.clone(),
            )),
            ChainBackend::Devnet => Arc::new(SolanaChain::devnet(
                shared_store.clone(),
                verifier.clone(),
                config.proof_verify.clone(),
            )),
            ChainBackend::Testnet => Arc::new(SolanaChain::testnet(
                shared_store.clone(),
                verifier.clone(),
                config.proof_verify.clone(),
            )),
            ChainBackend::Mainnet => Arc::new(SolanaChain::mainnet(
                shared_store.clone(),
                verifier.clone(),
                config.proof_verify.clone(),
            )),
            ChainBackend::Custom(url) => Arc::new(SolanaChain::new(
                url,
                shared_store.clone(),
                verifier.clone(),
                config.proof_verify.clone(),
            )),
        };

        // Encryption selection (pluggable, concrete enum)
        let encryption: Arc<dyn NoteEncryption> = match config.encryption {
            EncryptionBackend::ChaCha => Arc::new(ChaChaPolyEncryption::new()),
            EncryptionBackend::Mock => Arc::new(MockEncryption),
        };

        Self {
            config,
            indexer,
            chain,
            encryption,
            prover,
            verifier,
        }
    }

    /// Create a client bound to the configured backends.
    pub fn create_client(&self, seed: &[u8; 32]) -> MaspClient<dyn Indexer, dyn Chain> {
        let sk = SpendingKey::from_bytes(seed);
        MaspClient::new(
            sk,
            self.indexer.clone(),
            self.chain.clone(),
            self.prover.clone(),
        )
    }
}

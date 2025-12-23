//! Shared test environment for integration tests
//!
//! Goal: run the same tests with different backend implementations configured
//! via environment variables.
//!
//! ## State Persistence
//!
//! **IMPORTANT:** All tests in the same test suite share a single TestEnv instance.
//! This means:
//! - The MockStore accumulates state across tests (like a real indexer would)
//! - On-chain state persists across tests (unless you redeploy the program)
//! - Tests must be designed to work with potentially non-empty state
//!
//! This matches production behavior where the indexer and chain accumulate history.
//!
//! ## Chain/Indexer Synchronization
//!
//! In test mode, the chain and indexer share the same `Arc<MockStore>`.
//! When the chain processes transactions (shield, transfer, unshield), it
//! updates the shared store directly. The indexer reads from the same store,
//! so changes are visible immediately without external synchronization.
//!
//! This is "LocalSync" mode from `knowledge.md`. See
//! `client/src/backends/solana.rs` for the full architecture documentation.
//!
//! ```text
//! let shared_store = Arc::new(MockStore::new(MERKLE_DEPTH));
//! let chain = SolanaChain::surfpool(IndexerMode::LocalSync(shared_store.clone()))?;
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
//!
//! ## Program Deployment (Solana)
//!
//! For Solana backends, deploy a fresh program before running tests:
//! ```bash
//! solana-keygen new --no-passphrase -o /tmp/masp_test.json --force
//! solana program deploy target/deploy/solana_masp.so \
//!   --url http://127.0.0.1:8899 --program-id /tmp/masp_test.json
//! MASP_PROGRAM_ID=<id> cargo test ...
//! ```

use masp_client::backends::proof_system::{Groth16ProverScaffold, Groth16VerifierScaffold};
use masp_client::backends::LightIndexer;
#[cfg(feature = "solana-backend")]
use masp_client::backends::{IndexerMode, SolanaChain};
use masp_client::mock::{MockChain, MockChainOptions, MockStore};
use masp_client::proofs::{MockProofVerifier, MockSpendProver};
use masp_client::{
    BackendConfig, ChaChaPolyEncryption, Chain, ChainBackend, EncryptionBackend, Indexer,
    IndexerBackend, MaspClient, MockEncryption, NoteEncryption, ProofSystemBackend, ProofVerifier,
    SpendProver, SpendingKey,
};
use std::sync::{Arc, OnceLock};

/// Singleton TestEnv - shared across all tests in the suite.
///
/// Uses OnceLock so the first test to call `from_env()` creates the environment,
/// and all subsequent tests reuse it. This ensures:
/// - MockStore accumulates state across tests (like a real indexer)
/// - Chain connection is reused (efficient)
/// - All tests see the same state progression
static SHARED_ENV: OnceLock<TestEnv> = OnceLock::new();

/// Test environment using runtime-configurable backends.
///
/// We store trait objects for backends to allow runtime selection.
/// `MaspClient` supports this via `MaspClient<dyn Indexer, dyn Chain>`.
///
/// **Note:** All tests in a suite share a single TestEnv instance via `from_env()`.
/// This ensures consistent state accumulation like a production indexer would have.
pub struct TestEnv {
    #[allow(dead_code)]
    pub config: BackendConfig,
    pub indexer: Arc<dyn Indexer>,
    pub chain: Arc<dyn Chain>,
    pub encryption: Arc<dyn NoteEncryption>,
    pub prover: Arc<dyn SpendProver>,
    #[allow(dead_code)]
    pub verifier: Arc<dyn ProofVerifier>,
}

// Safety: All Arc<dyn Trait> components are Send + Sync
unsafe impl Send for TestEnv {}
unsafe impl Sync for TestEnv {}

impl TestEnv {
    /// Get shared test environment from env vars.
    ///
    /// All tests in the suite share a single TestEnv instance. This ensures
    /// the MockStore accumulates state like a real indexer would, and the
    /// on-chain state stays in sync with local expectations.
    ///
    /// The first call creates the environment; subsequent calls return a clone
    /// of the shared instance.
    pub fn from_env() -> &'static Self {
        SHARED_ENV.get_or_init(Self::create_new)
    }

    /// Create a new environment (internal - called once via OnceLock).
    fn create_new() -> Self {
        let config = BackendConfig::from_env();

        // Avoid interleaved output: tests run in parallel. Print the config at most once.
        if std::env::var("MASP_PRINT_CONFIG").is_ok() {
            static PRINT_ONCE: std::sync::Once = std::sync::Once::new();
            PRINT_ONCE.call_once(|| config.print_config());
        }

        // ARCHITECTURE: Shared store for "Mode A: Local Indexer" synchronization.
        //
        // The chain and indexer share the same Arc<MockStore>. When the chain
        // processes transactions (shield, transfer, unshield), it updates the store
        // directly. The indexer reads from the same store, so changes are visible
        // immediately without external synchronization.
        //
        // In production (Mode B), the chain would NOT hold the store, and an external
        // indexer (Helius/Light) would observe the ledger independently.
        //
        // See: knowledge.md "Architecture Decision: Chain/Indexer Synchronization"
        // See: client/src/backends/solana.rs for full architecture docs
        let shared_store = Arc::new(MockStore::new(masp_client::MERKLE_DEPTH));

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

        // Prover/verifier selection
        //
        // When using mock proofs with a real Solana chain (surfpool/devnet/etc),
        // we need to use OnChainMockSpendProver which generates Keccak256-based
        // proofs compatible with the on-chain mock verifier.
        //
        // When using mock proofs with MockChain, we use the simpler MockSpendProver.
        let uses_real_chain = !matches!(config.chain, ChainBackend::Mock);

        let prover: Arc<dyn SpendProver> = match config.proof_system {
            ProofSystemBackend::Mock if uses_real_chain => {
                #[cfg(feature = "onchain-mock")]
                {
                    Arc::new(masp_client::proofs::OnChainMockSpendProver)
                }
                #[cfg(not(feature = "onchain-mock"))]
                {
                    panic!(
                        "Using mock proofs with a real Solana chain requires the `onchain-mock` feature. \
                        Compile with: cargo test --features solana-backend,onchain-mock ..."
                    );
                }
            }
            ProofSystemBackend::Mock => Arc::new(MockSpendProver),
            ProofSystemBackend::UltraPlonk => ultraplonk_prover(),
            ProofSystemBackend::Groth16 => Arc::new(Groth16ProverScaffold::default()),
        };

        let verifier: Arc<dyn ProofVerifier> = match config.proof_system {
            ProofSystemBackend::Mock if uses_real_chain => {
                #[cfg(feature = "onchain-mock")]
                {
                    Arc::new(masp_client::proofs::OnChainMockProofVerifier)
                }
                #[cfg(not(feature = "onchain-mock"))]
                {
                    panic!("Using mock proofs with a real Solana chain requires the `onchain-mock` feature.");
                }
            }
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
            #[cfg(feature = "solana-backend")]
            ChainBackend::Surfpool => Arc::new(
                SolanaChain::surfpool(IndexerMode::LocalSync(shared_store.clone()))
                    .expect("Failed to create Surfpool SolanaChain"),
            ),
            #[cfg(feature = "solana-backend")]
            ChainBackend::Devnet => Arc::new(
                SolanaChain::devnet(IndexerMode::LocalSync(shared_store.clone()))
                    .expect("Failed to create Devnet SolanaChain"),
            ),
            #[cfg(feature = "solana-backend")]
            ChainBackend::Testnet => Arc::new(
                SolanaChain::testnet(IndexerMode::LocalSync(shared_store.clone()))
                    .expect("Failed to create Testnet SolanaChain"),
            ),
            #[cfg(feature = "solana-backend")]
            ChainBackend::Mainnet => {
                // Mainnet: require explicit MASP_PROGRAM_ID (no auto-deploy)
                if std::env::var("MASP_PROGRAM_ID").is_err() {
                    panic!(
                        "MASP_PROGRAM_ID required for mainnet. \
                        Auto-deploy is disabled for safety."
                    );
                }
                Arc::new(SolanaChain::mainnet().expect("Failed to create Mainnet SolanaChain"))
            }
            #[cfg(feature = "solana-backend")]
            ChainBackend::Custom(url) => Arc::new(
                SolanaChain::new(url, IndexerMode::LocalSync(shared_store.clone()))
                    .expect("Failed to create custom SolanaChain"),
            ),
            #[cfg(not(feature = "solana-backend"))]
            _ => {
                eprintln!(
                    "⚠️  MASP_CHAIN={} requires `solana-backend` feature. Using MockChain.",
                    match &config.chain {
                        ChainBackend::Mock => "mock",
                        ChainBackend::Surfpool => "surfpool",
                        ChainBackend::Devnet => "devnet",
                        ChainBackend::Testnet => "testnet",
                        ChainBackend::Mainnet => "mainnet",
                        ChainBackend::Custom(url) => url,
                    }
                );
                Arc::new(MockChain::new_with_options(
                    shared_store.clone(),
                    100,
                    MockChainOptions {
                        verifier: verifier.clone(),
                        verify_mode: config.proof_verify.clone(),
                    },
                ))
            }
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

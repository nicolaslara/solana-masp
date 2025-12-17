//! Shared test environment for integration tests
//!
//! Goal: run the same tests with different backend implementations configured
//! via environment variables.
//!
//! Backends are configured with:
//! - `MASP_CHAIN`      (mock|surfpool|devnet|testnet|mainnet|<custom_url>)
//! - `MASP_INDEXER`    (mock|light)
//! - `MASP_ENCRYPTION` (chacha|mock)  // mock is INSECURE, only for tests
//! - `MASP_PRINT_CONFIG=1` to print selection

use masp_client::backends::proof_system::{
    Groth16ProverScaffold, Groth16VerifierScaffold, UltraPlonkProverScaffold,
    UltraPlonkVerifierScaffold,
};
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
    pub prover: Arc<dyn SpendProver>,
    pub verifier: Arc<dyn ProofVerifier>,
}

impl TestEnv {
    /// Construct environment from env vars (single entrypoint).
    ///
    /// Today, non-mock backends are scaffolds that delegate to mocks, but we
    /// still instantiate the selected types so plumbing stays correct.
    pub fn from_env() -> Self {
        let config = BackendConfig::from_env();

        if std::env::var("MASP_PRINT_CONFIG").is_ok() {
            config.print_config();
        }

        // Shared store so chain writes are visible to the indexer in scaffold mode.
        let shared_store = Arc::new(MockNoteStore::new(16));

        // Proof system selection (scaffolds today)
        let prover: Arc<dyn SpendProver> = match config.proof_system {
            ProofSystemBackend::Mock => Arc::new(MockSpendProver),
            ProofSystemBackend::UltraPlonk => Arc::new(UltraPlonkProverScaffold::default()),
            ProofSystemBackend::Groth16 => Arc::new(Groth16ProverScaffold::default()),
        };

        let verifier: Arc<dyn ProofVerifier> = match config.proof_system {
            ProofSystemBackend::Mock => Arc::new(MockProofVerifier),
            ProofSystemBackend::UltraPlonk => Arc::new(UltraPlonkVerifierScaffold::default()),
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
        MaspClient::new(sk, self.indexer.clone(), self.chain.clone())
    }
}

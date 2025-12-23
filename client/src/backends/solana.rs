//! Solana chain backend
//!
//! This module provides the real Solana blockchain implementation for MASP.
//!
//! ## Usage Modes
//!
//! ### LocalSync Mode (Testing with Surfpool)
//!
//! For tests, SolanaChain shares a `MockStore` with the indexer.
//! After each transaction, it updates the store so the indexer sees changes.
//! This is fast and deterministic - perfect for unit/integration tests.
//!
//! ```ignore
//! let shared_store = Arc::new(MockStore::new(MERKLE_DEPTH));
//! let chain = SolanaChain::surfpool(IndexerMode::LocalSync(shared_store.clone()))?;
//! let indexer: Arc<dyn Indexer> = shared_store; // Same Arc!
//! ```
//!
//! ### ExternalIndexer Mode (Production)
//!
//! In production, SolanaChain just submits transactions. An external indexer
//! (Helius/Light) watches the ledger independently and updates its own state.
//!
//! ```ignore
//! let chain = SolanaChain::mainnet()?;
//! let indexer = HeliusIndexer::new(api_key)?;
//! ```
//!
//! ## Configuration
//!
//! Environment variables:
//! - `MASP_PROGRAM_ID` - Program ID (required for non-mock)
//! - `MASP_PAYER_KEYPAIR` - Path to payer keypair JSON (optional, uses default)

#[cfg(feature = "solana-backend")]
mod real_backend {
    use crate::mock::MockStore;
    use crate::traits::{
        Chain, ChainError, CiphertextPostingRequest, CiphertextPostingResult,
        InsertCommitmentResult, ShieldRequest, ShieldResult, TransferRequest, TransferResult,
        UnshieldRequest, UnshieldResult,
    };
    use crate::types::{Anchor, Commitment, Nullifier};

    // =========================================================================
    // Indexer Mode Configuration
    // =========================================================================

    /// How the chain synchronizes with the indexer.
    ///
    /// This determines whether the chain updates a local store directly (for tests)
    /// or relies on an external indexer to observe the ledger (production).
    #[derive(Clone)]
    pub enum IndexerMode {
        /// Chain shares store with indexer - updates happen synchronously.
        ///
        /// Use for: unit tests, integration tests, local development.
        /// The chain and indexer share the same `Arc<MockStore>`.
        LocalSync(Arc<MockStore>),

        /// External indexer observes ledger independently.
        ///
        /// Use for: production, staging, any environment with real indexers.
        /// Chain just submits TXs; Helius/Light Protocol indexes asynchronously.
        External,
    }

    impl std::fmt::Debug for IndexerMode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                IndexerMode::LocalSync(_) => write!(f, "LocalSync"),
                IndexerMode::External => write!(f, "External"),
            }
        }
    }
    use async_trait::async_trait;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use std::str::FromStr;
    use std::sync::Arc;

    /// System Program ID (11111111111111111111111111111111)
    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    // Instruction discriminators (must match solana-masp program)
    const IX_INITIALIZE: u8 = 0;
    const IX_INIT_PROOF_BUFFER: u8 = 1;
    const IX_UPLOAD_CHUNK: u8 = 2;
    const IX_SHIELD: u8 = 3;
    #[allow(dead_code)]
    const IX_TRANSFER: u8 = 4;
    #[allow(dead_code)]
    const IX_UNSHIELD: u8 = 5;

    // Circuit types
    const CIRCUIT_SHIELD: u8 = 0;
    #[allow(dead_code)]
    const CIRCUIT_TRANSFER: u8 = 1;
    #[allow(dead_code)]
    const CIRCUIT_UNSHIELD: u8 = 2;

    /// Derive tree state PDA
    fn derive_tree_state_pda(program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"masp", b"state"], program_id)
    }

    /// Real Solana chain backend
    ///
    /// Submits actual transactions to Solana (Surfpool, Devnet, Mainnet).
    ///
    /// ## IndexerMode Configuration
    ///
    /// - `IndexerMode::LocalSync(store)` - Chain updates store after each TX (tests)
    /// - `IndexerMode::External` - Chain just submits; external indexer observes (production)
    ///
    /// Note: SolanaChain does NOT verify proofs locally - that happens on-chain.
    /// Submitting an invalid proof will fail when the transaction is processed.
    pub struct SolanaChain {
        rpc_client: RpcClient,
        program_id: Pubkey,
        payer: Keypair,
        /// Indexer synchronization mode
        indexer_mode: IndexerMode,
        /// Whether program has been initialized (cached)
        initialized: std::sync::atomic::AtomicBool,
    }

    impl SolanaChain {
        /// Create a new SolanaChain with full configuration.
        pub fn new_with_config(
            rpc_url: &str,
            program_id: &str,
            payer: Keypair,
            indexer_mode: IndexerMode,
        ) -> Result<Self, ChainError> {
            let program_id = Pubkey::from_str(program_id)
                .map_err(|e| ChainError::Other(format!("Invalid program ID: {}", e)))?;

            let rpc_client = RpcClient::new(rpc_url.to_string());

            println!("🔗 SolanaChain: Real Solana backend");
            println!("   RPC URL: {}", rpc_url);
            println!("   Program: {}", program_id);
            println!("   Payer: {}", payer.pubkey());
            println!("   Indexer mode: {:?}", indexer_mode);

            Ok(Self {
                rpc_client,
                program_id,
                payer,
                indexer_mode,
                initialized: std::sync::atomic::AtomicBool::new(false),
            })
        }

        /// Create from environment variables.
        ///
        /// Reads:
        /// - `MASP_PROGRAM_ID` (required)
        /// - `MASP_PAYER_KEYPAIR` (optional, uses ~/.config/solana/id.json)
        pub fn from_env(rpc_url: &str, indexer_mode: IndexerMode) -> Result<Self, ChainError> {
            let program_id = std::env::var("MASP_PROGRAM_ID").map_err(|_| {
                ChainError::Other("MASP_PROGRAM_ID env var required for Solana backend".to_string())
            })?;

            let payer = load_payer_keypair()?;

            Self::new_with_config(rpc_url, &program_id, payer, indexer_mode)
        }

        /// Create for Surfpool (localhost).
        pub fn surfpool(indexer_mode: IndexerMode) -> Result<Self, ChainError> {
            Self::from_env("http://127.0.0.1:8899", indexer_mode)
        }

        /// Create for Devnet.
        pub fn devnet(indexer_mode: IndexerMode) -> Result<Self, ChainError> {
            Self::from_env("https://api.devnet.solana.com", indexer_mode)
        }

        /// Create for Testnet.
        pub fn testnet(indexer_mode: IndexerMode) -> Result<Self, ChainError> {
            Self::from_env("https://api.testnet.solana.com", indexer_mode)
        }

        /// Create for Mainnet (always ExternalIndexer - no local store in production).
        pub fn mainnet() -> Result<Self, ChainError> {
            Self::from_env("https://api.mainnet-beta.solana.com", IndexerMode::External)
        }

        /// Create for custom RPC URL.
        pub fn new(rpc_url: &str, indexer_mode: IndexerMode) -> Result<Self, ChainError> {
            Self::from_env(rpc_url, indexer_mode)
        }

        /// Get the local store if in LocalSync mode.
        fn local_store(&self) -> Option<&Arc<MockStore>> {
            match &self.indexer_mode {
                IndexerMode::LocalSync(store) => Some(store),
                IndexerMode::External => None,
            }
        }

        /// Get the RPC URL
        pub fn rpc_url(&self) -> String {
            self.rpc_client.url()
        }

        /// Get the program ID
        pub fn program_id(&self) -> &Pubkey {
            &self.program_id
        }

        /// Ensure program is initialized (idempotent).
        async fn ensure_initialized(&self) -> Result<(), ChainError> {
            if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }

            let (tree_state_pda, _) = derive_tree_state_pda(&self.program_id);

            // Check if already initialized on-chain
            match self.rpc_client.get_account(&tree_state_pda).await {
                Ok(_) => {
                    self.initialized
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                Err(_) => {
                    // Not initialized, do it now
                }
            }

            println!("🔧 Initializing MASP program...");

            let ix = Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new(tree_state_pda, false),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                ],
                data: vec![IX_INITIALIZE],
            };

            self.send_transaction(&[ix]).await?;
            self.initialized
                .store(true, std::sync::atomic::Ordering::Relaxed);
            println!("✅ MASP program initialized");

            Ok(())
        }

        /// Create and populate a proof buffer
        async fn create_proof_buffer(
            &self,
            circuit_type: u8,
            public_inputs: &[[u8; 32]],
            proof: &[u8],
        ) -> Result<Pubkey, ChainError> {
            let buffer = Keypair::new();
            let pi_count = public_inputs.len() as u8;

            // Step 1: Initialize buffer
            let init_data = vec![IX_INIT_PROOF_BUFFER, circuit_type, pi_count];
            let init_ix = Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new(buffer.pubkey(), true),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                ],
                data: init_data,
            };

            let blockhash = self
                .rpc_client
                .get_latest_blockhash()
                .await
                .map_err(|e| ChainError::Other(format!("Failed to get blockhash: {}", e)))?;

            let tx = Transaction::new_signed_with_payer(
                &[init_ix],
                Some(&self.payer.pubkey()),
                &[&self.payer, &buffer],
                blockhash,
            );

            self.rpc_client
                .send_and_confirm_transaction(&tx)
                .await
                .map_err(|e| ChainError::Other(format!("Failed to create proof buffer: {}", e)))?;

            // Step 2: Upload proof data
            let mut proof_data = Vec::new();
            for pi in public_inputs {
                proof_data.extend_from_slice(pi);
            }
            proof_data.extend_from_slice(proof);

            let mut upload_data = vec![IX_UPLOAD_CHUNK];
            upload_data.extend_from_slice(&0u16.to_le_bytes()); // offset = 0
            upload_data.extend_from_slice(&proof_data);

            let upload_ix = Instruction {
                program_id: self.program_id,
                accounts: vec![AccountMeta::new(buffer.pubkey(), false)],
                data: upload_data,
            };

            self.send_transaction(&[upload_ix]).await?;

            Ok(buffer.pubkey())
        }

        async fn send_transaction(
            &self,
            instructions: &[Instruction],
        ) -> Result<String, ChainError> {
            let blockhash = self
                .rpc_client
                .get_latest_blockhash()
                .await
                .map_err(|e| ChainError::Other(format!("Failed to get blockhash: {}", e)))?;

            let tx = Transaction::new_signed_with_payer(
                instructions,
                Some(&self.payer.pubkey()),
                &[&self.payer],
                blockhash,
            );

            let sig = self
                .rpc_client
                .send_and_confirm_transaction(&tx)
                .await
                .map_err(|e| ChainError::Other(format!("Transaction failed: {}", e)))?;

            Ok(sig.to_string())
        }

        fn commitment_to_bytes(commitment: &Commitment) -> [u8; 32] {
            use ark_ff::{BigInteger, PrimeField};
            let bytes = commitment.into_bigint().to_bytes_be();
            let mut result = [0u8; 32];
            result.copy_from_slice(&bytes);
            result
        }
    }

    /// Load payer keypair from file or env
    fn load_payer_keypair() -> Result<Keypair, ChainError> {
        // Try MASP_PAYER_KEYPAIR env var first
        if let Ok(path) = std::env::var("MASP_PAYER_KEYPAIR") {
            return load_keypair_from_file(&path);
        }

        // Fall back to default Solana CLI keypair
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let default_path = format!("{}/.config/solana/id.json", home);

        if std::path::Path::new(&default_path).exists() {
            return load_keypair_from_file(&default_path);
        }

        Err(ChainError::Other(
            "No payer keypair found. Set MASP_PAYER_KEYPAIR or run `solana-keygen new`".to_string(),
        ))
    }

    fn load_keypair_from_file(path: &str) -> Result<Keypair, ChainError> {
        let file_content = std::fs::read_to_string(path)
            .map_err(|e| ChainError::Other(format!("Failed to read keypair file: {}", e)))?;

        let bytes: Vec<u8> = serde_json::from_str(&file_content)
            .map_err(|e| ChainError::Other(format!("Failed to parse keypair JSON: {}", e)))?;

        // Solana SDK 3.x uses TryFrom<&[u8]> instead of from_bytes
        Keypair::try_from(bytes.as_slice())
            .map_err(|e| ChainError::Other(format!("Invalid keypair bytes: {}", e)))
    }

    #[async_trait]
    impl Chain for SolanaChain {
        async fn insert_commitment(
            &self,
            commitment: Commitment,
        ) -> Result<InsertCommitmentResult, ChainError> {
            // For LocalSync mode (local store), we can insert directly
            if let Some(store) = self.local_store() {
                store.insert_note_commitment(commitment, "direct_insert");
                return Ok(InsertCommitmentResult {
                    tx_sig: "local_insert".to_string(),
                    commitment,
                });
            }

            // For ExternalIndexer mode, commitment insertion happens via shield/transfer
            Err(ChainError::Other(
                "Direct insert_commitment not supported in ExternalIndexer mode - use shield()"
                    .to_string(),
            ))
        }

        async fn insert_nullifier(&self, _nullifier: Nullifier) -> Result<String, ChainError> {
            // Nullifier insertion happens via transfer/unshield instructions
            Err(ChainError::Other(
                "Direct insert_nullifier not supported - use transfer()/unshield()".to_string(),
            ))
        }

        async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
            // For LocalSync mode, read from local store
            if let Some(store) = self.local_store() {
                return Ok(store.current_root());
            }

            // For ExternalIndexer mode, would need to query on-chain state
            Err(ChainError::Other(
                "get_current_anchor requires local store or indexer".to_string(),
            ))
        }

        async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError> {
            // For LocalSync mode, check if anchor matches current root
            // Note: MockStore doesn't track anchor history, so we only check current
            if let Some(store) = self.local_store() {
                let current_root = store.current_root();
                return Ok(*anchor == current_root);
            }

            Err(ChainError::Other(
                "is_valid_anchor requires local store or indexer".to_string(),
            ))
        }

        async fn is_nullifier_spent(&self, _nullifier: &Nullifier) -> Result<bool, ChainError> {
            // For LocalSync mode with MockStore, nullifier tracking would need to be added
            // For now, return false (not spent) - real nullifier checks happen on-chain
            if self.local_store().is_some() {
                // TODO: Add nullifier tracking to MockStore or use separate set
                return Ok(false);
            }

            Err(ChainError::Other(
                "is_nullifier_spent requires local store or indexer".to_string(),
            ))
        }

        async fn post_ciphertexts(
            &self,
            _request: CiphertextPostingRequest,
        ) -> Result<CiphertextPostingResult, ChainError> {
            // TODO: Implement ciphertext posting (Tx A in two-tx model)
            Err(ChainError::Other(
                "post_ciphertexts not yet implemented".to_string(),
            ))
        }

        async fn shield(&self, request: ShieldRequest) -> Result<ShieldResult, ChainError> {
            // Ensure program is initialized
            self.ensure_initialized().await?;

            let (tree_state_pda, _) = derive_tree_state_pda(&self.program_id);

            // Convert commitment to bytes
            let commitment_bytes = Self::commitment_to_bytes(&request.commitment);

            // Build public inputs - must match what prover used
            let asset_id = crate::note::compute_asset_id(&request.token_address);
            let asset_id_bytes = Self::commitment_to_bytes(&asset_id);
            let amount_bytes = {
                let mut buf = [0u8; 32];
                buf[24..32].copy_from_slice(&request.amount.to_be_bytes());
                buf
            };
            let ct_hash_bytes = Self::commitment_to_bytes(&request.ct_hash);

            let public_inputs = [
                commitment_bytes,
                asset_id_bytes,
                amount_bytes,
                ct_hash_bytes,
            ];

            // Create proof buffer with the proof bytes
            let proof_buffer = self
                .create_proof_buffer(CIRCUIT_SHIELD, &public_inputs, &request.shield_proof)
                .await?;

            // Build shield instruction data
            let mut data = vec![IX_SHIELD];
            data.extend_from_slice(&commitment_bytes);
            data.extend_from_slice(&asset_id_bytes);
            data.extend_from_slice(&request.amount.to_le_bytes());
            data.extend_from_slice(&ct_hash_bytes);

            let ix = Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new(tree_state_pda, false),
                    AccountMeta::new_readonly(proof_buffer, false),
                ],
                data,
            };

            let tx_sig = self.send_transaction(&[ix]).await?;

            // Update local store if present (LocalSync mode sync)
            if let Some(store) = self.local_store() {
                store.insert_note_commitment(request.commitment, &tx_sig);
            }

            Ok(ShieldResult {
                tx_sig,
                commitment: request.commitment,
            })
        }

        async fn transfer(&self, _request: TransferRequest) -> Result<TransferResult, ChainError> {
            // TODO: Implement transfer
            Err(ChainError::Other(
                "transfer not yet implemented".to_string(),
            ))
        }

        async fn unshield(&self, _request: UnshieldRequest) -> Result<UnshieldResult, ChainError> {
            // TODO: Implement unshield
            Err(ChainError::Other(
                "unshield not yet implemented".to_string(),
            ))
        }
    }
}

#[cfg(feature = "solana-backend")]
pub use real_backend::{IndexerMode, SolanaChain};

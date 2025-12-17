//! Solana chain backend (scaffold)
//!
//! This module will provide a real Solana chain implementation.
//!
//! ## Status: SCAFFOLD
//!
//! Currently uses MockChain internally to verify the plugging works.
//! Will be replaced with real Solana RPC client.
//!
//! ## Future Implementation
//!
//! ```ignore
//! use solana_client::rpc_client::RpcClient;
//! use solana_sdk::{signature::Keypair, transaction::Transaction};
//!
//! impl SolanaChain {
//!     pub fn new(rpc_url: &str, payer: Keypair) -> Self { ... }
//! }
//! ```

use crate::backends::config::ProofVerificationMode;
use crate::mock::{MockChain, MockChainOptions, MockNoteStore};
use crate::traits::{
    Chain, ChainError, InsertCommitmentResult, ProofVerifier, ShieldRequest, ShieldResult,
    TransferRequest, TransferResult, UnshieldRequest, UnshieldResult,
};
use crate::types::{Anchor, Commitment, Nullifier};
use async_trait::async_trait;
use std::sync::Arc;

/// Solana chain backend
///
/// ## Current Status: SCAFFOLD
///
/// Uses MockChain internally. Will be replaced with real Solana client.
pub struct SolanaChain {
    /// RPC URL
    rpc_url: String,
    /// Internal mock (temporary - will be replaced with real client)
    inner: Arc<MockChain>,
}

impl SolanaChain {
    /// Create a new Solana chain backend
    ///
    /// Currently uses mock internally.
    pub fn new(
        rpc_url: &str,
        indexer: Arc<MockNoteStore>,
        verifier: Arc<dyn ProofVerifier>,
        verify_mode: ProofVerificationMode,
    ) -> Self {
        println!("🔗 SolanaChain: Initializing (scaffold mode)");
        println!("   RPC URL: {}", rpc_url);
        println!("   ⚠️  Using MockChain internally until real implementation");
        println!("   Proof verify mode: {}", verify_mode);
        println!("   Verifier: {}", verifier.system_name());

        Self {
            rpc_url: rpc_url.to_string(),
            inner: Arc::new(MockChain::new_with_options(
                indexer,
                100,
                MockChainOptions {
                    verifier,
                    verify_mode,
                },
            )),
        }
    }

    /// Get the RPC URL
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

#[async_trait]
impl Chain for SolanaChain {
    // ===== Low-level state operations =====

    async fn insert_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<InsertCommitmentResult, ChainError> {
        self.inner.insert_commitment(commitment).await
    }

    async fn insert_nullifier(&self, nullifier: Nullifier) -> Result<String, ChainError> {
        self.inner.insert_nullifier(nullifier).await
    }

    async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
        self.inner.get_current_anchor().await
    }

    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError> {
        self.inner.is_valid_anchor(anchor).await
    }

    async fn is_nullifier_spent(&self, nullifier: &Nullifier) -> Result<bool, ChainError> {
        self.inner.is_nullifier_spent(nullifier).await
    }

    async fn batch_check_nullifiers(
        &self,
        nullifiers: &[Nullifier],
    ) -> Result<Vec<bool>, ChainError> {
        self.inner.batch_check_nullifiers(nullifiers).await
    }

    // ===== High-level operations =====

    async fn shield(&self, request: ShieldRequest) -> Result<ShieldResult, ChainError> {
        self.inner.shield(request).await
    }

    async fn transfer(&self, request: TransferRequest) -> Result<TransferResult, ChainError> {
        self.inner.transfer(request).await
    }

    async fn unshield(&self, request: UnshieldRequest) -> Result<UnshieldResult, ChainError> {
        self.inner.unshield(request).await
    }
}

/// Helper to create SolanaChain for testing
impl SolanaChain {
    /// Create a Surfpool chain (local testing)
    pub fn surfpool(
        indexer: Arc<MockNoteStore>,
        verifier: Arc<dyn ProofVerifier>,
        verify_mode: ProofVerificationMode,
    ) -> Self {
        Self::new("http://127.0.0.1:8899", indexer, verifier, verify_mode)
    }

    /// Create a devnet chain
    pub fn devnet(
        indexer: Arc<MockNoteStore>,
        verifier: Arc<dyn ProofVerifier>,
        verify_mode: ProofVerificationMode,
    ) -> Self {
        Self::new(
            "https://api.devnet.solana.com",
            indexer,
            verifier,
            verify_mode,
        )
    }

    /// Create a testnet chain
    pub fn testnet(
        indexer: Arc<MockNoteStore>,
        verifier: Arc<dyn ProofVerifier>,
        verify_mode: ProofVerificationMode,
    ) -> Self {
        Self::new(
            "https://api.testnet.solana.com",
            indexer,
            verifier,
            verify_mode,
        )
    }

    /// Create a mainnet chain
    pub fn mainnet(
        indexer: Arc<MockNoteStore>,
        verifier: Arc<dyn ProofVerifier>,
        verify_mode: ProofVerificationMode,
    ) -> Self {
        Self::new(
            "https://api.mainnet-beta.solana.com",
            indexer,
            verifier,
            verify_mode,
        )
    }
}

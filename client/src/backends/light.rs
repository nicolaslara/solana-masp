//! Light Protocol indexer backend (scaffold)
//!
//! This module will provide a Light Protocol indexer via Helius RPC.
//!
//! ## Status: SCAFFOLD
//!
//! Currently uses MockNoteStore internally to verify the plugging works.
//! Will be replaced with real Helius/Light Protocol client.
//!
//! ## Future Implementation
//!
//! ```ignore
//! use helius_sdk::Helius;
//!
//! impl LightIndexer {
//!     pub fn new(api_key: &str) -> Self { ... }
//!
//!     // Light Protocol specific methods
//!     async fn get_compressed_account(&self, address: Pubkey) -> ... { ... }
//!     async fn get_validity_proof(&self, addresses: &[Pubkey]) -> ... { ... }
//! }
//! ```
//!
//! ## Helius ZK Compression API
//!
//! Key endpoints we'll use:
//! - `getCompressedAccount` - Fetch compressed account by address
//! - `getCompressedAccountProof` - Get Merkle proof for account
//! - `getMultipleCompressedAccountProofs` - Batch proofs
//! - `getCompressedAccountsByOwner` - List accounts by owner
//!
//! See: https://www.helius.dev/docs/api-reference/zk-compression/

use crate::mock::MockNoteStore;
use crate::proofs::MembershipWitness;
use crate::traits::{Indexer, IndexerError, NoteCommitmentStore, OutputCiphertext, StoreError};
use crate::types::{Anchor, Commitment};
use async_trait::async_trait;
use std::sync::Arc;

/// Light Protocol indexer backend
///
/// ## Current Status: SCAFFOLD
///
/// Uses MockNoteStore internally. Will be replaced with Helius client.
pub struct LightIndexer {
    /// Helius API key (for future use)
    _api_key: Option<String>,
    /// Internal mock (temporary - will be replaced with real client)
    inner: Arc<MockNoteStore>,
}

impl LightIndexer {
    /// Create a new Light Protocol indexer using an injected mock store.
    ///
    /// This is the recommended constructor for tests so the chain and indexer
    /// share the same underlying state (scaffold mode).
    pub fn with_mock_store(inner: Arc<MockNoteStore>, api_key: Option<&str>) -> Self {
        println!("📡 LightIndexer: Initializing (scaffold mode)");
        if let Some(key) = api_key {
            println!("   API Key: {}...", &key[..8.min(key.len())]);
        } else {
            println!("   API Key: not configured");
        }
        println!("   ⚠️  Using MockNoteStore internally until real implementation");

        Self {
            _api_key: api_key.map(String::from),
            inner,
        }
    }

    /// Create with default Helius configuration
    pub fn helius_with_mock_store(inner: Arc<MockNoteStore>) -> Self {
        let api_key = std::env::var("HELIUS_API_KEY").ok();
        Self::with_mock_store(inner, api_key.as_deref())
    }

    /// Backwards-compatible constructor (creates its own internal mock store).
    /// Prefer `helius_with_mock_store` in tests.
    pub fn helius() -> Self {
        Self::helius_with_mock_store(Arc::new(MockNoteStore::new(16)))
    }
}

#[async_trait]
impl NoteCommitmentStore for LightIndexer {
    async fn root(&self) -> Result<Anchor, StoreError> {
        // Scaffold: delegate to mock
        self.inner.root().await
    }

    async fn exists(&self, commitment: Commitment) -> Result<bool, StoreError> {
        // Scaffold: delegate to mock
        self.inner.exists(commitment).await
    }

    async fn get_witness(&self, commitment: Commitment) -> Result<MembershipWitness, StoreError> {
        // Scaffold: delegate to mock
        // Future: Return LightValidityProof instead of MerklePath
        self.inner.get_witness(commitment).await
    }

    async fn get_witnesses(
        &self,
        commitments: &[Commitment],
    ) -> Result<Vec<MembershipWitness>, StoreError> {
        // Scaffold: delegate to mock
        // Future: Batch into single validity proof via Helius
        self.inner.get_witnesses(commitments).await
    }
}

#[async_trait]
impl Indexer for LightIndexer {
    async fn scan_outputs_since(
        &self,
        since_tx: Option<&str>,
    ) -> Result<Vec<OutputCiphertext>, IndexerError> {
        // Scaffold: delegate to mock
        self.inner.scan_outputs_since(since_tx).await
    }

    async fn get_commitments_for_tx(&self, tx_sig: &str) -> Result<Vec<Commitment>, IndexerError> {
        // Scaffold: delegate to mock
        self.inner.get_commitments_for_tx(tx_sig).await
    }
}

/// Light Protocol specific features (future)
impl LightIndexer {
    /// Get compressed account by address
    ///
    /// Future: Will call Helius `getCompressedAccount` endpoint
    #[allow(dead_code)]
    pub async fn get_compressed_account(&self, _address: &[u8; 32]) -> Result<(), StoreError> {
        // TODO: Implement with Helius SDK
        unimplemented!("Light Protocol not yet implemented")
    }

    /// Get validity proof for multiple addresses
    ///
    /// Future: Will call Helius `getMultipleCompressedAccountProofs` endpoint
    #[allow(dead_code)]
    pub async fn get_validity_proof(&self, _addresses: &[[u8; 32]]) -> Result<(), StoreError> {
        // TODO: Implement with Helius SDK
        unimplemented!("Light Protocol not yet implemented")
    }
}

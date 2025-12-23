//! Solana chain backend
//!
//! This module provides the real Solana blockchain implementation for MASP.
//!
//! ## Usage
//!
//! Requires `solana-backend` feature:
//!
//! ```ignore
//! #[cfg(feature = "solana-backend")]
//! let chain = SolanaChain::surfpool(program_id, keypair)?;
//! ```
//!
//! If you don't need real Solana, use `MockChain` directly instead.

#[cfg(feature = "solana-backend")]
mod real_backend {
    use crate::traits::{
        Chain, ChainError, CiphertextPostingRequest, CiphertextPostingResult,
        InsertCommitmentResult, ShieldRequest, ShieldResult, TransferRequest, TransferResult,
        UnshieldRequest, UnshieldResult,
    };
    use crate::types::{Anchor, Commitment, Nullifier};
    use async_trait::async_trait;
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use std::str::FromStr;

    /// System Program ID (11111111111111111111111111111111)
    /// This is a protocol constant - never changes.
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
    /// # Note on Indexing
    ///
    /// This chain backend only submits transactions. It does NOT track commitments
    /// or nullifiers locally. For testing with mocks, use `MockChain` instead.
    ///
    /// In production, an external indexer (e.g., Helius) watches the ledger and
    /// provides the `Indexer` trait implementation for querying state.
    pub struct SolanaChain {
        rpc_client: RpcClient,
        program_id: Pubkey,
        payer: Keypair,
    }

    impl SolanaChain {
        /// Create a new SolanaChain for real Solana transactions.
        ///
        /// # Arguments
        /// * `rpc_url` - Solana RPC URL
        /// * `program_id` - MASP program ID
        /// * `payer` - Keypair for signing transactions
        pub fn new(rpc_url: &str, program_id: &str, payer: Keypair) -> Result<Self, ChainError> {
            let program_id = Pubkey::from_str(program_id)
                .map_err(|e| ChainError::Other(format!("Invalid program ID: {}", e)))?;

            let rpc_client = RpcClient::new(rpc_url.to_string());

            println!("🔗 SolanaChain: Real Solana backend");
            println!("   RPC URL: {}", rpc_url);
            println!("   Program: {}", program_id);
            println!("   Payer: {}", payer.pubkey());

            Ok(Self {
                rpc_client,
                program_id,
                payer,
            })
        }

        /// Create for Surfpool (localhost)
        pub fn surfpool(program_id: &str, payer: Keypair) -> Result<Self, ChainError> {
            Self::new("http://127.0.0.1:8899", program_id, payer)
        }

        /// Create for Devnet
        pub fn devnet(program_id: &str, payer: Keypair) -> Result<Self, ChainError> {
            Self::new("https://api.devnet.solana.com", program_id, payer)
        }

        /// Get the RPC URL
        pub fn rpc_url(&self) -> String {
            self.rpc_client.url()
        }

        /// Get the program ID
        pub fn program_id(&self) -> &Pubkey {
            &self.program_id
        }

        /// Initialize the MASP program state (call once per deployment)
        pub fn initialize(&self) -> Result<String, ChainError> {
            let (tree_state_pda, _) = derive_tree_state_pda(&self.program_id);

            let ix = Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new(tree_state_pda, false),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                ],
                data: vec![IX_INITIALIZE],
            };

            self.send_transaction(&[ix])
        }

        /// Create and populate a proof buffer
        fn create_proof_buffer(
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
                .map_err(|e| ChainError::Other(format!("Failed to get blockhash: {}", e)))?;

            let tx = Transaction::new_signed_with_payer(
                &[init_ix],
                Some(&self.payer.pubkey()),
                &[&self.payer, &buffer],
                blockhash,
            );

            self.rpc_client
                .send_and_confirm_transaction(&tx)
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

            self.send_transaction(&[upload_ix])?;

            Ok(buffer.pubkey())
        }

        fn send_transaction(&self, instructions: &[Instruction]) -> Result<String, ChainError> {
            let blockhash = self
                .rpc_client
                .get_latest_blockhash()
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

    #[async_trait]
    impl Chain for SolanaChain {
        async fn insert_commitment(
            &self,
            _commitment: Commitment,
        ) -> Result<InsertCommitmentResult, ChainError> {
            // Commitment insertion happens via shield/transfer instructions
            // The program updates the tree state atomically
            Err(ChainError::Other(
                "Direct insert_commitment not supported - use shield() instead".to_string(),
            ))
        }

        async fn insert_nullifier(&self, _nullifier: Nullifier) -> Result<String, ChainError> {
            // Nullifier insertion happens via transfer/unshield instructions
            // The program creates nullifier PDAs atomically
            Err(ChainError::Other(
                "Direct insert_nullifier not supported - use transfer()/unshield()".to_string(),
            ))
        }

        async fn get_current_anchor(&self) -> Result<Anchor, ChainError> {
            // TODO: Read TreeState account from on-chain
            Err(ChainError::Other(
                "get_current_anchor not yet implemented - use an Indexer".to_string(),
            ))
        }

        async fn is_valid_anchor(&self, _anchor: &Anchor) -> Result<bool, ChainError> {
            // TODO: Query TreeState account anchor history
            Err(ChainError::Other(
                "is_valid_anchor not yet implemented - use an Indexer".to_string(),
            ))
        }

        async fn is_nullifier_spent(&self, _nullifier: &Nullifier) -> Result<bool, ChainError> {
            // TODO: Check if nullifier PDA exists on-chain
            Err(ChainError::Other(
                "is_nullifier_spent not yet implemented - use an Indexer".to_string(),
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
            let (tree_state_pda, _) = derive_tree_state_pda(&self.program_id);

            // Convert commitment to bytes
            let commitment_bytes = Self::commitment_to_bytes(&request.commitment);

            // For mock proofs, the public inputs are commitment, asset_id, amount, ct_hash
            // TODO: proper asset_id from request.token_address
            let asset_id_bytes = {
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            };
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
            let proof_buffer =
                self.create_proof_buffer(CIRCUIT_SHIELD, &public_inputs, &request.shield_proof)?;

            // Build shield instruction data
            let mut data = vec![IX_SHIELD];
            data.extend_from_slice(&commitment_bytes);
            data.extend_from_slice(&asset_id_bytes);
            data.extend_from_slice(&request.amount.to_le_bytes()); // Amount as u64 LE
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

            let tx_sig = self.send_transaction(&[ix])?;

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
pub use real_backend::SolanaChain;

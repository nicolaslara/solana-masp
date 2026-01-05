//! Photon RPC client for Light Protocol indexer
//!
//! Photon is the indexer for Light Protocol's compressed accounts.
//! It provides:
//! - Compressed account lookups
//! - Merkle proofs for note spending
//! - Validity proofs for nullifier non-existence

use serde::Deserialize;

use super::pda::{derive_address, derive_nullifier_address_seed};

/// Photon RPC client
pub struct PhotonClient {
    url: String,
    client: reqwest::Client,
}

/// Compressed Groth16 proof from Light Protocol
#[derive(Debug, Clone)]
pub struct CompressedProof {
    /// Proof component A (32 bytes, compressed G1)
    pub a: [u8; 32],
    /// Proof component B (64 bytes, compressed G2)
    pub b: [u8; 64],
    /// Proof component C (32 bytes, compressed G1)
    pub c: [u8; 32],
}

/// Result of a validity proof request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityProofResult {
    /// The compressed proof
    pub compressed_proof: Option<CompressedProofResponse>,
    /// Address information (for extracting root indices)
    pub addresses: Option<Vec<AddressInfo>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressedProofResponse {
    pub a: String,
    pub b: String,
    pub c: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressInfo {
    pub address: Option<String>,
    pub root_index: Option<serde_json::Value>,
}

/// Batched validity proof result
#[derive(Debug, Clone)]
pub struct BatchedValidityProof {
    /// The compressed proof
    pub proof: CompressedProof,
    /// Number of nullifiers covered by this proof
    pub count: usize,
    /// Root indices for each nullifier in this batch
    pub root_indices: Vec<u16>,
}

// JSON-RPC response wrapper
#[derive(Debug, Deserialize)]
struct PhotonResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GetValidityProofResponse {
    value: Option<ValidityProofResult>,
}

/// Error type for Photon RPC operations
#[derive(Debug, thiserror::Error)]
pub enum PhotonError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Address derivation failed: {0}")]
    AddressDerivation(String),
}

impl PhotonClient {
    /// Create a new Photon client with a custom URL
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for Devnet (uses Helius Photon)
    pub fn devnet() -> Self {
        // Default Helius Photon endpoint for devnet
        // In production, you'd use an API key
        Self::new("https://devnet.helius-rpc.com/?api-key=")
    }

    /// Create a client for Mainnet (uses Helius Photon)
    pub fn mainnet() -> Self {
        Self::new("https://mainnet.helius-rpc.com/?api-key=")
    }

    /// Generic JSON-RPC call to Photon
    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, PhotonError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| PhotonError::Network(format!("Photon RPC request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(PhotonError::Network(format!(
                "Photon RPC HTTP {}: {}",
                status,
                text
            )));
        }

        let json: PhotonResponse<T> = response
            .json()
            .await
            .map_err(|e| PhotonError::InvalidResponse(format!("Failed to parse Photon response: {}", e)))?;

        if let Some(error) = json.error {
            return Err(PhotonError::Network(format!(
                "Photon RPC error: {:?}",
                error
            )));
        }

        json.result.ok_or_else(|| {
            PhotonError::InvalidResponse("Photon RPC missing result".to_string())
        })
    }

    /// Get validity proof for a derived address (nullifier non-existence)
    ///
    /// This proves that a nullifier has NOT been spent yet (the derived address
    /// does not exist in the address tree).
    pub async fn get_validity_proof(
        &self,
        derived_address: &[u8; 32],
        address_tree: &[u8; 32],
    ) -> Result<ValidityProofResult, PhotonError> {
        let params = serde_json::json!({
            "hashes": [],
            "newAddressesWithTrees": [{
                "address": bs58_encode(derived_address),
                "tree": bs58_encode(address_tree),
            }],
        });

        let result: GetValidityProofResponse = self
            .rpc_call("getValidityProofV2", params)
            .await?;

        result
            .value
            .ok_or_else(|| PhotonError::InvalidResponse("No validity proof returned".to_string()))
    }

    /// Get validity proof for a nullifier (non-existence check)
    ///
    /// This is the main entry point for checking if a nullifier can be spent.
    /// It derives the Light Protocol address from the nullifier and fetches
    /// the validity proof from Photon.
    ///
    /// # Arguments
    /// * `nullifier` - The 32-byte nullifier to check
    /// * `pool_pubkey` - The pool/program identifier for nullifier derivation
    /// * `address_tree` - The Light Protocol address tree
    ///
    /// # Returns
    /// A validity proof that can be submitted on-chain to prove the nullifier
    /// has not been spent.
    pub async fn get_nullifier_validity_proof(
        &self,
        nullifier: &[u8; 32],
        pool_pubkey: &[u8; 32],
        address_tree: &[u8; 32],
    ) -> Result<ValidityProofResult, PhotonError> {
        let seed = derive_nullifier_address_seed(nullifier, pool_pubkey);
        let derived_address = derive_address(&seed, address_tree)
            .map_err(|e| PhotonError::AddressDerivation(e.to_string()))?;

        self.get_validity_proof(&derived_address, address_tree).await
    }

    /// Get validity proofs for multiple nullifiers, batched in groups of 2.
    ///
    /// Photon has a limit of 2 addresses per validity proof request.
    /// For N nullifiers, this returns ceil(N/2) validity proofs.
    ///
    /// # Returns
    /// Vec of `BatchedValidityProof`, each covering 1-2 nullifiers
    pub async fn get_validity_proofs_batched(
        &self,
        nullifiers: &[[u8; 32]],
        pool_pubkey: &[u8; 32],
        address_tree: &[u8; 32],
    ) -> Result<Vec<BatchedValidityProof>, PhotonError> {
        if nullifiers.is_empty() {
            return Err(PhotonError::InvalidResponse("No nullifiers provided".to_string()));
        }

        // Photon limit: max 2 addresses per batch
        const BATCH_SIZE: usize = 2;
        let mut results = Vec::new();

        for chunk in nullifiers.chunks(BATCH_SIZE) {
            // Build addresses for this batch
            let mut new_addresses_with_trees = Vec::with_capacity(chunk.len());
            for nullifier in chunk {
                let seed = derive_nullifier_address_seed(nullifier, pool_pubkey);
                let derived_address = derive_address(&seed, address_tree)
                    .map_err(|e| PhotonError::AddressDerivation(e.to_string()))?;
                new_addresses_with_trees.push(serde_json::json!({
                    "address": bs58_encode(&derived_address),
                    "tree": bs58_encode(address_tree),
                }));
            }

            let params = serde_json::json!({
                "hashes": [],
                "newAddressesWithTrees": new_addresses_with_trees,
            });

            let result: GetValidityProofResponse = self
                .rpc_call("getValidityProofV2", params)
                .await?;

            let proof_result = result
                .value
                .ok_or_else(|| PhotonError::InvalidResponse("No validity proof returned".to_string()))?;

            // Parse the compressed proof
            let compressed = proof_result
                .compressed_proof
                .ok_or_else(|| PhotonError::InvalidResponse("No compressed proof in response".to_string()))?;

            let proof = parse_compressed_proof(&compressed)?;

            // Extract root indices from addresses
            let root_indices: Vec<u16> = proof_result
                .addresses
                .as_ref()
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|addr| {
                            addr.root_index.as_ref().and_then(|v| match v {
                                serde_json::Value::Number(n) => n.as_u64().map(|n| n as u16),
                                serde_json::Value::String(s) => s.parse().ok(),
                                _ => None,
                            })
                        })
                        .collect()
                })
                .unwrap_or_else(|| vec![0; chunk.len()]);

            results.push(BatchedValidityProof {
                proof,
                count: chunk.len(),
                root_indices,
            });
        }

        Ok(results)
    }
}

/// Base58 encode bytes (for Solana pubkey format)
fn bs58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Parse hex string to fixed-size byte array
fn parse_hex<const N: usize>(hex_str: &str) -> Result<[u8; N], PhotonError> {
    let hex_str = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex_str)
        .map_err(|e| PhotonError::InvalidResponse(format!("Invalid hex: {}", e)))?;
    
    if bytes.len() != N {
        return Err(PhotonError::InvalidResponse(format!(
            "Expected {} bytes, got {}",
            N,
            bytes.len()
        )));
    }

    let mut result = [0u8; N];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Parse CompressedProofResponse to CompressedProof
fn parse_compressed_proof(response: &CompressedProofResponse) -> Result<CompressedProof, PhotonError> {
    Ok(CompressedProof {
        a: parse_hex(&response.a)?,
        b: parse_hex(&response.b)?,
        c: parse_hex(&response.c)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bs58_encode() {
        let bytes = [0u8; 32];
        let encoded = bs58_encode(&bytes);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_parse_hex() {
        let result: Result<[u8; 4], _> = parse_hex("0x01020304");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [1, 2, 3, 4]);

        let result2: Result<[u8; 4], _> = parse_hex("01020304");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), [1, 2, 3, 4]);
    }
}

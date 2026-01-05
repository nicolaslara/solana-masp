//! Light Protocol integration for MASP
//!
//! This module provides client-side integration with Light Protocol:
//! - Photon RPC client for validity proofs
//! - Nullifier address derivation
//! - Merkle proof fetching
//!
//! ## Usage
//!
//! ```ignore
//! use masp_client::backends::light::PhotonClient;
//!
//! let client = PhotonClient::devnet();
//! let proof = client.get_nullifier_validity_proof(&nullifier, &merkle_tree, &address_tree).await?;
//! ```

mod photon;
mod pda;

pub use photon::{PhotonClient, ValidityProofResult, CompressedProof, BatchedValidityProof, PhotonError};
pub use pda::{derive_nullifier_address_seed, derive_address};

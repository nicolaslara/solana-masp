//! Out-of-Band (OOB) Communication for Payment Notifications
//!
//! When Alice pays Bob, she needs to tell him about the payment.
//! This can happen via:
//! - Direct message (Signal, email, etc.)
//! - Payment link/QR code
//! - Payment protocol (like BIP70)
//!
//! ## Two-Transaction Model (Ciphertext DA)
//!
//! Following the ciphertext data availability design:
//! - **Tx A** (ciphertext posting): Posts encrypted note data to the ledger
//! - **Tx B** (MASP state transition): The actual shielded transfer with proof
//!
//! ## What Gets Communicated
//!
//! The OOB message contains minimal data - just enough for Bob to find
//! and decrypt his note:
//!
//! ```text
//! OobPaymentNotification {
//!     tx_sig: "5K8Z...",           // Tx B: MASP state transition
//!     output_index: 0,              // Which output in Tx B
//!     ciphertext_tx_sig: "7Y3Q...", // Tx A: ciphertext posting (optional)
//!     // Optional: note plaintext if not using ciphertext scanning
//! }
//! ```
//!
//! Bob then:
//! 1. Fetches Tx B (MASP transaction) via RPC
//! 2. Fetches ciphertext from Tx A (or uses indexer lookup by ct_hash)
//! 3. Decrypts with his viewing key
//! 4. Verifies ct_hash binding: H(DOM_CIPHERTEXT, ciphertext) == proof's ct_hash
//! 5. Verifies the commitment exists on-chain
//!
//! ## Why This Design
//!
//! - **Minimal data**: tx_sig + output_index + optional ciphertext_tx_sig
//! - **Privacy**: No note details in OOB message if using encryption
//! - **Verifiable**: Bob verifies ct_hash binding via indexer/chain
//! - **Fallback**: If OOB fails, Bob can still scan all ciphertexts by ct_hash
//!
//! ## Trait Design
//!
//! The `OobChannel` trait abstracts the transport:
//! - `MockOobChannel` - In-memory for testing
//! - Future: `SignalOobChannel`, `HttpOobChannel`, etc.

use crate::encryption::EncryptedNote;
use crate::note::NotePlaintext;
use crate::types::{Commitment, Fr};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// OOB Message Types
// ============================================================================

/// Minimal payment notification (just enough to find the note)
///
/// ## Two-Transaction Model
///
/// - `tx_sig`: The MASP state transition (Tx B) containing the proof + public inputs
/// - `ciphertext_tx_sig`: The ciphertext posting (Tx A) containing encrypted note data
///
/// If `ciphertext_tx_sig` is None, the recipient can still find the ciphertext
/// by looking up `ct_hash` from Tx B's public inputs via the indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentNotification {
    /// Transaction signature for MASP state transition (Tx B)
    ///
    /// This is the main transaction containing the ZK proof and public inputs
    /// (commitment, nullifiers, ct_hashes, etc.)
    pub tx_sig: String,

    /// Output index within the transaction (0 = first output, 1 = change, etc.)
    pub output_index: u32,

    /// Optional: Transaction signature for ciphertext posting (Tx A)
    ///
    /// This is the separate transaction that posts encrypted note data for DA.
    /// If provided, the recipient can fetch ciphertext directly from Tx A.
    /// If not provided, the recipient uses the indexer's `get_ciphertext_by_hash()`
    /// with the ct_hash from Tx B's public inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_tx_sig: Option<String>,

    /// Optional: commitment for quick verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<[u8; 32]>,
}

/// Full payment details (when sender wants to share note plaintext directly)
///
/// Use this when:
/// - Recipient doesn't support ciphertext scanning
/// - For debugging/testing
/// - When privacy against transport is acceptable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    /// The payment notification
    pub notification: PaymentNotification,

    /// Note plaintext (optional - use ciphertext scanning if not provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_plaintext: Option<NotePlaintext>,

    /// Encrypted note (optional - for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_note: Option<Vec<u8>>,
}

impl PaymentNotification {
    /// Create a new payment notification (minimal, no ciphertext tx reference)
    pub fn new(tx_sig: String, output_index: u32) -> Self {
        Self {
            tx_sig,
            output_index,
            ciphertext_tx_sig: None,
            commitment: None,
        }
    }

    /// Create with commitment for quick verification
    pub fn with_commitment(tx_sig: String, output_index: u32, commitment: Commitment) -> Self {
        use crate::hash::field_to_bytes;
        Self {
            tx_sig,
            output_index,
            ciphertext_tx_sig: None,
            commitment: Some(field_to_bytes(&commitment)),
        }
    }

    /// Create with both Tx A (ciphertext) and Tx B (MASP) references
    ///
    /// # Arguments
    /// * `masp_tx_sig` - Transaction signature for MASP state transition (Tx B)
    /// * `ciphertext_tx_sig` - Transaction signature for ciphertext posting (Tx A)
    /// * `output_index` - Which output in the MASP transaction
    /// * `commitment` - The output commitment (optional, for quick verification)
    pub fn with_ciphertext_tx(
        masp_tx_sig: String,
        ciphertext_tx_sig: String,
        output_index: u32,
        commitment: Option<Commitment>,
    ) -> Self {
        use crate::hash::field_to_bytes;
        Self {
            tx_sig: masp_tx_sig,
            output_index,
            ciphertext_tx_sig: Some(ciphertext_tx_sig),
            commitment: commitment.map(|c| field_to_bytes(&c)),
        }
    }

    /// Get commitment as Fr (if provided)
    pub fn get_commitment(&self) -> Option<Fr> {
        self.commitment
            .map(|bytes| crate::hash::field_from_bytes(&bytes))
    }

    /// Check if this notification includes a ciphertext transaction reference
    pub fn has_ciphertext_tx(&self) -> bool {
        self.ciphertext_tx_sig.is_some()
    }
}

impl PaymentDetails {
    /// Create minimal details (just notification)
    pub fn minimal(notification: PaymentNotification) -> Self {
        Self {
            notification,
            note_plaintext: None,
            encrypted_note: None,
        }
    }

    /// Create with note plaintext (for OOB without encryption)
    pub fn with_plaintext(notification: PaymentNotification, plaintext: NotePlaintext) -> Self {
        Self {
            notification,
            note_plaintext: Some(plaintext),
            encrypted_note: None,
        }
    }

    /// Create with encrypted note (for verification)
    pub fn with_encrypted(notification: PaymentNotification, encrypted: &EncryptedNote) -> Self {
        Self {
            notification,
            note_plaintext: None,
            encrypted_note: Some(encrypted.to_bytes()),
        }
    }
}

// ============================================================================
// OOB Channel Errors
// ============================================================================

/// Errors from OOB operations
#[derive(Debug, Error)]
pub enum OobError {
    #[error("Failed to send notification: {0}")]
    SendFailed(String),

    #[error("Failed to receive notification: {0}")]
    ReceiveFailed(String),

    #[error("Channel not connected")]
    NotConnected,

    #[error("Invalid notification format")]
    InvalidFormat,

    #[error("Notification queue empty")]
    QueueEmpty,
}

// ============================================================================
// OOB Channel Trait
// ============================================================================

/// Trait for out-of-band payment notification channels
///
/// Implementations provide the transport mechanism:
/// - `MockOobChannel` - In-memory queue for testing
/// - Future: Signal, HTTP webhook, QR code, etc.
#[async_trait]
pub trait OobChannel: Send + Sync {
    /// Send a payment notification to a recipient
    ///
    /// # Arguments
    /// * `recipient_id` - Identifier for the recipient (address, pubkey, etc.)
    /// * `notification` - The payment notification to send
    async fn send(
        &self,
        recipient_id: &str,
        notification: PaymentNotification,
    ) -> Result<(), OobError>;

    /// Send full payment details to a recipient
    async fn send_details(
        &self,
        recipient_id: &str,
        details: PaymentDetails,
    ) -> Result<(), OobError>;

    /// Receive pending notifications for this recipient
    ///
    /// Returns all notifications received since last call.
    async fn receive(&self, recipient_id: &str) -> Result<Vec<PaymentNotification>, OobError>;

    /// Receive full payment details
    async fn receive_details(&self, recipient_id: &str) -> Result<Vec<PaymentDetails>, OobError>;

    /// Get channel name (for logging/debugging)
    fn channel_name(&self) -> &'static str;
}

// ============================================================================
// Mock OOB Channel (for testing)
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;

/// Mock OOB channel using in-memory queues
///
/// Each recipient has a queue of pending notifications.
pub struct MockOobChannel {
    notifications: RwLock<HashMap<String, Vec<PaymentNotification>>>,
    details: RwLock<HashMap<String, Vec<PaymentDetails>>>,
}

impl MockOobChannel {
    pub fn new() -> Self {
        Self {
            notifications: RwLock::new(HashMap::new()),
            details: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MockOobChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OobChannel for MockOobChannel {
    async fn send(
        &self,
        recipient_id: &str,
        notification: PaymentNotification,
    ) -> Result<(), OobError> {
        let mut notifications = self.notifications.write().unwrap();
        notifications
            .entry(recipient_id.to_string())
            .or_default()
            .push(notification);
        Ok(())
    }

    async fn send_details(
        &self,
        recipient_id: &str,
        details: PaymentDetails,
    ) -> Result<(), OobError> {
        let mut all_details = self.details.write().unwrap();
        all_details
            .entry(recipient_id.to_string())
            .or_default()
            .push(details);
        Ok(())
    }

    async fn receive(&self, recipient_id: &str) -> Result<Vec<PaymentNotification>, OobError> {
        let mut notifications = self.notifications.write().unwrap();
        Ok(notifications.remove(recipient_id).unwrap_or_default())
    }

    async fn receive_details(&self, recipient_id: &str) -> Result<Vec<PaymentDetails>, OobError> {
        let mut all_details = self.details.write().unwrap();
        Ok(all_details.remove(recipient_id).unwrap_or_default())
    }

    fn channel_name(&self) -> &'static str {
        "MockOobChannel"
    }
}

// ============================================================================
// Helper: Payment Flow with OOB
// ============================================================================

/// Helper for building OOB notifications from transfer results
///
/// Supports both single-tx (legacy) and two-tx (ciphertext DA) models.
pub struct OobNotificationBuilder;

impl OobNotificationBuilder {
    /// Create notification for a simple transfer output (single-tx model)
    ///
    /// Use this when ciphertext is embedded in the same transaction as the proof.
    pub fn for_output(
        tx_sig: &str,
        output_index: u32,
        commitment: Commitment,
    ) -> PaymentNotification {
        PaymentNotification::with_commitment(tx_sig.to_string(), output_index, commitment)
    }

    /// Create notification for change output (back to sender)
    pub fn for_change(tx_sig: &str, commitment: Commitment) -> PaymentNotification {
        // Change is typically output index 1
        PaymentNotification::with_commitment(tx_sig.to_string(), 1, commitment)
    }

    /// Create notification with ciphertext DA (two-tx model)
    ///
    /// Use this when ciphertext is posted in a separate transaction (Tx A)
    /// from the MASP state transition (Tx B).
    ///
    /// # Arguments
    /// * `masp_tx_sig` - Transaction signature for MASP state transition (Tx B)
    /// * `ciphertext_tx_sig` - Transaction signature for ciphertext posting (Tx A)
    /// * `output_index` - Which output in the MASP transaction
    /// * `commitment` - The output commitment
    pub fn for_output_with_ciphertext_tx(
        masp_tx_sig: &str,
        ciphertext_tx_sig: &str,
        output_index: u32,
        commitment: Commitment,
    ) -> PaymentNotification {
        PaymentNotification::with_ciphertext_tx(
            masp_tx_sig.to_string(),
            ciphertext_tx_sig.to_string(),
            output_index,
            Some(commitment),
        )
    }

    /// Create notification for change with ciphertext DA (two-tx model)
    pub fn for_change_with_ciphertext_tx(
        masp_tx_sig: &str,
        ciphertext_tx_sig: &str,
        commitment: Commitment,
    ) -> PaymentNotification {
        PaymentNotification::with_ciphertext_tx(
            masp_tx_sig.to_string(),
            ciphertext_tx_sig.to_string(),
            1, // Change is typically output index 1
            Some(commitment),
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_oob_send_receive() {
        let channel = MockOobChannel::new();

        let notification = PaymentNotification::new("tx_123".to_string(), 0);

        // Send to Bob
        channel.send("bob", notification.clone()).await.unwrap();

        // Bob receives
        let received = channel.receive("bob").await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].tx_sig, "tx_123");

        // Queue is now empty
        let received = channel.receive("bob").await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_mock_oob_multiple_recipients() {
        let channel = MockOobChannel::new();

        channel
            .send("bob", PaymentNotification::new("tx_1".to_string(), 0))
            .await
            .unwrap();
        channel
            .send("alice", PaymentNotification::new("tx_2".to_string(), 0))
            .await
            .unwrap();
        channel
            .send("bob", PaymentNotification::new("tx_3".to_string(), 1))
            .await
            .unwrap();

        let bob_received = channel.receive("bob").await.unwrap();
        assert_eq!(bob_received.len(), 2);

        let alice_received = channel.receive("alice").await.unwrap();
        assert_eq!(alice_received.len(), 1);
    }

    #[tokio::test]
    async fn test_payment_details() {
        let channel = MockOobChannel::new();

        let notification = PaymentNotification::new("tx_123".to_string(), 0);
        let details = PaymentDetails::minimal(notification);

        channel.send_details("bob", details).await.unwrap();

        let received = channel.receive_details("bob").await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].notification.tx_sig, "tx_123");
    }

    #[test]
    fn test_notification_serialization() {
        let notification = PaymentNotification::new("5K8Z...".to_string(), 0);
        let json = serde_json::to_string(&notification).unwrap();
        let recovered: PaymentNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.tx_sig, "5K8Z...");
    }
}

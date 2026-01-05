//! Note encryption and decryption
//!
//! This module provides encryption for note plaintexts using ECIES
//! (Elliptic Curve Integrated Encryption Scheme) so they can be stored
//! in transaction data (ledger space) without revealing contents.
//!
//! ## Storage Location
//!
//! Encrypted notes are stored in Solana transaction instruction data:
//! - NOT in PDAs (would be expensive and unnecessary)
//! - In the transaction's instruction data field
//! - Retrievable via `getTransaction` RPC (Helius, standard Solana RPC)
//!
//! ## Encryption Scheme (ECIES)
//!
//! ```text
//! Encryption (sender knows recipient's pk_d and g_d):
//! 1. Generate ephemeral keypair: esk (random), epk = esk * g_d
//! 2. ECDH: shared_secret = esk * pk_d
//! 3. KDF: symmetric_key = Poseidon(DOM_CIPHERTEXT, ss.x, ss.y, epk_x)
//! 4. Encrypt: ChaCha20-Poly1305(symmetric_key, nonce, plaintext)
//! 5. Output: (epk, nonce, ciphertext, tag)
//!
//! Decryption (recipient has ivk):
//! 1. Compute: shared_secret = ivk * epk
//!    (Since ivk * epk = ivk * esk * g_d = esk * ivk * g_d = esk * pk_d)
//! 2. Same KDF to derive symmetric_key
//! 3. Decrypt with ChaCha20-Poly1305
//! ```
//!
//! ## Trait-Based Design
//!
//! The `NoteEncryption` trait allows swapping encryption algorithms:
//! - `ChaChaPolyEncryption` - Production (ChaCha20-Poly1305)
//! - `MockEncryption` - Testing (simple XOR, fast but insecure)

use crate::domain::{DomainTag, DomainTagExt};
use crate::hash::{field_from_bytes, field_to_bytes, poseidon_hash};
use crate::keys::{DiversifiedAddress, FullViewingKey};
use crate::note::{Note, NotePlaintext};
use crate::types::Fr;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_grumpkin::{
    Affine as GrumpkinAffine, Fr as GrumpkinScalar, Projective as GrumpkinProjective,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;
use thiserror::Error;

// ============================================================================
// RNG trait for object-safe encryption
// ============================================================================

/// Crypto-secure RNG trait used by note encryption.
///
/// We use a dedicated trait because Rust does not allow trait objects like
/// `dyn RngCore + CryptoRng` directly (only auto-traits can be combined in
/// trait objects).
pub trait CryptoRngCore: RngCore + CryptoRng {}
impl<T: RngCore + CryptoRng + ?Sized> CryptoRngCore for T {}

// ============================================================================
// Constants
// ============================================================================

/// Size of note plaintext
/// asset_id(32) + amount(8) + recipient(32) + diversifier_index(8) + nullifier_nonce(32) + note_randomness(32) = 144 bytes
pub const PLAINTEXT_SIZE: usize = 144;

/// Ephemeral public key size (x and y coordinates)
pub const EPK_SIZE: usize = 64;

/// Nonce size for ChaCha20-Poly1305
pub const NONCE_SIZE: usize = 12;

/// Diversifier index size (u64, little-endian) stored alongside ciphertext.
///
/// This is public metadata that lets wallets avoid scanning many indices during trial decryption.
pub const DIVERSIFIER_INDEX_SIZE: usize = 8;

/// Authentication tag size for ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16;

/// Total encrypted note size
pub const ENCRYPTED_NOTE_SIZE: usize =
    DIVERSIFIER_INDEX_SIZE + EPK_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + TAG_SIZE;

// ============================================================================
// Errors
// ============================================================================

/// Errors from encryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    #[error("Invalid ciphertext length")]
    InvalidLength,

    #[error("Invalid ephemeral key")]
    InvalidEphemeralKey,

    #[error("Note not for this recipient")]
    WrongRecipient,

    #[error("Serialization error")]
    SerializationError,

    #[error("Commitment mismatch: decrypted note doesn't match expected commitment")]
    CommitmentMismatch,
}

// ============================================================================
// Encryption Trait
// ============================================================================

/// Trait for note encryption algorithms
///
/// Allows swapping encryption implementations:
/// - Production: ECIES with ChaCha20-Poly1305
/// - Testing: Simplified mock encryption
///
/// ## AAD Binding
///
/// The commitment is included as Additional Authenticated Data (AAD)
/// to prevent ciphertext swapping attacks. This binds the ciphertext
/// to the specific note commitment.
pub trait NoteEncryption: Send + Sync {
    /// Encrypt a note for a recipient (C_enc only)
    ///
    /// The commitment is computed from the note and used as AAD
    /// to bind the ciphertext to this specific note.
    fn encrypt(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
    ) -> EncryptedNote;

    /// Encrypt a note with both C_enc (for recipient) and C_out (for sender)
    ///
    /// This is the recommended method for production use as it enables
    /// sender to recover what they sent.
    fn encrypt_with_outgoing(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
        sender_ovk: Fr,
    ) -> OutputCiphertexts;

    /// Try to decrypt a note with a viewing key at a specific diversifier
    ///
    /// If `expected_commitment` is provided, verifies the decrypted note
    /// matches. This is optional because during trial decryption we don't
    /// always know the commitment beforehand.
    fn try_decrypt(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
    ) -> Result<Note, EncryptionError>;

    /// Try to decrypt with commitment verification (for known commitments)
    fn try_decrypt_with_commitment(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
        expected_commitment: Fr,
    ) -> Result<Note, EncryptionError> {
        let note = self.try_decrypt(encrypted, fvk, diversifier_index)?;
        if note.commitment() != expected_commitment {
            return Err(EncryptionError::CommitmentMismatch);
        }
        Ok(note)
    }

    /// Try to decrypt C_out to recover sent note
    fn try_decrypt_outgoing(
        &self,
        c_out: &OutgoingCiphertext,
        epk_bytes: &[u8; EPK_SIZE],
        commitment: Fr,
        ovk: Fr,
    ) -> Result<OutgoingPlaintext, EncryptionError>;

    /// Get the encryption scheme name
    fn scheme_name(&self) -> &'static str;
}

// ============================================================================
// Blanket impls
// ============================================================================

// Allow passing `&E` anywhere an `E: NoteEncryption` is expected.
// This is particularly useful for wiring tests/config where encryption may be
// stored in a struct and borrowed.
impl<T: NoteEncryption + ?Sized> NoteEncryption for &T {
    fn encrypt(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
    ) -> EncryptedNote {
        (**self).encrypt(rng, note, recipient_addr)
    }

    fn encrypt_with_outgoing(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
        sender_ovk: Fr,
    ) -> OutputCiphertexts {
        (**self).encrypt_with_outgoing(rng, note, recipient_addr, sender_ovk)
    }

    fn try_decrypt(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
    ) -> Result<Note, EncryptionError> {
        (**self).try_decrypt(encrypted, fvk, diversifier_index)
    }

    fn try_decrypt_with_commitment(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
        expected_commitment: Fr,
    ) -> Result<Note, EncryptionError> {
        (**self).try_decrypt_with_commitment(encrypted, fvk, diversifier_index, expected_commitment)
    }

    fn try_decrypt_outgoing(
        &self,
        c_out: &OutgoingCiphertext,
        epk_bytes: &[u8; EPK_SIZE],
        commitment: Fr,
        ovk: Fr,
    ) -> Result<OutgoingPlaintext, EncryptionError> {
        (**self).try_decrypt_outgoing(c_out, epk_bytes, commitment, ovk)
    }

    fn scheme_name(&self) -> &'static str {
        (**self).scheme_name()
    }
}

// Allow passing `Arc<E>` anywhere an `E: NoteEncryption` is expected.
impl<T: NoteEncryption + ?Sized> NoteEncryption for Arc<T> {
    fn encrypt(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
    ) -> EncryptedNote {
        (**self).encrypt(rng, note, recipient_addr)
    }

    fn encrypt_with_outgoing(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
        sender_ovk: Fr,
    ) -> OutputCiphertexts {
        (**self).encrypt_with_outgoing(rng, note, recipient_addr, sender_ovk)
    }

    fn try_decrypt(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
    ) -> Result<Note, EncryptionError> {
        (**self).try_decrypt(encrypted, fvk, diversifier_index)
    }

    fn try_decrypt_with_commitment(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
        expected_commitment: Fr,
    ) -> Result<Note, EncryptionError> {
        (**self).try_decrypt_with_commitment(encrypted, fvk, diversifier_index, expected_commitment)
    }

    fn try_decrypt_outgoing(
        &self,
        c_out: &OutgoingCiphertext,
        epk_bytes: &[u8; EPK_SIZE],
        commitment: Fr,
        ovk: Fr,
    ) -> Result<OutgoingPlaintext, EncryptionError> {
        (**self).try_decrypt_outgoing(c_out, epk_bytes, commitment, ovk)
    }

    fn scheme_name(&self) -> &'static str {
        (**self).scheme_name()
    }
}

// ============================================================================
// Encrypted Note Structure
// ============================================================================

/// Encrypted note for storage in transaction data
///
/// This is what gets stored in Solana instruction data and retrieved
/// via Helius/RPC `getTransaction` calls.
#[derive(Debug, Clone)]
pub struct EncryptedNote {
    /// Diversifier index used to derive the recipient address for this ciphertext.
    ///
    /// This is public metadata (not secret) and should be included in the transaction output
    /// alongside the ciphertext, so wallets do not need to scan many indices to find the right one.
    pub diversifier_index: u64,

    /// Ephemeral public key (epk = esk * g_d)
    /// Stored as (x, y) coordinates, 32 bytes each
    pub ephemeral_key: [u8; EPK_SIZE],

    /// Nonce for authenticated encryption
    pub nonce: [u8; NONCE_SIZE],

    /// Encrypted note plaintext with authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedNote {
    /// Serialize for storage in transaction instruction data
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCRYPTED_NOTE_SIZE);
        bytes.extend_from_slice(&self.diversifier_index.to_le_bytes());
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from transaction instruction data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < DIVERSIFIER_INDEX_SIZE + EPK_SIZE + NONCE_SIZE {
            return Err(EncryptionError::InvalidLength);
        }

        let mut di = [0u8; DIVERSIFIER_INDEX_SIZE];
        di.copy_from_slice(&bytes[..DIVERSIFIER_INDEX_SIZE]);
        let diversifier_index = u64::from_le_bytes(di);

        let mut ephemeral_key = [0u8; EPK_SIZE];
        ephemeral_key
            .copy_from_slice(&bytes[DIVERSIFIER_INDEX_SIZE..DIVERSIFIER_INDEX_SIZE + EPK_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(
            &bytes
                [DIVERSIFIER_INDEX_SIZE + EPK_SIZE..DIVERSIFIER_INDEX_SIZE + EPK_SIZE + NONCE_SIZE],
        );

        let ciphertext = bytes[DIVERSIFIER_INDEX_SIZE + EPK_SIZE + NONCE_SIZE..].to_vec();

        Ok(Self {
            diversifier_index,
            ephemeral_key,
            nonce,
            ciphertext,
        })
    }
}

// ============================================================================
// Outgoing Ciphertext (C_out) - For Sender Recovery
// ============================================================================

/// Size of C_out plaintext
///
/// V2 (current): esk(32) + note_plaintext(144) = 176 bytes
///
/// Note: older versions (V1) also included `pk_d.x` explicitly, but that is redundant because
/// the note plaintext already contains `recipient = pk_d.x`. We keep backward-compatible
/// decoding for historical ciphertexts without adding an explicit version byte.
pub const C_OUT_PLAINTEXT_SIZE: usize = 32 + PLAINTEXT_SIZE;

/// Historical V1 size: esk(32) + pk_d_x(32) + note_plaintext(144) = 208 bytes
pub const C_OUT_PLAINTEXT_SIZE_V1: usize = 32 + 32 + PLAINTEXT_SIZE;

/// Total C_out size (nonce + ciphertext + tag)
pub const C_OUT_SIZE: usize = NONCE_SIZE + C_OUT_PLAINTEXT_SIZE + TAG_SIZE;

/// Outgoing ciphertext - allows sender to recover what they sent
///
/// ## Purpose
/// When Alice sends a note to Bob, she encrypts C_out with her outgoing
/// viewing key (ovk). Later, Alice can decrypt C_out to see:
/// - What note she sent
/// - Who she sent it to (pk_d)
/// - The ephemeral secret (esk) used for the encryption
///
/// ## Encryption Scheme
/// ```text
/// ock = Poseidon(DOM_OCK, ovk, epk.x, commitment)
/// C_out = ChaCha20Poly1305(ock, nonce, esk || pk_d.x || note_plaintext)
/// ```
///
/// ## Why Include esk?
/// With esk, Alice can recompute the shared secret:
/// `ss = esk * pk_d`
/// This allows her to decrypt C_enc too, verifying consistency.
#[derive(Debug, Clone)]
pub struct OutgoingCiphertext {
    /// Nonce for authenticated encryption
    pub nonce: [u8; NONCE_SIZE],

    /// Encrypted payload: esk || pk_d.x || note_plaintext
    pub ciphertext: Vec<u8>,
}

/// Decrypted C_out contents
#[derive(Debug, Clone)]
pub struct OutgoingPlaintext {
    /// Ephemeral secret key used for C_enc
    pub esk: Fr,
    /// Recipient's pk_d.x (redundant with `note.recipient`, provided for convenience)
    pub recipient_pk_d_x: Fr,
    /// The note that was sent
    pub note: Note,
}

impl OutgoingCiphertext {
    /// Serialize for storage in transaction instruction data
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(C_OUT_SIZE);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from transaction instruction data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < NONCE_SIZE {
            return Err(EncryptionError::InvalidLength);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
        let ciphertext = bytes[NONCE_SIZE..].to_vec();

        Ok(Self { nonce, ciphertext })
    }
}

/// Full output ciphertexts for a transaction output
///
/// Contains both:
/// - C_enc: For recipient (encrypted with recipient's pk)
/// - C_out: For sender (encrypted with sender's ovk)
#[derive(Debug, Clone)]
pub struct OutputCiphertexts {
    /// For recipient - encrypted with ECDH shared secret
    pub c_enc: EncryptedNote,

    /// For sender - encrypted with ovk-derived key
    pub c_out: OutgoingCiphertext,

    /// The commitment this output corresponds to
    pub commitment: Fr,
}

impl OutputCiphertexts {
    /// Serialize both ciphertexts
    pub fn to_bytes(&self) -> Vec<u8> {
        let c_enc_bytes = self.c_enc.to_bytes();
        let c_out_bytes = self.c_out.to_bytes();
        let commitment_bytes = field_to_bytes(&self.commitment);

        let mut bytes = Vec::with_capacity(c_enc_bytes.len() + c_out_bytes.len() + 32);
        bytes.extend_from_slice(&commitment_bytes);
        bytes.extend_from_slice(&c_enc_bytes);
        bytes.extend_from_slice(&c_out_bytes);
        bytes
    }

    /// Deserialize both ciphertexts
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < 32 + ENCRYPTED_NOTE_SIZE + NONCE_SIZE {
            return Err(EncryptionError::InvalidLength);
        }

        let commitment = field_from_bytes(&bytes[..32].try_into().unwrap());
        let c_enc = EncryptedNote::from_bytes(&bytes[32..32 + ENCRYPTED_NOTE_SIZE])?;
        let c_out = OutgoingCiphertext::from_bytes(&bytes[32 + ENCRYPTED_NOTE_SIZE..])?;

        Ok(Self {
            c_enc,
            c_out,
            commitment,
        })
    }
}

// ============================================================================
// C_out Encryption/Decryption Functions
// ============================================================================

/// Derive the outgoing ciphertext key (ock)
///
/// `ock = Poseidon(DOM_OCK, ovk, epk_x, commitment)`
///
/// This key is deterministic from:
/// - ovk: sender's outgoing viewing key (derived from seed)
/// - epk_x: ephemeral public key x-coordinate (from transaction)
/// - commitment: note commitment (from transaction)
fn derive_outgoing_key(ovk: Fr, epk_x: Fr, commitment: Fr) -> [u8; 32] {
    let key_field = poseidon_hash(&[
        DomainTag::OutgoingCiphertextKey.to_field(),
        ovk,
        epk_x,
        commitment,
    ]);
    field_to_bytes(&key_field)
}

/// Encrypt C_out for sender recovery
///
/// # Arguments
/// * `ovk` - Sender's outgoing viewing key
/// * `esk` - Ephemeral secret key used for C_enc
/// * `epk` - Ephemeral public key (for key derivation)
/// * `note` - The note being sent
/// * `commitment` - Note commitment (for key derivation)
/// * `rng` - Random number generator for nonce
pub fn encrypt_outgoing<R: Rng + ?Sized>(
    rng: &mut R,
    ovk: Fr,
    esk: Fr,
    epk_bytes: &[u8; EPK_SIZE],
    note: &Note,
    commitment: Fr,
) -> OutgoingCiphertext {
    // 1. Derive outgoing ciphertext key
    let epk_x = field_from_bytes(&epk_bytes[..32].try_into().unwrap());
    let ock = derive_outgoing_key(ovk, epk_x, commitment);

    // 2. Build plaintext: esk || note_plaintext
    // Note: `pk_d.x` is already contained in `note_plaintext.recipient`.
    let mut plaintext = Vec::with_capacity(C_OUT_PLAINTEXT_SIZE);
    plaintext.extend_from_slice(&field_to_bytes(&esk));
    plaintext.extend_from_slice(&serialize_note(note));

    // 3. Generate nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce_bytes);

    // 4. Encrypt with ChaCha20-Poly1305
    // AAD = commitment (binds C_out to this specific note)
    let aad = field_to_bytes(&commitment);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&ock));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .expect("encryption should not fail");

    OutgoingCiphertext {
        nonce: nonce_bytes,
        ciphertext,
    }
}

/// Decrypt C_out to recover sent note
///
/// # Arguments
/// * `ovk` - Sender's outgoing viewing key
/// * `c_out` - The outgoing ciphertext
/// * `epk_bytes` - Ephemeral public key from transaction
/// * `commitment` - Note commitment from transaction
///
/// # Returns
/// The decrypted outgoing plaintext, or error if decryption fails.
pub fn decrypt_outgoing(
    ovk: Fr,
    c_out: &OutgoingCiphertext,
    epk_bytes: &[u8; EPK_SIZE],
    commitment: Fr,
) -> Result<OutgoingPlaintext, EncryptionError> {
    // 1. Derive outgoing ciphertext key
    let epk_x = field_from_bytes(&epk_bytes[..32].try_into().unwrap());
    let ock = derive_outgoing_key(ovk, epk_x, commitment);

    // 2. Decrypt with ChaCha20-Poly1305
    let aad = field_to_bytes(&commitment);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&ock));
    let nonce = Nonce::from_slice(&c_out.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &c_out.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // 3. Parse plaintext (backward-compatible):
    // - V2 (current): esk(32) || note_plaintext(144)
    // - V1 (legacy):  esk(32) || pk_d.x(32) || note_plaintext(144)
    if plaintext.len() == C_OUT_PLAINTEXT_SIZE {
        let esk = field_from_bytes(&plaintext[..32].try_into().unwrap());
        let note = deserialize_note(&plaintext[32..])?;
        let recipient_pk_d_x = note.recipient;

        return Ok(OutgoingPlaintext {
            esk,
            recipient_pk_d_x,
            note,
        });
    }

    if plaintext.len() == C_OUT_PLAINTEXT_SIZE_V1 {
        let esk = field_from_bytes(&plaintext[..32].try_into().unwrap());
        let recipient_pk_d_x = field_from_bytes(&plaintext[32..64].try_into().unwrap());
        let note = deserialize_note(&plaintext[64..])?;

        return Ok(OutgoingPlaintext {
            esk,
            recipient_pk_d_x,
            note,
        });
    }

    Err(EncryptionError::InvalidLength)
}

/// Try to decrypt C_out (for sender scanning)
///
/// Returns None if this C_out wasn't encrypted by this sender.
pub fn try_decrypt_outgoing(
    ovk: Fr,
    c_out: &OutgoingCiphertext,
    epk_bytes: &[u8; EPK_SIZE],
    commitment: Fr,
) -> Option<OutgoingPlaintext> {
    decrypt_outgoing(ovk, c_out, epk_bytes, commitment).ok()
}

// ============================================================================
// ChaCha20-Poly1305 ECIES Implementation (Production)
// ============================================================================

/// Production encryption using ECIES with ChaCha20-Poly1305
///
/// This is the recommended encryption for production use:
/// - ECDH key exchange on Grumpkin curve (Noir's embedded curve for BN254)
/// - ChaCha20-Poly1305 authenticated encryption
/// - Poseidon-based KDF for key derivation
pub struct ChaChaPolyEncryption;

impl ChaChaPolyEncryption {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChaChaPolyEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteEncryption for ChaChaPolyEncryption {
    fn encrypt(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
    ) -> EncryptedNote {
        // 1. Generate ephemeral secret key
        let esk = Fr::rand(rng);

        // 2. Compute ephemeral public key: epk = esk * g_d
        let epk =
            (GrumpkinProjective::from(recipient_addr.g_d) * to_grumpkin_scalar(esk)).into_affine();

        // 3. ECDH: shared_secret = esk * pk_d
        let shared_secret =
            (GrumpkinProjective::from(recipient_addr.pk_d) * to_grumpkin_scalar(esk)).into_affine();

        // 4. Serialize ephemeral public key
        let ephemeral_key = serialize_point(&epk);

        // 5. KDF: derive 32-byte symmetric key
        // Includes epk in derivation to bind key to this specific encryption
        let symmetric_key = derive_symmetric_key(&shared_secret, &ephemeral_key);

        // 6. Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        // 7. Build AAD: (diversifier_index || ephemeral_key)
        // Note: Zcash uses commitment as AAD, but we use epk because:
        // - epk is always known during decryption (it's in the ciphertext)
        // - We verify commitment after decryption
        // - This allows trial decryption without knowing commitment
        let mut aad = Vec::with_capacity(DIVERSIFIER_INDEX_SIZE + EPK_SIZE);
        aad.extend_from_slice(&recipient_addr.diversifier_index.to_le_bytes());
        aad.extend_from_slice(&ephemeral_key);

        // 8. Encrypt with ChaCha20-Poly1305 using AAD
        let plaintext = serialize_note(note);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption should not fail");

        EncryptedNote {
            diversifier_index: recipient_addr.diversifier_index,
            ephemeral_key,
            nonce: nonce_bytes,
            ciphertext,
        }
    }

    fn try_decrypt(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
    ) -> Result<Note, EncryptionError> {
        // Quick reject: if the ciphertext declares a different diversifier, don't bother.
        if encrypted.diversifier_index != diversifier_index {
            return Err(EncryptionError::WrongRecipient);
        }
        let addr = fvk.diversified_address(diversifier_index);
        let ivk = fvk.ivk();

        // Deserialize ephemeral public key
        let epk = deserialize_point(&encrypted.ephemeral_key)?;

        // ECDH: shared_secret = ivk * epk
        let shared_secret = (GrumpkinProjective::from(epk) * to_grumpkin_scalar(ivk)).into_affine();

        // KDF: derive same symmetric key
        let symmetric_key = derive_symmetric_key(&shared_secret, &encrypted.ephemeral_key);

        // AAD is (diversifier_index || ephemeral_key)
        let mut aad = Vec::with_capacity(DIVERSIFIER_INDEX_SIZE + EPK_SIZE);
        aad.extend_from_slice(&encrypted.diversifier_index.to_le_bytes());
        aad.extend_from_slice(&encrypted.ephemeral_key);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &encrypted.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        // Deserialize note
        let note = deserialize_note(&plaintext)?;

        // Verify note's committed diversifier matches the ciphertext/attempted diversifier.
        if note.diversifier_index != diversifier_index {
            return Err(EncryptionError::WrongRecipient);
        }

        // Verify recipient matches
        if note.recipient != addr.to_field() {
            return Err(EncryptionError::WrongRecipient);
        }

        Ok(note)
    }

    /// Decrypt with known commitment verification
    ///
    /// Same as try_decrypt but also verifies the commitment matches.
    /// Use this when you have the commitment from the chain.
    fn try_decrypt_with_commitment(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
        expected_commitment: Fr,
    ) -> Result<Note, EncryptionError> {
        let note = self.try_decrypt(encrypted, fvk, diversifier_index)?;

        // Verify commitment matches
        if note.commitment() != expected_commitment {
            return Err(EncryptionError::CommitmentMismatch);
        }

        Ok(note)
    }

    fn encrypt_with_outgoing(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
        sender_ovk: Fr,
    ) -> OutputCiphertexts {
        // 1. Generate ephemeral secret key
        let esk = Fr::rand(rng);

        // 2. Compute ephemeral public key: epk = esk * g_d
        let epk =
            (GrumpkinProjective::from(recipient_addr.g_d) * to_grumpkin_scalar(esk)).into_affine();

        // 3. ECDH: shared_secret = esk * pk_d
        let shared_secret =
            (GrumpkinProjective::from(recipient_addr.pk_d) * to_grumpkin_scalar(esk)).into_affine();

        // 4. Serialize ephemeral public key
        let ephemeral_key = serialize_point(&epk);

        // 5. KDF: derive 32-byte symmetric key
        let symmetric_key = derive_symmetric_key(&shared_secret, &ephemeral_key);

        // 6. Generate random nonce for C_enc
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        // 7. Compute commitment for AAD
        let commitment = note.commitment();

        // 8. Build AAD: (diversifier_index || ephemeral_key)
        let mut aad = Vec::with_capacity(DIVERSIFIER_INDEX_SIZE + EPK_SIZE);
        aad.extend_from_slice(&recipient_addr.diversifier_index.to_le_bytes());
        aad.extend_from_slice(&ephemeral_key);

        // 9. Encrypt C_enc with ChaCha20-Poly1305
        let plaintext = serialize_note(note);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption should not fail");

        let c_enc = EncryptedNote {
            diversifier_index: recipient_addr.diversifier_index,
            ephemeral_key,
            nonce: nonce_bytes,
            ciphertext,
        };

        // 10. Encrypt C_out for sender recovery
        let c_out = encrypt_outgoing(rng, sender_ovk, esk, &ephemeral_key, note, commitment);

        OutputCiphertexts {
            c_enc,
            c_out,
            commitment,
        }
    }

    fn try_decrypt_outgoing(
        &self,
        c_out: &OutgoingCiphertext,
        epk_bytes: &[u8; EPK_SIZE],
        commitment: Fr,
        ovk: Fr,
    ) -> Result<OutgoingPlaintext, EncryptionError> {
        decrypt_outgoing(ovk, c_out, epk_bytes, commitment)
    }

    fn scheme_name(&self) -> &'static str {
        "ECIES-ChaCha20Poly1305"
    }
}

// ============================================================================
// Mock Encryption (Testing)
// ============================================================================

/// Mock encryption for testing (fast but insecure)
///
/// Uses simple XOR with a derived key. DO NOT USE IN PRODUCTION.
pub struct MockEncryption;

impl MockEncryption {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteEncryption for MockEncryption {
    fn encrypt(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
    ) -> EncryptedNote {
        // For mock: store the full nonce in the ephemeral_key field
        let nonce_fr = Fr::rand(rng);
        let nonce_bytes = field_to_bytes(&nonce_fr);

        // For mock: encrypt with the note's recipient (from note.recipient field)
        // This way any viewing key that produces this recipient can decrypt
        let key = derive_mock_key(note.recipient, nonce_fr);
        let plaintext = serialize_note(note);
        let ciphertext = xor_crypt(&plaintext, &key);

        // Store nonce_fr in ephemeral_key (first 32 bytes) for mock
        let mut ephemeral_key = [0u8; EPK_SIZE];
        ephemeral_key[..32].copy_from_slice(&nonce_bytes);

        // Use a fixed nonce value for the struct (mock doesn't use ChaCha)
        let nonce = [0u8; NONCE_SIZE];

        EncryptedNote {
            diversifier_index: recipient_addr.diversifier_index,
            ephemeral_key,
            nonce,
            ciphertext,
        }
    }

    fn try_decrypt(
        &self,
        encrypted: &EncryptedNote,
        fvk: &FullViewingKey,
        diversifier_index: u64,
    ) -> Result<Note, EncryptionError> {
        if encrypted.diversifier_index != diversifier_index {
            return Err(EncryptionError::WrongRecipient);
        }
        let addr = fvk.diversified_address(diversifier_index);

        // Recover nonce_fr from ephemeral_key
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes.copy_from_slice(&encrypted.ephemeral_key[..32]);
        let nonce_fr = field_from_bytes(&nonce_bytes);

        // Try to decrypt with this address
        let key = derive_mock_key(addr.to_field(), nonce_fr);
        let plaintext = xor_crypt(&encrypted.ciphertext, &key);

        let note = deserialize_note(&plaintext)?;

        // Verify the decrypted recipient matches what we tried
        if note.recipient != addr.to_field() {
            return Err(EncryptionError::WrongRecipient);
        }

        Ok(note)
    }

    fn encrypt_with_outgoing(
        &self,
        rng: &mut dyn CryptoRngCore,
        note: &Note,
        recipient_addr: &DiversifiedAddress,
        sender_ovk: Fr,
    ) -> OutputCiphertexts {
        // For mock: use simple encryption for both C_enc and C_out
        let c_enc = self.encrypt(rng, note, recipient_addr);
        let commitment = note.commitment();

        // Mock C_out: just store the note plaintext XOR'd with ovk-derived key
        let esk = Fr::rand(rng);

        // Build mock C_out plaintext
        let mut plaintext = Vec::with_capacity(C_OUT_PLAINTEXT_SIZE);
        plaintext.extend_from_slice(&field_to_bytes(&esk));
        plaintext.extend_from_slice(&serialize_note(note));

        // Derive mock key from ovk
        let key = derive_mock_key(sender_ovk, commitment);
        let ciphertext = xor_crypt(&plaintext, &key);

        let c_out = OutgoingCiphertext {
            nonce: [0u8; NONCE_SIZE],
            ciphertext,
        };

        OutputCiphertexts {
            c_enc,
            c_out,
            commitment,
        }
    }

    fn try_decrypt_outgoing(
        &self,
        c_out: &OutgoingCiphertext,
        _epk_bytes: &[u8; EPK_SIZE],
        commitment: Fr,
        ovk: Fr,
    ) -> Result<OutgoingPlaintext, EncryptionError> {
        // Mock decryption: XOR with ovk-derived key
        let key = derive_mock_key(ovk, commitment);
        let plaintext = xor_crypt(&c_out.ciphertext, &key);

        // Support both V2 and legacy V1 formats (see decrypt_outgoing).
        if plaintext.len() == C_OUT_PLAINTEXT_SIZE {
            let esk = field_from_bytes(&plaintext[..32].try_into().unwrap());
            let note = deserialize_note(&plaintext[32..])?;
            let recipient_pk_d_x = note.recipient;
            return Ok(OutgoingPlaintext {
                esk,
                recipient_pk_d_x,
                note,
            });
        }

        if plaintext.len() == C_OUT_PLAINTEXT_SIZE_V1 {
            let esk = field_from_bytes(&plaintext[..32].try_into().unwrap());
            let recipient_pk_d_x = field_from_bytes(&plaintext[32..64].try_into().unwrap());
            let note = deserialize_note(&plaintext[64..])?;
            return Ok(OutgoingPlaintext {
                esk,
                recipient_pk_d_x,
                note,
            });
        }

        Err(EncryptionError::InvalidLength)
    }

    fn scheme_name(&self) -> &'static str {
        "Mock-XOR (INSECURE)"
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert BN254 Fr to Grumpkin scalar
fn to_grumpkin_scalar(f: Fr) -> GrumpkinScalar {
    let bytes = f.into_bigint().to_bytes_le();
    GrumpkinScalar::from_le_bytes_mod_order(&bytes)
}

/// Convert Grumpkin base field element (== BN254 Fr) to Fr
fn from_grumpkin_base(fq: ark_grumpkin::Fq) -> Fr {
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Derive 32-byte symmetric key from shared secret point using Poseidon KDF
///
/// Includes ephemeral public key in derivation to bind key to this encryption.
fn derive_symmetric_key(shared_secret: &GrumpkinAffine, epk_bytes: &[u8; EPK_SIZE]) -> [u8; 32] {
    let ss_x = from_grumpkin_base(shared_secret.x);
    let ss_y = from_grumpkin_base(shared_secret.y);

    // Include epk_x in KDF for binding
    let epk_x = field_from_bytes(&epk_bytes[..32].try_into().unwrap());

    let key_field = poseidon_hash(&[DomainTag::Ciphertext.to_field(), ss_x, ss_y, epk_x]);

    field_to_bytes(&key_field)
}

/// Serialize Grumpkin point to bytes (x || y, 32 bytes each)
fn serialize_point(point: &GrumpkinAffine) -> [u8; EPK_SIZE] {
    let mut bytes = [0u8; EPK_SIZE];
    let x_bytes = point.x.into_bigint().to_bytes_le();
    let y_bytes = point.y.into_bigint().to_bytes_le();
    bytes[..32].copy_from_slice(&x_bytes[..32]);
    bytes[32..].copy_from_slice(&y_bytes[..32]);
    bytes
}

/// Deserialize Grumpkin point from bytes
fn deserialize_point(bytes: &[u8; EPK_SIZE]) -> Result<GrumpkinAffine, EncryptionError> {
    use ark_grumpkin::Fq;

    let x = Fq::from_le_bytes_mod_order(&bytes[..32]);
    let y = Fq::from_le_bytes_mod_order(&bytes[32..]);

    // Construct the affine point (this doesn't validate it's on the curve)
    let point = GrumpkinAffine::new(x, y);

    // Verify point is on curve
    if !point.is_on_curve() {
        return Err(EncryptionError::InvalidEphemeralKey);
    }

    Ok(point)
}

/// Serialize note to bytes
fn serialize_note(note: &Note) -> Vec<u8> {
    let p = note.to_plaintext();
    let mut bytes = Vec::with_capacity(PLAINTEXT_SIZE);
    bytes.extend_from_slice(&p.asset_id);
    bytes.extend_from_slice(&p.amount.to_le_bytes());
    bytes.extend_from_slice(&p.recipient);
    bytes.extend_from_slice(&p.diversifier_index.to_le_bytes());
    bytes.extend_from_slice(&p.nullifier_nonce);
    bytes.extend_from_slice(&p.note_randomness);
    bytes
}

/// Deserialize note from bytes
fn deserialize_note(bytes: &[u8]) -> Result<Note, EncryptionError> {
    if bytes.len() < PLAINTEXT_SIZE {
        return Err(EncryptionError::InvalidLength);
    }

    let mut asset_id = [0u8; 32];
    asset_id.copy_from_slice(&bytes[0..32]);

    let amount = u64::from_le_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| EncryptionError::SerializationError)?,
    );

    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&bytes[40..72]);

    let diversifier_index = u64::from_le_bytes(
        bytes[72..80]
            .try_into()
            .map_err(|_| EncryptionError::SerializationError)?,
    );

    let mut nullifier_nonce = [0u8; 32];
    nullifier_nonce.copy_from_slice(&bytes[80..112]);

    let mut note_randomness = [0u8; 32];
    note_randomness.copy_from_slice(&bytes[112..144]);

    let plaintext = NotePlaintext {
        asset_id,
        amount,
        recipient,
        diversifier_index,
        nullifier_nonce,
        note_randomness,
    };

    Ok(Note::from_plaintext(&plaintext))
}

/// Derive mock encryption key (for MockEncryption only)
fn derive_mock_key(recipient: Fr, nonce: Fr) -> Vec<u8> {
    let mut key = Vec::with_capacity(PLAINTEXT_SIZE);
    for i in 0..(PLAINTEXT_SIZE / 32 + 1) {
        let block = poseidon_hash(&[
            DomainTag::Ciphertext.to_field(),
            recipient,
            nonce,
            Fr::from(i as u64),
        ]);
        key.extend_from_slice(&field_to_bytes(&block));
    }
    key.truncate(PLAINTEXT_SIZE);
    key
}

/// XOR encryption/decryption (for MockEncryption only)
fn xor_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect()
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Encrypt a note using the default (production) encryption
pub fn encrypt_note(
    rng: &mut dyn CryptoRngCore,
    note: &Note,
    recipient_addr: &DiversifiedAddress,
) -> EncryptedNote {
    ChaChaPolyEncryption::new().encrypt(rng, note, recipient_addr)
}

/// Try to decrypt a note using the default (production) encryption
pub fn try_decrypt_note(
    encrypted: &EncryptedNote,
    fvk: &FullViewingKey,
    diversifier_index: u64,
) -> Option<Note> {
    ChaChaPolyEncryption::new()
        .try_decrypt(encrypted, fvk, diversifier_index)
        .ok()
}

/// Trial decrypt: try multiple diversifier indices
pub fn trial_decrypt(encrypted: &EncryptedNote, fvk: &FullViewingKey) -> Option<(Note, u64)> {
    let enc = ChaChaPolyEncryption::new();
    let i = encrypted.diversifier_index;
    enc.try_decrypt(encrypted, fvk, i).ok().map(|n| (n, i))
}

// ============================================================================
// Note Verification Utilities
// ============================================================================

/// Verification result for a decrypted note
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteVerification {
    /// Note is valid and matches the on-chain commitment
    Valid,
    /// Commitment doesn't match the note contents
    CommitmentMismatch { expected: Fr, computed: Fr },
    /// Recipient doesn't match any known address
    WrongRecipient,
    /// Note decryption failed
    DecryptionFailed,
}

/// Verify a decrypted note against an expected commitment
pub fn verify_note_commitment(note: &Note, expected_commitment: Fr) -> NoteVerification {
    let computed = note.commitment();
    if computed == expected_commitment {
        NoteVerification::Valid
    } else {
        NoteVerification::CommitmentMismatch {
            expected: expected_commitment,
            computed,
        }
    }
}

/// Verify a note belongs to a viewing key
pub fn verify_note_ownership(
    note: &Note,
    fvk: &FullViewingKey,
    max_diversifier: u64,
) -> Option<u64> {
    for i in 0..=max_diversifier {
        let addr = fvk.diversified_address(i);
        if note.recipient == addr.to_field() {
            return Some(i);
        }
    }
    None
}

/// Full verification of a decrypted note
pub fn verify_decrypted_note(
    note: &Note,
    expected_commitment: Fr,
    fvk: &FullViewingKey,
    max_diversifier: u64,
) -> NoteVerification {
    let commitment_result = verify_note_commitment(note, expected_commitment);
    if commitment_result != NoteVerification::Valid {
        return commitment_result;
    }

    if verify_note_ownership(note, fvk, max_diversifier).is_none() {
        return NoteVerification::WrongRecipient;
    }

    NoteVerification::Valid
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::compute_asset_id;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_token() -> [u8; 32] {
        [1u8; 32]
    }

    // ---- ChaCha20-Poly1305 Tests ----

    #[test]
    fn test_chacha_encrypt_decrypt_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = ChaChaPolyEncryption::new();

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(0);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let encrypted = enc.encrypt(&mut rng, &note, &addr);
        let decrypted = enc.try_decrypt(&encrypted, &fvk, 0).unwrap();

        assert_eq!(decrypted.asset_id, note.asset_id);
        assert_eq!(decrypted.amount, note.amount);
        assert_eq!(decrypted.recipient, note.recipient);
        assert_eq!(decrypted.nullifier_nonce, note.nullifier_nonce);
        assert_eq!(decrypted.note_randomness, note.note_randomness);
    }

    #[test]
    fn test_chacha_wrong_key_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = ChaChaPolyEncryption::new();

        let recipient_sk = SpendingKey::from_bytes(&[42u8; 32]);
        let recipient_fvk = recipient_sk.to_full_viewing_key();
        let recipient_addr = recipient_fvk.diversified_address(0);

        let attacker_sk = SpendingKey::from_bytes(&[99u8; 32]);
        let attacker_fvk = attacker_sk.to_full_viewing_key();

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            recipient_addr.to_field(),
            recipient_addr.diversifier_index,
        );

        let encrypted = enc.encrypt(&mut rng, &note, &recipient_addr);

        // Attacker cannot decrypt (wrong key)
        let result = enc.try_decrypt(&encrypted, &attacker_fvk, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha_tampered_ciphertext_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = ChaChaPolyEncryption::new();

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(0);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let mut encrypted = enc.encrypt(&mut rng, &note, &addr);

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail (authentication tag mismatch)
        let result = enc.try_decrypt(&encrypted, &fvk, 0);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_chacha_wrong_diversifier_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = ChaChaPolyEncryption::new();

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(5);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let encrypted = enc.encrypt(&mut rng, &note, &addr);

        // Wrong diversifier fails
        let result = enc.try_decrypt(&encrypted, &fvk, 0);
        assert!(result.is_err());

        // Correct diversifier succeeds
        let result = enc.try_decrypt(&encrypted, &fvk, 5);
        assert!(result.is_ok());
    }

    // ---- Mock Encryption Tests ----

    #[test]
    fn test_mock_encrypt_decrypt_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = MockEncryption::new();

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(0);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let encrypted = enc.encrypt(&mut rng, &note, &addr);
        let decrypted = enc.try_decrypt(&encrypted, &fvk, 0).unwrap();

        assert_eq!(decrypted.amount, note.amount);
    }

    // ---- Serialization Tests ----

    #[test]
    fn test_encrypted_note_serialization() {
        let mut rng = StdRng::seed_from_u64(12345);
        let enc = ChaChaPolyEncryption::new();

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(0);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let encrypted = enc.encrypt(&mut rng, &note, &addr);

        // Serialize and deserialize
        let bytes = encrypted.to_bytes();
        let recovered = EncryptedNote::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.ephemeral_key, recovered.ephemeral_key);
        assert_eq!(encrypted.nonce, recovered.nonce);
        assert_eq!(encrypted.ciphertext, recovered.ciphertext);

        // Should still decrypt
        let decrypted = enc.try_decrypt(&recovered, &fvk, 0).unwrap();
        assert_eq!(decrypted.amount, 100);
    }

    // ---- Verification Tests ----

    #[test]
    fn test_verify_commitment_valid() {
        let mut rng = StdRng::seed_from_u64(12345);
        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(&mut rng, asset_id, 100, Fr::from(999u64), 0);

        let commitment = note.commitment();
        let result = verify_note_commitment(&note, commitment);
        assert_eq!(result, NoteVerification::Valid);
    }

    #[test]
    fn test_verify_commitment_mismatch() {
        let mut rng = StdRng::seed_from_u64(12345);
        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(&mut rng, asset_id, 100, Fr::from(999u64), 0);

        let wrong_commitment = Fr::from(12345u64);
        let result = verify_note_commitment(&note, wrong_commitment);
        assert!(matches!(
            result,
            NoteVerification::CommitmentMismatch { .. }
        ));
    }

    #[test]
    fn test_trial_decrypt_finds_note() {
        let mut rng = StdRng::seed_from_u64(12345);

        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.diversified_address(3);

        let asset_id = compute_asset_id(&test_token());
        let note = Note::new(
            &mut rng,
            asset_id,
            100,
            addr.to_field(),
            addr.diversifier_index,
        );

        let encrypted = encrypt_note(&mut rng, &note, &addr);

        let result = trial_decrypt(&encrypted, &fvk);
        assert!(result.is_some());

        let (decrypted, diversifier) = result.unwrap();
        assert_eq!(diversifier, 3);
        assert_eq!(decrypted.amount, 100);
    }

    #[test]
    fn test_scheme_names() {
        assert_eq!(
            ChaChaPolyEncryption::new().scheme_name(),
            "ECIES-ChaCha20Poly1305"
        );
        assert_eq!(MockEncryption::new().scheme_name(), "Mock-XOR (INSECURE)");
    }
}

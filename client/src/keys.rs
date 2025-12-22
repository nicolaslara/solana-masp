//! Sapling-style key hierarchy for MASP
//!
//! Uses Zcash Sapling terminology (see ZIP-32, Protocol Spec §4.2.2):
//!
//! ```text
//! sk (SpendingKey) - 32 random bytes, root secret
//!  │
//!  ├─► ask (spend auth secret)──► ak = ask * G  (public)
//!  │                                    │
//!  └─► nsk (nullifier secret)──► nk = nsk * G  (public)
//!                                       │
//!                    ┌──────────────────┘
//!                    ▼
//!              fvk = (ak, nk)  ─── FullViewingKey (can view, CANNOT spend)
//!                    │
//!                    ├─► ivk = H(ak.x, nk.x)  ─── IncomingViewingKey (decrypt received)
//!                    │         │
//!                    │         ▼
//!                    │   pk_d = ivk * g_d  ─── DiversifiedAddress
//!                    │
//!                    └─► ovk = H(ak.x, nk.x, "ovk")  ─── OutgoingViewingKey (decrypt sent)
//! ```
//!
//! **Key separation:**
//! - `SpendingKey` - can spend (has ask, nsk secrets)
//! - `FullViewingKey` - can view all tx, CANNOT spend (only ak, nk public keys)
//! - `IncomingViewingKey` (ivk) - can decrypt notes sent TO you
//! - `OutgoingViewingKey` (ovk) - can decrypt notes sent BY you (C_out)
//!
//! **Sapling terminology:**
//! - `sk`  = spending key (root secret)
//! - `ask` = spend authorization secret
//! - `nsk` = nullifier secret  
//! - `ak`  = authorization public key
//! - `nk`  = nullifier public key
//! - `fvk` = full viewing key (ak, nk)
//! - `ivk` = incoming viewing key
//! - `ovk` = outgoing viewing key
//! - `g_d` = diversifier base point
//! - `pk_d`= diversified payment address

use crate::domain::DomainTag;
use crate::hash::poseidon2_hash_noir;
use crate::types::Fr;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_grumpkin::{
    Affine as GrumpkinAffine, Fr as GrumpkinScalar, Projective as GrumpkinProjective,
};
use rand::Rng;

/// Grumpkin generator point (matches Noir's std::embedded_curve_ops)
fn generator() -> GrumpkinProjective {
    GrumpkinProjective::generator()
}

/// Convert BN254 Fr to Grumpkin scalar
///
/// NOTE: Grumpkin's scalar field IS BN254's base field, so this is a direct conversion.
/// The scalar field order is the same as BN254's base field modulus.
fn to_grumpkin_scalar(f: Fr) -> GrumpkinScalar {
    // Fr (BN254 scalar) -> bytes -> GrumpkinScalar (== BN254 base field, but they share order)
    // Actually, Grumpkin's scalar field order equals BN254's base field, and BN254's scalar
    // field is slightly smaller. We reduce mod order to be safe.
    let bytes = f.into_bigint().to_bytes_le();
    GrumpkinScalar::from_le_bytes_mod_order(&bytes)
}

/// Convert Grumpkin base field element (== BN254 scalar field Fr) to Fr
///
/// Grumpkin's base field IS BN254's scalar field, so this is just a type conversion.
fn from_grumpkin_base(fq: ark_grumpkin::Fq) -> Fr {
    // Grumpkin Fq == BN254 Fr (same field), direct conversion
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

/// The root spending key (sk) - guards all spending authority
///
/// This is the SECRET that must be protected. From it we derive:
/// - `ask` (spend authorization secret) - needed to sign spends
/// - `nsk` (nullifier secret) - needed to compute nullifiers
#[derive(Debug, Clone)]
pub struct SpendingKey {
    sk: Fr,
}

impl SpendingKey {
    /// Create from a BN254 field element (internal convenience).
    pub(crate) fn from_field(sk: Fr) -> Self {
        Self { sk }
    }

    /// Generate a random spending key
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self { sk: Fr::rand(rng) }
    }

    /// Create from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            sk: Fr::from_be_bytes_mod_order(bytes),
        }
    }

    /// Derive spend authorization secret (Sapling: ask)
    /// PRIVATE - needed for spend signatures
    pub fn ask(&self) -> Fr {
        poseidon2_hash_noir(&[DomainTag::AuthorizationSecret.to_field(), self.sk], 2)
    }

    /// Derive nullifier secret (Sapling: nsk)
    /// PRIVATE - needed for nullifier computation
    pub fn nsk(&self) -> Fr {
        poseidon2_hash_noir(&[DomainTag::NullifierSecret.to_field(), self.sk], 2)
    }

    /// Derive the full viewing key (can view but CANNOT spend)
    ///
    /// The FVK contains only PUBLIC keys (ak, nk).
    /// Give this to someone who should see your transactions but not spend.
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        let ask = self.ask();
        let nsk = self.nsk();

        // Compute public keys on Grumpkin (matches Noir's embedded curve)
        let ak = (generator() * to_grumpkin_scalar(ask)).into_affine();
        let nk = (generator() * to_grumpkin_scalar(nsk)).into_affine();

        FullViewingKey { ak, nk }
    }

    /// Get nullifier key as field element (nk.x)
    /// Convenience method for computing nullifiers
    pub fn nk_field(&self) -> Fr {
        self.to_full_viewing_key().nk_field()
    }

    /// Get raw key as field element
    pub fn as_field(&self) -> Fr {
        self.sk
    }
}

/// Full viewing key - can view transactions but CANNOT spend
///
/// Contains only PUBLIC keys (ak, nk). Safe to share with:
/// - Auditors who need to see your transaction history
/// - Watch-only wallets
///
/// Does NOT contain ask or nsk (the secrets needed to spend).
#[derive(Debug, Clone)]
pub struct FullViewingKey {
    /// Authorization public key (Sapling: ak)
    /// ak = ask * G (Grumpkin point)
    pub ak: GrumpkinAffine,

    /// Nullifier public key (Sapling: nk)
    /// nk = nsk * G (Grumpkin point)
    pub nk: GrumpkinAffine,
}

impl FullViewingKey {
    /// Derive the incoming viewing key (Sapling: ivk)
    ///
    /// `ivk = H(DOM_IVK, ak.x, nk.x)`
    ///
    /// The ivk allows decrypting notes sent TO addresses derived from this key.
    pub fn ivk(&self) -> Fr {
        let ak_x = from_grumpkin_base(self.ak.x);
        let nk_x = from_grumpkin_base(self.nk.x);
        poseidon2_hash_noir(&[DomainTag::IncomingViewingKey.to_field(), ak_x, nk_x], 3)
    }

    /// Derive the outgoing viewing key (Sapling: ovk)
    ///
    /// `ovk = H(DOM_OVK, ak.x, nk.x)`
    ///
    /// The ovk allows decrypting notes sent BY this key (C_out).
    /// This enables sender to recover what they sent (audit trail).
    pub fn ovk(&self) -> Fr {
        let ak_x = from_grumpkin_base(self.ak.x);
        let nk_x = from_grumpkin_base(self.nk.x);
        poseidon2_hash_noir(&[DomainTag::OutgoingViewingKey.to_field(), ak_x, nk_x], 3)
    }

    /// Get the nullifier key as a field element (nk.x coordinate)
    ///
    /// Used in nullifier computation: `nf = H(DOM, nk.x, nonce)`
    pub fn nk_field(&self) -> Fr {
        from_grumpkin_base(self.nk.x)
    }

    /// Generate a diversified address at the given index (Sapling: pk_d)
    ///
    /// Different indices produce unlinkable addresses from the same key.
    /// `pk_d = ivk * g_d` where `g_d` is derived from the diversifier.
    pub fn diversified_address(&self, diversifier_index: u64) -> DiversifiedAddress {
        let ivk = self.ivk();

        // Derive diversifier base point (Sapling: g_d)
        // g_d = H(index) * G (simplified; Sapling uses hash-to-curve)
        let g_d_scalar = poseidon2_hash_noir(&[Fr::from(diversifier_index)], 1);
        let g_d = (generator() * to_grumpkin_scalar(g_d_scalar)).into_affine();

        // pk_d = ivk * g_d
        let pk_d = (GrumpkinProjective::from(g_d) * to_grumpkin_scalar(ivk)).into_affine();

        DiversifiedAddress {
            diversifier_index,
            g_d,
            pk_d,
        }
    }
}

/// A diversified payment address (Sapling: d, pk_d)
///
/// Multiple addresses can be derived from one viewing key,
/// providing unlinkability between addresses.
#[derive(Debug, Clone)]
pub struct DiversifiedAddress {
    /// Diversifier index used to derive this address
    pub diversifier_index: u64,

    /// Diversifier base point (Sapling: g_d)
    pub g_d: GrumpkinAffine,

    /// Diversified transmission key (Sapling: pk_d)
    /// pk_d = ivk * g_d
    pub pk_d: GrumpkinAffine,
}

impl DiversifiedAddress {
    /// Get address as field element (pk_d.x for use as note recipient)
    pub fn to_field(&self) -> Fr {
        from_grumpkin_base(self.pk_d.x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_key_derivation_deterministic() {
        let sk1 = SpendingKey::from_bytes(&[42u8; 32]);
        let sk2 = SpendingKey::from_bytes(&[42u8; 32]);

        assert_eq!(sk1.ask(), sk2.ask());
        assert_eq!(sk1.nsk(), sk2.nsk());

        let fvk1 = sk1.to_full_viewing_key();
        let fvk2 = sk2.to_full_viewing_key();
        assert_eq!(fvk1.ak, fvk2.ak);
        assert_eq!(fvk1.nk, fvk2.nk);
    }

    #[test]
    fn test_different_spending_keys() {
        let sk1 = SpendingKey::from_bytes(&[1u8; 32]);
        let sk2 = SpendingKey::from_bytes(&[2u8; 32]);

        assert_ne!(sk1.ask(), sk2.ask());
        assert_ne!(sk1.nk_field(), sk2.nk_field());
    }

    #[test]
    fn test_fvk_cannot_derive_secrets() {
        // This test documents that FVK doesn't expose ask/nsk
        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();

        // FVK only has public keys, not secrets
        // We can get nk.x for nullifier computation (view-only needs this)
        let _nk_x = fvk.nk_field();

        // But we cannot get ask or nsk from FVK
        // (they're not fields on FullViewingKey)
    }

    #[test]
    fn test_diversified_addresses_different() {
        let fvk = SpendingKey::from_bytes(&[42u8; 32]).to_full_viewing_key();

        let addr0 = fvk.diversified_address(0);
        let addr1 = fvk.diversified_address(1);

        assert_ne!(addr0.pk_d, addr1.pk_d);
        assert_ne!(addr0.to_field(), addr1.to_field());
    }

    #[test]
    fn test_diversified_address_deterministic() {
        let fvk = SpendingKey::from_bytes(&[42u8; 32]).to_full_viewing_key();

        let addr1 = fvk.diversified_address(5);
        let addr2 = fvk.diversified_address(5);

        assert_eq!(addr1.pk_d, addr2.pk_d);
    }

    #[test]
    fn test_random_key() {
        let mut rng = StdRng::seed_from_u64(12345);
        let sk = SpendingKey::random(&mut rng);

        assert_ne!(sk.nk_field(), Fr::from(0u64));
    }

    #[test]
    fn test_ivk_derivation() {
        let fvk = SpendingKey::from_bytes(&[42u8; 32]).to_full_viewing_key();

        let ivk1 = fvk.ivk();
        let ivk2 = fvk.ivk();
        assert_eq!(ivk1, ivk2);
        assert_ne!(ivk1, Fr::from(0u64));
    }

    #[test]
    fn test_ovk_derivation() {
        let fvk = SpendingKey::from_bytes(&[42u8; 32]).to_full_viewing_key();

        let ovk1 = fvk.ovk();
        let ovk2 = fvk.ovk();
        assert_eq!(ovk1, ovk2);
        assert_ne!(ovk1, Fr::from(0u64));

        // ovk should be different from ivk
        assert_ne!(fvk.ovk(), fvk.ivk());
    }

    #[test]
    fn test_ovk_different_for_different_keys() {
        let fvk1 = SpendingKey::from_bytes(&[1u8; 32]).to_full_viewing_key();
        let fvk2 = SpendingKey::from_bytes(&[2u8; 32]).to_full_viewing_key();

        assert_ne!(fvk1.ovk(), fvk2.ovk());
    }

    #[test]
    fn test_grumpkin_generator_matches_noir() {
        let gen = super::generator();
        let gen_affine = gen.into_affine();

        // Noir's embedded curve generator (from testing): x=1, y=17631683881184975370165255887551781615748388533673675138860
        println!("Grumpkin generator x: {}", gen_affine.x);
        println!("Grumpkin generator y: {}", gen_affine.y);

        // Check x coordinate is 1 (matches Noir's embedded curve generator)
        assert_eq!(gen_affine.x, ark_grumpkin::Fq::from(1u64));
    }

    /// Generates valid Prover.toml values for circuit testing.
    /// Run with: cargo test -p masp-client gen_valid_circuit_witness -- --nocapture --ignored
    #[test]
    #[ignore]
    fn gen_valid_circuit_witness() {
        use crate::hash::merkle_hash;
        use crate::note::Note;
        use crate::nullifier::compute_nullifier;
        use crate::tx_binding::{tx_binding_transfer, tx_binding_unshield};
        use ark_ff::{BigInteger, PrimeField};

        fn fr_to_dec(fr: Fr) -> String {
            let bigint = fr.into_bigint();
            let bytes = bigint.to_bytes_be();
            num_bigint::BigUint::from_bytes_be(&bytes).to_string()
        }

        // Create spending key
        let sk = SpendingKey::from_bytes(&[42u8; 32]);
        let fvk = sk.to_full_viewing_key();

        // Get diversified address at index 0
        let div_index = 0u64;
        let addr = fvk.diversified_address(div_index);
        let note_recipient = addr.to_field();

        // Note fields
        let note_asset_id = Fr::from(10u64);
        let note_amount = 100u64;
        let note_nullifier_nonce = Fr::from(12345u64);
        let note_randomness = Fr::from(67890u64);

        // Create note and compute commitment
        let note = Note::with_values(
            note_asset_id,
            note_amount,
            note_recipient,
            div_index,
            note_nullifier_nonce,
            note_randomness,
        );
        let commitment = note.commitment();

        // Compute nullifier using nsk (secret!)
        let nsk = sk.nsk();
        let nullifier = compute_nullifier(nsk, note_nullifier_nonce);

        // Build Merkle tree: leaf is commitment, compute root with 16 zero siblings
        let zero_sibling = Fr::from(0u64);
        let mut current = commitment;
        for _ in 0..16 {
            // path_index = false means current is left child
            current = merkle_hash(current, zero_sibling);
        }
        let anchor = current;

        // Compute tx_binding for transfer
        let nullifiers = [nullifier, Fr::from(0u64), Fr::from(0u64)];
        let _ct_hashes = [Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)];
        let tx_binding_xfer = tx_binding_transfer(anchor, &nullifiers, 1, 1);

        // Compute output nonce using circuit's formula: H(DOM_NULLIFIER_NONCE, tx_binding, output_index)
        use crate::domain::DomainTag;
        let output_nonce = poseidon2_hash_noir(
            &[
                DomainTag::NullifierNonce.to_field(),
                tx_binding_xfer,
                Fr::from(0u64),
            ],
            3,
        );

        // Create output note with derived nonce and compute its commitment
        let output_randomness = Fr::from(11111u64);
        let output_note = Note::with_values(
            note_asset_id,
            note_amount,
            note_recipient, // self-transfer
            div_index,
            output_nonce,
            output_randomness,
        );
        let output_commitment = output_note.commitment();

        println!("=== TRANSFER Prover.toml ===\n");
        println!("anchor = \"{}\"", fr_to_dec(anchor));
        println!("nullifiers = [\"{}\", \"0\", \"0\"]", fr_to_dec(nullifier));
        println!(
            "output_commitments = [\"{}\", \"0\", \"0\"]",
            fr_to_dec(output_commitment)
        );
        println!("input_count = 1");
        println!("output_count = 1");
        println!("ct_hashes = [\"1\", \"0\", \"0\"]");
        println!("tx_binding = \"{}\"", fr_to_dec(tx_binding_xfer));
        println!();
        println!("transfer_asset_id = \"{}\"", fr_to_dec(note_asset_id));
        println!();
        println!("[[inputs]]");
        println!("enabled = true");
        println!("note_asset_id = \"{}\"", fr_to_dec(note_asset_id));
        println!("note_amount = {}", note_amount);
        println!("note_recipient = \"{}\"", fr_to_dec(note_recipient));
        println!("note_diversifier_index = {}", div_index);
        println!(
            "note_nullifier_nonce = \"{}\"",
            fr_to_dec(note_nullifier_nonce)
        );
        println!("note_randomness = \"{}\"", fr_to_dec(note_randomness));
        println!("spending_key = \"{}\"", fr_to_dec(sk.as_field()));
        println!("siblings = [\"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\"]");
        println!("path_indices = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false]");
        println!();
        println!("# Input commitment = {}", fr_to_dec(commitment));
        println!();
        // Output note
        println!("[[outputs]]");
        println!("enabled = true");
        println!("note_asset_id = \"{}\"", fr_to_dec(note_asset_id));
        println!("note_amount = {}", note_amount);
        println!("note_recipient = \"{}\"", fr_to_dec(note_recipient));
        println!("note_diversifier_index = {}", div_index);
        println!("note_nullifier_nonce = \"{}\"", fr_to_dec(output_nonce));
        println!("note_randomness = \"{}\"", fr_to_dec(output_randomness));
        println!();
        println!("[[outputs]]");
        println!("enabled = false");
        println!("note_asset_id = \"0\"");
        println!("note_amount = 0");
        println!("note_recipient = \"0\"");
        println!("note_diversifier_index = 0");
        println!("note_nullifier_nonce = \"0\"");
        println!("note_randomness = \"0\"");
        println!();
        println!("[[outputs]]");
        println!("enabled = false");
        println!("note_asset_id = \"0\"");
        println!("note_amount = 0");
        println!("note_recipient = \"0\"");
        println!("note_diversifier_index = 0");
        println!("note_nullifier_nonce = \"0\"");
        println!("note_randomness = \"0\"");

        // Compute tx_binding for unshield
        let public_recipient_limbs = [0u64, 0u64, 0u64, 0u64];
        let tx_binding_unsh = tx_binding_unshield(
            anchor,
            nullifier,
            note_amount,
            public_recipient_limbs,
            note_asset_id,
        );

        println!("\n\n=== UNSHIELD Prover.toml ===\n");
        println!("anchor = \"{}\"", fr_to_dec(anchor));
        println!("nullifier = \"{}\"", fr_to_dec(nullifier));
        println!("tx_binding = \"{}\"", fr_to_dec(tx_binding_unsh));
        println!("public_amount = {}", note_amount);
        println!("public_recipient_limbs = [0, 0, 0, 0]");
        println!("public_asset_id = \"{}\"", fr_to_dec(note_asset_id));
        println!();
        println!("note_asset_id = \"{}\"", fr_to_dec(note_asset_id));
        println!("note_amount = {}", note_amount);
        println!("note_recipient = \"{}\"", fr_to_dec(note_recipient));
        println!("note_diversifier_index = {}", div_index);
        println!(
            "note_nullifier_nonce = \"{}\"",
            fr_to_dec(note_nullifier_nonce)
        );
        println!("note_randomness = \"{}\"", fr_to_dec(note_randomness));
        println!("spending_key = \"{}\"", fr_to_dec(sk.as_field()));
        println!("siblings = [\"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\"]");
        println!("path_indices = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false]");
    }
}

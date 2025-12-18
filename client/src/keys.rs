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
use crate::hash::poseidon_hash;
use crate::types::Fr;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as JubJubScalar};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use rand::Rng;

/// Baby JubJub generator point
fn generator() -> EdwardsProjective {
    EdwardsProjective::generator()
}

/// Convert BN254 Fr to Baby JubJub scalar (reduce mod JubJub order)
fn to_jubjub_scalar(f: Fr) -> JubJubScalar {
    let bytes = f.into_bigint().to_bytes_le();
    JubJubScalar::from_le_bytes_mod_order(&bytes)
}

/// Convert Baby JubJub base field element to BN254 Fr
fn from_jubjub_base(fq: ark_ed_on_bn254::Fq) -> Fr {
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
        poseidon_hash(&[DomainTag::AuthorizationSecret.to_field(), self.sk])
    }

    /// Derive nullifier secret (Sapling: nsk)
    /// PRIVATE - needed for nullifier computation
    pub fn nsk(&self) -> Fr {
        poseidon_hash(&[DomainTag::NullifierSecret.to_field(), self.sk])
    }

    /// Derive the full viewing key (can view but CANNOT spend)
    ///
    /// The FVK contains only PUBLIC keys (ak, nk).
    /// Give this to someone who should see your transactions but not spend.
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        let ask = self.ask();
        let nsk = self.nsk();

        // Compute public keys on Baby JubJub
        let ak = (generator() * to_jubjub_scalar(ask)).into_affine();
        let nk = (generator() * to_jubjub_scalar(nsk)).into_affine();

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
    /// ak = ask * G (Baby JubJub point)
    pub ak: EdwardsAffine,

    /// Nullifier public key (Sapling: nk)  
    /// nk = nsk * G (Baby JubJub point)
    pub nk: EdwardsAffine,
}

impl FullViewingKey {
    /// Derive the incoming viewing key (Sapling: ivk)
    ///
    /// `ivk = H(DOM_IVK, ak.x, nk.x)`
    ///
    /// The ivk allows decrypting notes sent TO addresses derived from this key.
    pub fn ivk(&self) -> Fr {
        let ak_x = from_jubjub_base(self.ak.x);
        let nk_x = from_jubjub_base(self.nk.x);
        poseidon_hash(&[DomainTag::IncomingViewingKey.to_field(), ak_x, nk_x])
    }

    /// Derive the outgoing viewing key (Sapling: ovk)
    ///
    /// `ovk = H(DOM_OVK, ak.x, nk.x)`
    ///
    /// The ovk allows decrypting notes sent BY this key (C_out).
    /// This enables sender to recover what they sent (audit trail).
    pub fn ovk(&self) -> Fr {
        let ak_x = from_jubjub_base(self.ak.x);
        let nk_x = from_jubjub_base(self.nk.x);
        poseidon_hash(&[DomainTag::OutgoingViewingKey.to_field(), ak_x, nk_x])
    }

    /// Get the nullifier key as a field element (nk.x coordinate)
    ///
    /// Used in nullifier computation: `nf = H(DOM, nk.x, nonce)`
    pub fn nk_field(&self) -> Fr {
        from_jubjub_base(self.nk.x)
    }

    /// Generate a diversified address at the given index (Sapling: pk_d)
    ///
    /// Different indices produce unlinkable addresses from the same key.
    /// `pk_d = ivk * g_d` where `g_d` is derived from the diversifier.
    pub fn diversified_address(&self, diversifier_index: u64) -> DiversifiedAddress {
        let ivk = self.ivk();

        // Derive diversifier base point (Sapling: g_d)
        // g_d = H(index) * G (simplified; Sapling uses hash-to-curve)
        let g_d_scalar = poseidon_hash(&[Fr::from(diversifier_index)]);
        let g_d = (generator() * to_jubjub_scalar(g_d_scalar)).into_affine();

        // pk_d = ivk * g_d
        let pk_d = (EdwardsProjective::from(g_d) * to_jubjub_scalar(ivk)).into_affine();

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
    pub g_d: EdwardsAffine,

    /// Diversified transmission key (Sapling: pk_d)
    /// pk_d = ivk * g_d
    pub pk_d: EdwardsAffine,
}

impl DiversifiedAddress {
    /// Get address as field element (pk_d.x for use as note recipient)
    pub fn to_field(&self) -> Fr {
        from_jubjub_base(self.pk_d.x)
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
}

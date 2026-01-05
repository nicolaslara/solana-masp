//! Light Protocol Nullifier Store (STUB)
//!
//! Uses Light Protocol's derived addresses for nullifier tracking.
//! This replaces PDA-based nullifier storage with Light Protocol's
//! compressed account system.
//!
//! ## Status: SCAFFOLD
//!
//! This module outlines the integration pattern. Full implementation pending:
//! - borsh version alignment (light-sdk uses 0.10, we use 1.6)
//! - API surface exploration with light-sdk v0.17+
//!
//! ## How it works:
//!
//! 1. Client derives nullifier address using `derive_nullifier_address_seed()`
//! 2. Client fetches validity proof from Photon (proves address doesn't exist)
//! 3. Client submits transaction with validity proof
//! 4. On-chain program uses Light CPI to create the derived address
//! 5. If address already exists (nullifier spent), CPI fails
//!
//! ## Light SDK Integration Notes
//!
//! The light-sdk without Anchor uses borsh 0.10, while our program uses borsh 1.6.
//! Options:
//! 1. Downgrade to borsh 0.10 (affects masp-protocol compatibility)
//! 2. Use invoke_signed directly with manual serialization (more work)
//! 3. Create a wrapper crate that bridges the versions
//!
//! For now, we document the pattern and stub the interface.

#![cfg(feature = "light-protocol")]

use solana_program::{account_info::AccountInfo, msg, program_error::ProgramError, pubkey::Pubkey};

/// Seed prefix for nullifier addresses (matches client-side derivation)
pub const NULLIFIER_SEED_PREFIX: &[u8] = b"nullifr\0";

/// Compressed proof from client (matches Light Protocol format)
#[derive(Clone, Debug)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl CompressedProof {
    /// Parse from instruction data (128 bytes)
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 128 {
            return Err(ProgramError::InvalidInstructionData);
        }
        
        let mut a = [0u8; 32];
        let mut b = [0u8; 64];
        let mut c = [0u8; 32];
        
        a.copy_from_slice(&data[0..32]);
        b.copy_from_slice(&data[32..96]);
        c.copy_from_slice(&data[96..128]);
        
        Ok(Self { a, b, c })
    }
    
    /// Total size in bytes
    pub const SIZE: usize = 128;
}

/// Light Protocol CPI parameters for nullifier insertion
#[derive(Clone, Debug)]
pub struct LightNullifierParams {
    /// Output state tree index in remaining accounts
    pub output_state_tree_index: u8,
    /// Address tree index in Light CPI tree accounts
    pub address_tree_account_index: u8,
    /// Address queue index in Light CPI tree accounts  
    pub address_queue_account_index: u8,
    /// Root index for the address tree validity proof
    pub address_tree_root_index: u16,
}

/// Insert a nullifier using Light Protocol CPI
///
/// STUB: This function outlines the integration pattern.
/// Full implementation requires borsh version alignment.
///
/// # Arguments
/// * `signer` - Fee payer and transaction signer
/// * `remaining_accounts` - Light Protocol accounts (state tree, address tree, etc.)
/// * `nullifier` - The nullifier to mark as spent
/// * `validity_proof` - Proof that the nullifier address doesn't exist yet
/// * `pool_pubkey` - Pool identifier for nullifier derivation
/// * `params` - Light Protocol CPI parameters
/// * `program_id` - Our program ID
///
/// # Errors
/// Returns error if:
/// - Nullifier already spent (address already exists)
/// - Invalid validity proof
/// - Light Protocol CPI fails
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
pub fn insert_with_light_cpi<'info>(
    signer: &AccountInfo<'info>,
    remaining_accounts: &[AccountInfo<'info>],
    nullifier: [u8; 32],
    validity_proof: CompressedProof,
    pool_pubkey: &Pubkey,
    params: LightNullifierParams,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    msg!("LightNullifier: STUB - Light Protocol integration pending");
    msg!("  nullifier: {:?}...", &nullifier[..8]);
    msg!("  pool: {}", pool_pubkey);
    msg!("  output_tree_idx: {}", params.output_state_tree_index);
    
    // STUB: Full implementation would:
    //
    // 1. Derive CPI signer PDA
    //    let (cpi_authority, bump) = Pubkey::find_program_address(&[b"cpi_authority"], program_id);
    //
    // 2. Derive nullifier address seed
    //    let seed = derive_nullifier_address_seed(&nullifier, pool_pubkey);
    //
    // 3. Build Light CPI accounts
    //    let light_cpi_accounts = CpiAccounts::new(signer, remaining_accounts, cpi_signer);
    //
    // 4. Create nullifier record light account
    //    let nullifier_record = LightAccount::<NullifierRecord>::new_init(...);
    //
    // 5. Build new address params
    //    let address_params = NewAddressParamsPacked { seed, ... };
    //
    // 6. Build validity proof
    //    let validity_proof_light = ValidityProof(Some(CompressedProof { a, b, c }));
    //
    // 7. Execute Light CPI
    //    LightSystemProgramCpi::new_cpi(cpi_signer, validity_proof_light)
    //        .with_new_addresses(&[address_params])
    //        .with_light_account(nullifier_record)
    //        .invoke(light_cpi_accounts)?;
    
    Err(ProgramError::Custom(999)) // STUB: Not implemented
}

/// Derive nullifier address seed (matches client-side)
///
/// seed = keccak256("nullifr\0" || nullifier || pool_pubkey)
pub fn derive_nullifier_address_seed(nullifier: &[u8; 32], pool_pubkey: &Pubkey) -> [u8; 32] {
    use solana_program::keccak;
    
    let pool_bytes = pool_pubkey.to_bytes();
    
    // Concatenate: prefix || nullifier || pool_pubkey
    let mut input = [0u8; 8 + 32 + 32];
    input[0..8].copy_from_slice(NULLIFIER_SEED_PREFIX);
    input[8..40].copy_from_slice(nullifier);
    input[40..72].copy_from_slice(&pool_bytes);
    
    keccak::hash(&input).to_bytes()
}

/// Derive address from seed and tree (Light Protocol style)
///
/// Uses bump search to find valid BN254 field element.
pub fn derive_address(seed: &[u8; 32], address_tree: &Pubkey) -> Result<([u8; 32], u8), ProgramError> {
    use solana_program::keccak;
    
    // BN254 field modulus (big-endian)
    const BN254_MODULUS_P: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];
    
    let tree_bytes = address_tree.to_bytes();
    let mut base = [0u8; 64];
    base[..32].copy_from_slice(&tree_bytes);
    base[32..].copy_from_slice(seed);
    
    for bump in (0u8..=255).rev() {
        let mut data = [0u8; 65];
        data[..64].copy_from_slice(&base);
        data[64] = bump;
        
        let hash = keccak::hash(&data);
        let mut out = hash.to_bytes();
        
        // Clear MSB and check if result is valid field element
        out[0] = 0;
        if bytes_lt_modulus(&out, &BN254_MODULUS_P) {
            return Ok((out, bump));
        }
    }
    
    Err(ProgramError::Custom(100)) // No valid bump found
}

fn bytes_lt_modulus(x: &[u8; 32], modulus: &[u8; 32]) -> bool {
    for i in 0..32 {
        if x[i] < modulus[i] {
            return true;
        }
        if x[i] > modulus[i] {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derive_nullifier_address_seed() {
        let nullifier = [0x42u8; 32];
        let pool = Pubkey::new_unique();
        
        let seed = derive_nullifier_address_seed(&nullifier, &pool);
        
        // Should be deterministic
        let seed2 = derive_nullifier_address_seed(&nullifier, &pool);
        assert_eq!(seed, seed2);
        
        // Different nullifier = different seed
        let different_nullifier = [0x43u8; 32];
        let seed3 = derive_nullifier_address_seed(&different_nullifier, &pool);
        assert_ne!(seed, seed3);
    }
    
    #[test]
    fn test_derive_address() {
        let seed = [0x42u8; 32];
        let tree = Pubkey::new_unique();
        
        let result = derive_address(&seed, &tree);
        assert!(result.is_ok());
        
        let (address, _bump) = result.unwrap();
        // MSB should be cleared
        assert_eq!(address[0], 0);
    }
    
    #[test]
    fn test_compressed_proof_from_bytes() {
        let mut data = [0u8; 128];
        data[0] = 1;  // a
        data[32] = 2; // b
        data[96] = 3; // c
        
        let proof = CompressedProof::from_bytes(&data).unwrap();
        assert_eq!(proof.a[0], 1);
        assert_eq!(proof.b[0], 2);
        assert_eq!(proof.c[0], 3);
    }
}

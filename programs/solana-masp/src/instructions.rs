//! MASP instruction handlers
//!
//! ## Architecture: Program vs Indexer Responsibilities
//!
//! The program does NOT maintain the full Merkle tree. Instead:
//! - **Indexer** maintains the tree off-chain and provides membership witnesses
//! - **Program** validates anchors (roots) and creates nullifier PDAs
//!
//! See `state.rs` for detailed architecture documentation.
//!
//! ## Instructions
//!
//! 0. Initialize - Create tree state and pool accounts
//! 1. InitProofBuffer - Create buffer for proof upload
//! 2. UploadChunk - Upload proof data in chunks
//! 3. Shield - Deposit tokens into shielded pool
//! 4. Transfer - Move value between shielded notes
//! 5. Unshield - Withdraw tokens from shielded pool
//! 6. UpdateRoot - Update the commitment tree root (called by indexer/relayer)

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

use crate::verify::{ProofSystem, CURRENT_PROOF_SYSTEM};

// Re-export instruction data types from shared protocol crate
pub use masp_protocol::{ShieldData, TransferData, UnshieldData};

/// System program ID (11111111111111111111111111111111)
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]);

/// Create a CreateAccount instruction for the System program
///
/// In solana-program v3.x, system_instruction is in a separate crate.
/// We inline the instruction construction to avoid the dependency.
pub fn create_account_instruction(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> solana_program::instruction::Instruction {
    solana_program::instruction::Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            solana_program::instruction::AccountMeta::new(*from_pubkey, true),
            solana_program::instruction::AccountMeta::new(*to_pubkey, true),
        ],
        data: {
            // SystemInstruction::CreateAccount { lamports, space, owner }
            // Discriminant: 0 (CreateAccount)
            let mut data = vec![0u8; 4 + 8 + 8 + 32];
            data[0..4].copy_from_slice(&0u32.to_le_bytes()); // CreateAccount = 0
            data[4..12].copy_from_slice(&lamports.to_le_bytes());
            data[12..20].copy_from_slice(&space.to_le_bytes());
            data[20..52].copy_from_slice(owner.as_ref());
            data
        },
    }
}

use crate::error::MaspError;
use crate::state::{BufferStatus, CircuitType, ProofBufferHeader, TreeState, PROOF_SIZE};
use crate::verify;

// =============================================================================
// Instruction Discriminators
// =============================================================================

pub const IX_INITIALIZE: u8 = 0;
pub const IX_INIT_PROOF_BUFFER: u8 = 1;
pub const IX_UPLOAD_CHUNK: u8 = 2;
pub const IX_SHIELD: u8 = 3;
pub const IX_TRANSFER: u8 = 4;
pub const IX_UNSHIELD: u8 = 5;
/// Ciphertext posting (Tx A in two-tx model) - data carrier only, no state changes
pub const IX_POST_CIPHERTEXTS: u8 = 7;

/// Update root instruction discriminator.
///
/// ⚠️ LOCAL TESTING ONLY - This instruction is feature-gated behind `local-testing`.
/// In production, root updates come from Light Protocol or external indexer,
/// NOT from this instruction.
#[cfg(feature = "local-testing")]
pub const IX_UPDATE_ROOT: u8 = 6;

// =============================================================================
// Initialize
// =============================================================================

/// Initialize the MASP tree state
///
/// Accounts:
/// 0. [signer] Authority (pays for account creation)
/// 1. [writable] Tree state PDA (to be created)
/// 2. [] System program
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let tree_state_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Verify authority is signer
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive tree state PDA
    let (tree_state_pda, bump) = Pubkey::find_program_address(TreeState::SEEDS, program_id);
    if tree_state_account.key != &tree_state_pda {
        msg!("Invalid tree state PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check not already initialized
    if !tree_state_account.data_is_empty() {
        return Err(MaspError::AlreadyInitialized.into());
    }

    // Create the tree state account
    let rent = Rent::get()?;
    let space = TreeState::SIZE;
    let lamports = rent.minimum_balance(space);

    let seeds_with_bump: &[&[u8]] = &[b"masp", b"state", &[bump]];

    invoke_signed(
        &create_account_instruction(
            authority.key,
            tree_state_account.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[
            authority.clone(),
            tree_state_account.clone(),
            system_program.clone(),
        ],
        &[seeds_with_bump],
    )?;

    // Initialize tree state
    let state = TreeState::new(*authority.key);
    state.serialize(&mut *tree_state_account.try_borrow_mut_data()?)?;

    msg!("MASP: Initialized tree state");
    Ok(())
}

// =============================================================================
// Init Proof Buffer
// =============================================================================

/// Initialize a proof buffer for uploading proof data
///
/// Accounts:
/// 0. [signer, writable] Payer
/// 1. [writable] Buffer account (to be created)
/// 2. [] System program
///
/// Data:
/// - [0]: circuit_type (0=shield, 1=transfer, 2=unshield)
/// - [1]: pi_count (number of public inputs)
pub fn process_init_proof_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let payer = next_account_info(accounts_iter)?;
    let buffer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let circuit_type = data[0];
    let pi_count = data[1];

    // Validate circuit type
    CircuitType::try_from(circuit_type).map_err(|_| MaspError::InvalidInstruction)?;

    // Calculate buffer size: header + (pi_count * 32) + proof
    let pi_bytes = (pi_count as usize) * 32;
    let buffer_size = ProofBufferHeader::SIZE + pi_bytes + PROOF_SIZE;

    // Create buffer account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(buffer_size);

    invoke_signed(
        &create_account_instruction(
            payer.key,
            buffer.key,
            lamports,
            buffer_size as u64,
            program_id,
        ),
        &[payer.clone(), buffer.clone(), system_program.clone()],
        &[], // No PDA seeds - buffer is a regular account
    )?;

    // Initialize header
    let mut buffer_data = buffer.try_borrow_mut_data()?;
    // Canonical header layout (matches verifier + inputs parsing):
    // [status(1), circuit_type(1), data_len(2), pi_count(1)]
    buffer_data[0] = BufferStatus::Incomplete as u8;
    buffer_data[1] = circuit_type;
    buffer_data[2] = 0; // data_len low byte
    buffer_data[3] = 0; // data_len high byte
    buffer_data[4] = pi_count;

    msg!(
        "MASP: Initialized proof buffer for circuit {} with {} public inputs",
        circuit_type,
        pi_count
    );
    Ok(())
}

// =============================================================================
// Upload Chunk
// =============================================================================

/// Upload a chunk of proof data
///
/// Accounts:
/// 0. [writable] Buffer account
///
/// Data:
/// - [0..2]: offset (u16 LE)
/// - [2..]: chunk data
pub fn process_upload_chunk(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let buffer = next_account_info(accounts_iter)?;

    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let offset = u16::from_le_bytes([data[0], data[1]]) as usize;
    let chunk = &data[2..];

    let mut buffer_data = buffer.try_borrow_mut_data()?;

    // Check status
    if buffer_data[0] != BufferStatus::Incomplete as u8 {
        msg!("Buffer not in incomplete state");
        return Err(MaspError::AlreadyInitialized.into());
    }

    // Write chunk after header
    let data_start = ProofBufferHeader::SIZE + offset;
    let data_end = data_start + chunk.len();

    if data_end > buffer_data.len() {
        msg!("Chunk would overflow buffer");
        return Err(ProgramError::InvalidInstructionData);
    }

    buffer_data[data_start..data_end].copy_from_slice(chunk);

    // Update data length
    let new_len = offset + chunk.len();
    // Header bytes [2..4] are data_len (u16 LE) in the canonical layout.
    buffer_data[2] = (new_len & 0xff) as u8;
    buffer_data[3] = ((new_len >> 8) & 0xff) as u8;

    msg!("MASP: Uploaded {} bytes at offset {}", chunk.len(), offset);
    Ok(())
}

// =============================================================================
// Shield
// =============================================================================

/// Shield - Deposit tokens into shielded pool
///
/// Accounts:
/// 0. [signer] Depositor
/// 1. [writable] Tree state PDA
/// 2. [readable] Proof buffer (with verified proof)
/// 3. [] Commitment store program (when simple-onchain-store feature)
/// 4. [writable] Commitment store state PDA (when simple-onchain-store feature)
/// 5. [] Verifier program (for UltraPlonk CPI)
pub fn process_shield(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    use crate::inputs::ShieldInputs;

    #[cfg(feature = "cu-log")]
    solana_program::log::sol_log_compute_units();

    let accounts_iter = &mut accounts.iter();
    let depositor = next_account_info(accounts_iter)?;
    let tree_state_account = next_account_info(accounts_iter)?;
    let proof_buffer = next_account_info(accounts_iter)?;

    // Store accounts (when simple-onchain-store feature enabled)
    #[cfg(feature = "simple-onchain-store")]
    let store_program = next_account_info(accounts_iter)?;
    #[cfg(feature = "simple-onchain-store")]
    let store_state = next_account_info(accounts_iter)?;

    if !depositor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data (needed for inline mode, optional for buffer mode)
    let shield_data = ShieldData::try_from_slice(data)?;

    // Verify tree state PDA
    let (tree_state_pda, _bump) = Pubkey::find_program_address(TreeState::SEEDS, program_id);
    if tree_state_account.key != &tree_state_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Load tree state
    let mut tree_state = TreeState::try_from_slice(&tree_state_account.try_borrow_data()?)?;

    if tree_state.paused {
        msg!("MASP is paused");
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate circuit type in buffer
    {
        let buffer_data = proof_buffer.try_borrow_data()?;
        let circuit_type = buffer_data[1];
        if circuit_type != CircuitType::Shield as u8 {
            msg!(
                "Wrong circuit type in buffer: got {}, expected {}",
                circuit_type,
                CircuitType::Shield as u8
            );
            return Err(MaspError::InvalidProofData.into());
        }
    }

    // Extract public inputs from buffer or instruction data based on proof system
    // This is the single source of truth for state updates
    let inputs = ShieldInputs::extract(proof_buffer, &shield_data)?;

    #[cfg(feature = "cu-log")]
    {
        msg!("CU: before verify_shield");
        solana_program::log::sol_log_compute_units();
    }

    // Verify proof based on proof system
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => {
            // Buffer mode: PIs are in the buffer, same bytes we extracted above
            let verifier_program = next_account_info(accounts_iter)?;
            verify::verify_proof(verify::ProofSource::Buffer {
                verifier_program,
                payer: depositor,
                proof_buffer,
            })?;
        }
        _ => {
            // Inline mode: use instruction data for PIs
            let public_inputs = inputs.to_public_inputs();
            let buffer_data = proof_buffer.try_borrow_data()?;
            const HEADER_SIZE: usize = 5;
            let pi_count = buffer_data[4] as usize;
            let proof_start = HEADER_SIZE + pi_count * 32;
            let proof_end = proof_start + PROOF_SIZE;
            if proof_end > buffer_data.len() {
                return Err(MaspError::BufferIncomplete.into());
            }
            let proof_bytes = &buffer_data[proof_start..proof_end];
            verify::verify_proof(verify::ProofSource::Bytes {
                circuit_type: CircuitType::Shield,
                public_inputs: &public_inputs,
                proof_bytes,
            })?;
        }
    }

    #[cfg(feature = "cu-log")]
    {
        msg!("CU: after verify_shield");
        solana_program::log::sol_log_compute_units();
    }

    // TODO: Execute SPL token transfer from depositor to pool
    // spl_token::instruction::transfer(...)

    // Insert commitment into the Merkle tree
    {
        use crate::stores::commitment_store;
        #[cfg(feature = "simple-onchain-store")]
        commitment_store::insert(store_program, store_state, depositor, inputs.commitment)?;
        #[cfg(not(feature = "simple-onchain-store"))]
        commitment_store::insert(depositor, inputs.commitment)?;
    }

    // Update MASP's tree state - increment leaf count
    tree_state
        .increment_leaf_count()
        .map_err(|_| MaspError::Overflow)?;

    // Serialize updated state
    tree_state.serialize(&mut *tree_state_account.try_borrow_mut_data()?)?;

    msg!("MASP: Shield - commitment {:?}", inputs.commitment);
    Ok(())
}

// =============================================================================
// Transfer
// =============================================================================

/// Transfer - Move value between shielded notes
///
/// Accounts:
/// 0. [signer] Relayer/user
/// 1. [writable] Tree state PDA
/// 2. [readable] Proof buffer
/// 3. [] System program
/// 4. [] Commitment store program (when simple-onchain-store feature)
/// 5. [writable] Commitment store state PDA (when simple-onchain-store feature)
/// N. [] Verifier program (for UltraPlonk CPI)
/// N+1..M. [writable] Nullifier PDAs (to be created)
pub fn process_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    use crate::inputs::TransferInputs;

    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let tree_state_account = next_account_info(accounts_iter)?;
    let proof_buffer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Store accounts (when simple-onchain-store feature enabled)
    #[cfg(feature = "simple-onchain-store")]
    let store_program = next_account_info(accounts_iter)?;
    #[cfg(feature = "simple-onchain-store")]
    let store_state = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data (needed for inline mode, optional for buffer mode)
    let transfer_data = TransferData::try_from_slice(data)?;

    // Verify tree state PDA
    let (tree_state_pda, _bump) = Pubkey::find_program_address(TreeState::SEEDS, program_id);
    if tree_state_account.key != &tree_state_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Load tree state
    let mut tree_state = TreeState::try_from_slice(&tree_state_account.try_borrow_data()?)?;

    if tree_state.paused {
        msg!("MASP is paused");
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate circuit type in buffer
    {
        let buffer_data = proof_buffer.try_borrow_data()?;
        let circuit_type = buffer_data[1];
        if circuit_type != CircuitType::Transfer as u8 {
            msg!(
                "Wrong circuit type in buffer: got {}, expected {}",
                circuit_type,
                CircuitType::Transfer as u8
            );
            return Err(MaspError::InvalidProofData.into());
        }
    }

    // Extract public inputs from buffer or instruction data based on proof system
    let inputs = TransferInputs::extract(proof_buffer, &transfer_data)?;

    // Validate anchor (using extracted inputs)
    if !tree_state.is_valid_anchor(&inputs.anchor) {
        return Err(MaspError::InvalidAnchor.into());
    }

    // Verify proof based on proof system
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => {
            let verifier_program = next_account_info(accounts_iter)?;
            verify::verify_proof(verify::ProofSource::Buffer {
                verifier_program,
                payer: authority,
                proof_buffer,
            })?;
        }
        _ => {
            let public_inputs = inputs.to_public_inputs();
            let buffer_data = proof_buffer.try_borrow_data()?;
            const HEADER_SIZE: usize = 5;
            let pi_count = buffer_data[4] as usize;
            let proof_start = HEADER_SIZE + pi_count * 32;
            let proof_end = proof_start + PROOF_SIZE;
            if proof_end > buffer_data.len() {
                return Err(MaspError::BufferIncomplete.into());
            }
            let proof_bytes = &buffer_data[proof_start..proof_end];
            verify::verify_proof(verify::ProofSource::Bytes {
                circuit_type: CircuitType::Transfer,
                public_inputs: &public_inputs,
                proof_bytes,
            })?;
        }
    }

    // Mark nullifiers as spent (double-spend prevention)
    for i in 0..inputs.input_count as usize {
        let nullifier = &inputs.nullifiers[i];

        // Skip zero nullifiers (disabled inputs)
        if nullifier == &[0u8; 32] {
            continue;
        }

        // Get nullifier account from remaining accounts
        let nullifier_account = next_account_info(accounts_iter)?;

        // Use nullifier store abstraction
        use crate::stores::nullifier_store;
        #[cfg(feature = "simple-onchain-store")]
        nullifier_store::insert(
            store_program,
            authority,
            nullifier_account,
            system_program,
            *nullifier,
        )?;
        #[cfg(not(feature = "simple-onchain-store"))]
        nullifier_store::insert(
            authority,
            nullifier_account,
            system_program,
            *nullifier,
            program_id,
        )?;
    }

    // Insert output commitments into the Merkle tree
    for i in 0..inputs.output_count as usize {
        let commitment = &inputs.output_commitments[i];
        if commitment != &[0u8; 32] {
            use crate::stores::commitment_store;
            #[cfg(feature = "simple-onchain-store")]
            commitment_store::insert(store_program, store_state, authority, *commitment)?;
            #[cfg(not(feature = "simple-onchain-store"))]
            commitment_store::insert(authority, *commitment)?;

            // Update MASP's tree state
            tree_state
                .increment_leaf_count()
                .map_err(|_| MaspError::Overflow)?;

            msg!("MASP: Transfer output {} - commitment {:?}", i, commitment);
        }
    }

    // Serialize updated state
    tree_state.serialize(&mut *tree_state_account.try_borrow_mut_data()?)?;

    msg!(
        "MASP: Transfer - {} inputs, {} outputs",
        inputs.input_count,
        inputs.output_count
    );
    Ok(())
}

// =============================================================================
// Unshield
// =============================================================================

/// Unshield - Withdraw tokens from shielded pool
///
/// Accounts:
/// 0. [signer] Relayer/user
/// 1. [writable] Tree state PDA
/// 2. [readable] Proof buffer
/// 3. [writable] Nullifier PDA (to be created)
/// 4. [] System program
/// 5. [] Store program (when simple-onchain-store feature)
/// 6. [] Verifier program (for UltraPlonk CPI)
pub fn process_unshield(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    use crate::inputs::UnshieldInputs;

    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let tree_state_account = next_account_info(accounts_iter)?;
    let proof_buffer = next_account_info(accounts_iter)?;
    let nullifier_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Store program (when simple-onchain-store feature enabled)
    #[cfg(feature = "simple-onchain-store")]
    let store_program = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data (needed for inline mode, optional for buffer mode)
    let unshield_data = UnshieldData::try_from_slice(data)?;

    // Verify tree state PDA
    let (tree_state_pda, _bump) = Pubkey::find_program_address(TreeState::SEEDS, program_id);
    if tree_state_account.key != &tree_state_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Load tree state
    let tree_state = TreeState::try_from_slice(&tree_state_account.try_borrow_data()?)?;

    if tree_state.paused {
        msg!("MASP is paused");
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate circuit type in buffer
    {
        let buffer_data = proof_buffer.try_borrow_data()?;
        let circuit_type = buffer_data[1];
        if circuit_type != CircuitType::Unshield as u8 {
            msg!(
                "Wrong circuit type in buffer: got {}, expected {}",
                circuit_type,
                CircuitType::Unshield as u8
            );
            return Err(MaspError::InvalidProofData.into());
        }
    }

    // Extract public inputs from buffer or instruction data based on proof system
    let inputs = UnshieldInputs::extract(proof_buffer, &unshield_data)?;

    // Validate anchor (using extracted inputs)
    if !tree_state.is_valid_anchor(&inputs.anchor) {
        return Err(MaspError::InvalidAnchor.into());
    }

    // Verify proof based on proof system
    match CURRENT_PROOF_SYSTEM {
        ProofSystem::UltraPlonk => {
            let verifier_program = next_account_info(accounts_iter)?;
            verify::verify_proof(verify::ProofSource::Buffer {
                verifier_program,
                payer: authority,
                proof_buffer,
            })?;
        }
        _ => {
            let public_inputs = inputs.to_public_inputs();
            let buffer_data = proof_buffer.try_borrow_data()?;
            const HEADER_SIZE: usize = 5;
            let pi_count = buffer_data[4] as usize;
            let proof_start = HEADER_SIZE + pi_count * 32;
            let proof_end = proof_start + PROOF_SIZE;
            if proof_end > buffer_data.len() {
                return Err(MaspError::BufferIncomplete.into());
            }
            let proof_bytes = &buffer_data[proof_start..proof_end];
            verify::verify_proof(verify::ProofSource::Bytes {
                circuit_type: CircuitType::Unshield,
                public_inputs: &public_inputs,
                proof_bytes,
            })?;
        }
    }

    // Mark nullifier as spent
    let nullifier = &inputs.nullifier;
    {
        use crate::stores::nullifier_store;
        #[cfg(feature = "simple-onchain-store")]
        nullifier_store::insert(
            store_program,
            authority,
            nullifier_account,
            system_program,
            *nullifier,
        )?;
        #[cfg(not(feature = "simple-onchain-store"))]
        nullifier_store::insert(
            authority,
            nullifier_account,
            system_program,
            *nullifier,
            program_id,
        )?;
    }

    // TODO: Execute SPL token transfer from pool to recipient
    // Amount and recipient available in inputs.amount and inputs.recipient()

    msg!("MASP: Unshield successful - {} tokens", inputs.amount);
    Ok(())
}

// =============================================================================
// UpdateRoot - LOCAL TESTING ONLY
// =============================================================================
//
// ⚠️ WARNING: This instruction is for LOCAL TESTING ONLY.
//
// It is feature-gated behind `local-testing` and MUST NOT be enabled in
// production deployments. In production, root updates come from:
// - Light Protocol (with validity proofs)
// - External trusted indexer with proper authorization
//
// This instruction exists to support Mode A (Local Indexer) testing where
// the client/indexer updates the tree root directly.

/// Update root instruction data
///
/// ⚠️ LOCAL TESTING ONLY - gated behind `local-testing` feature.
#[cfg(feature = "local-testing")]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UpdateRootData {
    /// New Merkle root to add to history
    pub new_root: [u8; 32],

    /// Expected leaf count after this update
    /// Used for consistency check (indexer and program agree on state)
    pub expected_leaf_count: u64,
}

/// Update the commitment tree root
///
/// ⚠️ LOCAL TESTING ONLY - This instruction is feature-gated behind `local-testing`.
/// DO NOT enable in production deployments!
///
/// This instruction is called by the indexer/relayer after inserting new
/// commitments into the off-chain Merkle tree. The program validates:
/// 1. Authority matches the tree state authority
/// 2. Expected leaf count matches (consistency check)
///
/// Then adds the new root to the anchor history.
///
/// ## Production Alternative
///
/// In production, use one of:
/// - Light Protocol integration (proves correctness via validity proofs)
/// - Multisig-controlled root updates
/// - Governance-controlled updates
///
/// Accounts:
/// 0. [signer] Authority (must match tree state authority)
/// 1. [writable] Tree state PDA
#[cfg(feature = "local-testing")]
pub fn process_update_root(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let tree_state_account = next_account_info(accounts_iter)?;

    // Parse instruction data
    let update_data =
        UpdateRootData::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    // Verify authority is signer
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify tree state PDA
    let (expected_state_pda, _bump) = Pubkey::find_program_address(TreeState::SEEDS, program_id);

    if tree_state_account.key != &expected_state_pda {
        msg!("Invalid tree state PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Load and verify tree state
    let mut tree_state = TreeState::try_from_slice(&tree_state_account.data.borrow())
        .map_err(|_| MaspError::InvalidAccountData)?;

    // Verify authority matches
    if authority.key != &tree_state.authority {
        msg!(
            "Authority mismatch: expected {}, got {}",
            tree_state.authority,
            authority.key
        );
        return Err(MaspError::InvalidAuthority.into());
    }

    // Verify leaf count consistency (optional but recommended)
    // The indexer should know how many leaves are in the tree
    if update_data.expected_leaf_count != tree_state.leaf_count {
        msg!(
            "Leaf count mismatch: expected {}, got {}",
            update_data.expected_leaf_count,
            tree_state.leaf_count
        );
        return Err(MaspError::StateInconsistency.into());
    }

    // Update the root (adds current root to history, sets new root)
    tree_state.update_root(update_data.new_root);

    // Save updated state
    tree_state.serialize(&mut *tree_state_account.try_borrow_mut_data()?)?;

    msg!(
        "MASP[local-testing]: Root updated. New root: {:?}... Leaf count: {}",
        &update_data.new_root[..4],
        tree_state.leaf_count
    );
    Ok(())
}

// ============================================================================
// Ciphertext Posting (Tx A in Two-TX Model)
// ============================================================================

/// Process ciphertext posting instruction (Tx A).
///
/// This is a **data carrier** instruction - it does NOT modify program state.
/// The ciphertext bytes are stored in the ledger for data availability (DA).
/// Recipients discover these transactions via the tx_sig shared out-of-band.
///
/// ## Security Model
///
/// This instruction intentionally has no authorization requirements:
/// - Anyone can post arbitrary ciphertext bytes
/// - The bytes are not validated or parsed
/// - Security comes from cryptographic binding in Tx B:
///   - Tx B's public inputs include `ct_hash` (hash of ciphertext bytes)
///   - The ZK proof binds the note to this `ct_hash`
///   - Recipients verify `ct_hash` matches the ciphertext they received
///
/// ## Format
///
/// Instruction data after discriminator:
/// - 1 byte: count (number of ciphertexts, 1-3)
/// - Variable: packed ciphertexts (each prefixed with u16 LE length)
///
/// No accounts required beyond the payer (for transaction fees).
pub fn process_post_ciphertexts(_data: &[u8]) -> ProgramResult {
    // This is purely a data carrier - no state changes, no validation.
    // The ciphertext bytes are now in the ledger history.
    //
    // In production, we could add:
    // - CU logging for analytics
    // - Basic format validation (optional)
    // - Rate limiting via account requirements
    //
    // For now, we just accept any bytes.
    #[cfg(feature = "cu-log")]
    {
        msg!("MASP: PostCiphertexts - data carrier (no state change)");
    }

    Ok(())
}

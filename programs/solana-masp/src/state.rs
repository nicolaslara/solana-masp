//! MASP on-chain state
//!
//! ## Architecture: Program vs Indexer Responsibilities
//!
//! ### Program Responsibilities (on-chain)
//!
//! 1. **Verify ZK proofs** - Shield, Transfer, Unshield circuits
//! 2. **Validate anchors** - Check proof anchor is in recent root history
//! 3. **Prevent double-spending** - Create/Check nullifiers (existence = spent)
//! 4. **Execute token transfers** - SPL token deposits/withdrawals
//! 5. **Emit events** - Commitment/nullifier data for indexers to observe
//!
//!
//! ### Indexer Responsibilities (off-chain, for performance)
//!
//! 1. **Maintain Merkle tree** - Full tree with all commitments (faster than on-chain)
//! 2. **Provide membership witnesses** - Merkle paths for spending
//! 3. **Index ciphertexts** - For efficient trial decryption / note discovery
//! 4. **Submit root updates** - To program after commitment inserts (via CPI or instruction)
//!
//! ### External Store Abstraction (Two Separate Stores)
//!
//! The MASP program delegates state storage to **two separate external stores**:
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │                         MASP Program                               │
//! │  - Verify ZK proofs                                                │
//! │  - SPL token transfers                                             │
//! │  - CPI to external stores                                          │
//! └─────────────────────┬───────────────────────┬─────────────────────┘
//!                       │ CPI                   │ CPI
//!                       ▼                       ▼
//!         ┌─────────────────────────┐  ┌─────────────────────────┐
//!         │  NoteCommitmentStore    │  │      NullifierSet        │
//!         │  (membership proofs)    │  │  (non-membership proofs) │
//!         └─────────────────────────┘  └─────────────────────────┘
//!                       │                       │
//!          ┌────────────┴────────────┐  ┌───────┴───────────────┐
//!          ▼                         ▼  ▼                       ▼
//!   ┌───────────────┐    ┌───────────────┐   ┌───────────────┐
//!   │ MockStore     │    │ Light Protocol│   │ Light Protocol│
//!   │ (PDAs, naive) │    │ (compressed)  │   │ (compressed)  │
//!   └───────────────┘    └───────────────┘   └───────────────┘
//! ```
//!
//! #### NoteCommitmentStore
//! - Stores note commitments in a Merkle tree
//! - Provides membership witnesses (Merkle paths or validity proofs)
//! - Mock: Naive on-chain Merkle tree
//! - Production: Light Protocol compressed accounts with validity proofs
//!
//! #### NullifierSet
//! - Stores spent nullifiers for double-spend prevention
//! - Provides non-membership proofs (prove nullifier doesn't exist → insert)
//! - Mock: Naive on-chain set (PDAs, existence = spent)
//! - Production: Light Protocol compressed accounts with non-membership proofs
//!
//! #### Why Two Separate Stores?
//! - Different proof types: membership vs non-membership
//! - Matches `client/src/traits.rs` architecture (`NoteCommitmentStore` + `NullifierSet`)
//! - Cleaner separation of concerns
//! - Light Protocol may use different trees for each
//!
//! ### Current Implementation (Milestone 1)
//!
//! For initial testing, nullifiers are stored directly by MASP as simple PDAs.
//! This will be refactored to use the external store abstraction in Milestone 4
//! (Light Protocol integration).
//!
//! ## State Model (Milestone 1 - will be refactored)
//!
//! ⚠️ **NOTE**: This is a temporary Milestone 1 implementation.
//! In Milestone 4, state will move to external stores (Light Protocol).
//!
//! ### Program-Owned State
//!
//! 1. **TreeState** - Main program state (single PDA)
//!    - Anchor history (ring buffer of recent roots)
//!    - Leaf count (for tracking; tree itself is off-chain)
//!    - Seed: ["masp", "state"]
//!
//! 2. **PoolTokenAccount** - SPL token accounts owned by the program
//!    - One per supported token (derived from mint)
//!    - Seed: ["pool", mint_pubkey]
//!
//! 3. **ProofBuffer** - Temporary account for proof upload
//!    - Created per transaction, closed after verification
//!    - Holds proof bytes (too large for single TX instruction data)
//!
//! ### Temporary State (Milestone 1 only - will move to external stores)
//!
//! 4. **NullifierAccount** - ⚠️ TEMPORARY: PDA per nullifier (Milestone 1)
//!    - Existence = spent; absence = unspent
//!    - Seed: ["nullifier", nullifier_bytes]
//!    - **Production**: Will use NullifierSet with non-membership proofs

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

// =============================================================================
// Constants
// =============================================================================

/// Tree depth (32 levels = 2^32 leaves max)
pub const TREE_DEPTH: usize = 32;

/// Number of recent anchors to keep in history
/// (Allows transactions in-flight to use slightly stale roots)
pub const ANCHOR_HISTORY_SIZE: usize = 16;

/// Maximum proof buffer size: header + public inputs + proof
/// Header: 5 bytes, Max PI: 16 * 32 = 512, Max Proof: 2144 (UltraPlonk)
/// Note: This is the maximum across all proof systems.
pub const MAX_PROOF_BUFFER_SIZE: usize = 5 + 512 + 2144;

/// Proof size (depends on proof system at compile time)
/// UltraPlonk: 2144 bytes
/// Groth16: 192 bytes
/// Mock: 32 bytes
#[cfg(all(feature = "local-testing", feature = "mock-proofs"))]
pub const PROOF_SIZE: usize = 32;

#[cfg(not(all(feature = "local-testing", feature = "mock-proofs")))]
pub const PROOF_SIZE: usize = 2144; // UltraPlonk (default)

/// Maximum public inputs per circuit
pub const MAX_PUBLIC_INPUTS: usize = 16;

// =============================================================================
// TreeState - Main program state
// =============================================================================

/// Main MASP state account
///
/// Note: This does NOT store the full Merkle tree. The tree is maintained
/// off-chain by the indexer. This account only tracks:
/// - Recent roots (anchor history) for anchor validation
/// - Leaf count (for tracking; not authoritative)
///
/// The ZK proof binds to an anchor (root). The program validates the anchor
/// is in recent history. The indexer maintains the full tree and provides
/// membership witnesses (Merkle paths) for spending.
///
/// PDA seeds: ["masp", "state"]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct TreeState {
    /// Magic/version byte for account validation
    pub version: u8,

    /// Current Merkle root (latest anchor)
    pub current_root: [u8; 32],

    /// Number of leaves (commitments) in tree
    pub leaf_count: u64,

    /// Ring buffer of recent roots for anchor validation
    /// Allows transactions to verify against slightly stale roots
    pub anchor_history: [[u8; 32]; ANCHOR_HISTORY_SIZE],

    /// Index of next slot in anchor history ring buffer
    pub anchor_history_index: u8,

    /// Authority that can pause/upgrade (optional governance)
    pub authority: Pubkey,

    /// Whether the pool is paused
    pub paused: bool,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 64],
}

impl TreeState {
    /// Current version
    pub const VERSION: u8 = 1;

    /// Account size in bytes
    pub const SIZE: usize = 1 // version
        + 32 // current_root
        + 8 // leaf_count
        + (32 * ANCHOR_HISTORY_SIZE) // anchor_history
        + 1 // anchor_history_index
        + 32 // authority
        + 1 // paused
        + 64; // reserved

    /// Seeds for PDA derivation
    pub const SEEDS: &'static [&'static [u8]] = &[b"masp", b"state"];

    /// Create new tree state
    pub fn new(authority: Pubkey) -> Self {
        Self {
            version: Self::VERSION,
            current_root: empty_tree_root(),
            leaf_count: 0,
            anchor_history: [[0u8; 32]; ANCHOR_HISTORY_SIZE],
            anchor_history_index: 0,
            authority,
            paused: false,
            _reserved: [0u8; 64],
        }
    }

    /// Check if an anchor is valid (in recent history or current root)
    pub fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        // Check current root
        if anchor == &self.current_root {
            return true;
        }

        // Check history ring buffer
        for root in &self.anchor_history {
            if anchor == root {
                return true;
            }
        }

        false
    }

    /// Update root and push old root to history
    pub fn update_root(&mut self, new_root: [u8; 32]) {
        // Push current root to history before updating
        let idx = self.anchor_history_index as usize;
        self.anchor_history[idx] = self.current_root;
        self.anchor_history_index = ((idx + 1) % ANCHOR_HISTORY_SIZE) as u8;

        self.current_root = new_root;
    }

    /// Increment leaf count
    pub fn increment_leaf_count(&mut self) -> Result<u64, ()> {
        self.leaf_count = self.leaf_count.checked_add(1).ok_or(())?;
        Ok(self.leaf_count)
    }
}

// =============================================================================
// NullifierAccount - Spent nullifier marker
// =============================================================================

/// Marker account for spent nullifiers
///
/// Existence of this account = nullifier is spent.
/// PDA seeds: ["nullifier", nullifier_bytes]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct NullifierAccount {
    /// Magic/version byte
    pub version: u8,

    /// The nullifier value (redundant but useful for debugging)
    pub nullifier: [u8; 32],

    /// Slot when this nullifier was spent
    pub spent_slot: u64,
}

impl NullifierAccount {
    /// Current version
    pub const VERSION: u8 = 1;

    /// Account size
    pub const SIZE: usize = 1 + 32 + 8;

    /// Get PDA seeds for a nullifier
    pub fn seeds(nullifier: &[u8; 32]) -> Vec<Vec<u8>> {
        vec![b"nullifier".to_vec(), nullifier.to_vec()]
    }

    /// Create new nullifier account
    pub fn new(nullifier: [u8; 32], spent_slot: u64) -> Self {
        Self {
            version: Self::VERSION,
            nullifier,
            spent_slot,
        }
    }
}

// =============================================================================
// ProofBuffer - Temporary proof storage
// =============================================================================

/// Buffer status
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum BufferStatus {
    /// Buffer is being filled
    Incomplete = 0,
    /// Buffer is ready for verification
    Ready = 1,
    /// Buffer has been verified (can be closed)
    Verified = 2,
}

/// Proof buffer header
///
/// Layout (canonical, matches verifier + inputs parsing):
/// [status: u8][circuit_type: u8][data_len: u16 LE][pi_count: u8][...data...]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ProofBufferHeader {
    /// Buffer status
    pub status: u8,

    /// Circuit type (0=shield, 1=transfer, 2=unshield)
    pub circuit_type: u8,

    /// Current length of uploaded data (public inputs bytes + proof bytes uploaded so far)
    pub data_len: u16,

    /// Number of public inputs
    pub pi_count: u8,
}

impl ProofBufferHeader {
    /// Header size in bytes
    pub const SIZE: usize = 5;
}

/// Circuit types for VK selection
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CircuitType {
    Shield = 0,
    Transfer = 1,
    Unshield = 2,
}

impl TryFrom<u8> for CircuitType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CircuitType::Shield),
            1 => Ok(CircuitType::Transfer),
            2 => Ok(CircuitType::Unshield),
            _ => Err(()),
        }
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Compute the root of an empty tree (all zero leaves)
///
/// For a Poseidon-based Merkle tree with depth 32, this is computed by
/// hashing zeros up the tree. For now, we use a placeholder.
///
/// TODO: Compute actual empty tree root with Poseidon2
fn empty_tree_root() -> [u8; 32] {
    // Placeholder - in production, compute H(H(H(...H(0,0)...)))
    [0u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_state_size() {
        // Verify size calculation matches actual serialized size
        let state = TreeState::new(Pubkey::default());
        let serialized = borsh::to_vec(&state).unwrap();
        assert_eq!(serialized.len(), TreeState::SIZE);
    }

    #[test]
    fn test_anchor_history() {
        let mut state = TreeState::new(Pubkey::default());

        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let root3 = [3u8; 32];

        // Initial root is empty tree
        assert!(state.is_valid_anchor(&state.current_root));

        // Update to root1
        state.update_root(root1);
        assert!(state.is_valid_anchor(&root1));
        assert!(state.is_valid_anchor(&empty_tree_root())); // Old root in history

        // Update to root2
        state.update_root(root2);
        assert!(state.is_valid_anchor(&root2));
        assert!(state.is_valid_anchor(&root1)); // In history
        assert!(state.is_valid_anchor(&empty_tree_root())); // Still in history

        // Update to root3
        state.update_root(root3);
        assert!(state.is_valid_anchor(&root3));
        assert!(state.is_valid_anchor(&root2));
        assert!(state.is_valid_anchor(&root1));
    }

    #[test]
    fn test_nullifier_account_size() {
        let nf = NullifierAccount::new([0u8; 32], 12345);
        let serialized = borsh::to_vec(&nf).unwrap();
        assert_eq!(serialized.len(), NullifierAccount::SIZE);
    }
}

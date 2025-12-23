//! Mock Commitment Store state
//!
//! ⚠️ **FOR LOCAL TESTING ONLY**
//!
//! This is a naive implementation for testing. In production, use Light Protocol.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

// =============================================================================
// Constants
// =============================================================================

/// Tree depth (16 levels = 65536 leaves max for testing)
/// Production Light Protocol supports much larger trees.
pub const TREE_DEPTH: usize = 16;

/// Maximum leaves in tree
pub const MAX_LEAVES: u64 = 1 << TREE_DEPTH;

/// Number of recent anchors to keep
pub const ANCHOR_HISTORY_SIZE: usize = 16;

// =============================================================================
// Store State
// =============================================================================

/// Main store state account
///
/// ⚠️ This is a naive implementation. The Merkle tree is stored in a separate
/// account due to size constraints. This state just tracks metadata.
///
/// PDA seeds: ["mock_store", "state"]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct StoreState {
    /// Magic/version byte
    pub version: u8,

    /// Current Merkle root
    pub current_root: [u8; 32],

    /// Number of leaves (commitments) in tree
    pub leaf_count: u64,

    /// Ring buffer of recent roots for anchor validation
    pub anchor_history: [[u8; 32]; ANCHOR_HISTORY_SIZE],

    /// Index of next slot in anchor history
    pub anchor_history_index: u8,

    /// Authority that can manage the store
    pub authority: Pubkey,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 64],
}

impl StoreState {
    pub const VERSION: u8 = 1;

    pub const SIZE: usize = 1 // version
        + 32 // current_root
        + 8 // leaf_count
        + (32 * ANCHOR_HISTORY_SIZE) // anchor_history
        + 1 // anchor_history_index
        + 32 // authority
        + 64; // reserved

    pub const SEEDS: &'static [&'static [u8]] = &[b"mock_store", b"state"];

    pub fn new(authority: Pubkey) -> Self {
        Self {
            version: Self::VERSION,
            current_root: empty_tree_root(),
            leaf_count: 0,
            anchor_history: [[0u8; 32]; ANCHOR_HISTORY_SIZE],
            anchor_history_index: 0,
            authority,
            _reserved: [0u8; 64],
        }
    }

    /// Check if an anchor is valid (in recent history or current root)
    pub fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        if anchor == &self.current_root {
            return true;
        }

        for root in &self.anchor_history {
            if anchor == root {
                return true;
            }
        }

        false
    }

    /// Update root and push old root to history
    pub fn update_root(&mut self, new_root: [u8; 32]) {
        let idx = self.anchor_history_index as usize;
        self.anchor_history[idx] = self.current_root;
        self.anchor_history_index = ((idx + 1) % ANCHOR_HISTORY_SIZE) as u8;
        self.current_root = new_root;
    }

    /// Check if tree is full
    pub fn is_full(&self) -> bool {
        self.leaf_count >= MAX_LEAVES
    }
}

// =============================================================================
// Nullifier Account
// =============================================================================

/// Marker account for spent nullifiers
///
/// Existence of this account = nullifier is spent.
/// PDA seeds: ["nullifier", nullifier_bytes]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct NullifierAccount {
    pub version: u8,
    pub nullifier: [u8; 32],
    pub spent_slot: u64,
}

impl NullifierAccount {
    pub const VERSION: u8 = 1;
    pub const SIZE: usize = 1 + 32 + 8;

    pub fn seeds(nullifier: &[u8; 32]) -> Vec<Vec<u8>> {
        vec![b"nullifier".to_vec(), nullifier.to_vec()]
    }

    pub fn new(nullifier: [u8; 32], spent_slot: u64) -> Self {
        Self {
            version: Self::VERSION,
            nullifier,
            spent_slot,
        }
    }
}

// =============================================================================
// Merkle Tree Account (simplified)
// =============================================================================

/// Merkle tree data account
///
/// ⚠️ NAIVE IMPLEMENTATION: Stores all tree nodes on-chain.
/// This is expensive but simple for testing.
///
/// PDA seeds: ["mock_store", "tree"]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct MerkleTreeAccount {
    pub version: u8,

    /// Tree nodes: nodes[level][index]
    /// Level 0 = leaves, Level TREE_DEPTH = root
    /// Stored as flat array for simplicity
    pub nodes: Vec<[u8; 32]>,
}

impl MerkleTreeAccount {
    pub const VERSION: u8 = 1;
    pub const SEEDS: &'static [&'static [u8]] = &[b"mock_store", b"tree"];

    /// Calculate total nodes in tree
    pub const fn total_nodes() -> usize {
        // Sum of 2^i for i in 0..TREE_DEPTH = 2^(TREE_DEPTH+1) - 1
        (1 << (TREE_DEPTH + 1)) - 1
    }

    /// Calculate account size
    pub fn size() -> usize {
        1 + 4 + (Self::total_nodes() * 32) // version + vec len + nodes
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Compute the root of an empty tree
///
/// For a Poseidon-based tree, this would be computed properly.
/// For testing, we use zeros.
fn empty_tree_root() -> [u8; 32] {
    [0u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_state_size() {
        let state = StoreState::new(Pubkey::default());
        let serialized = borsh::to_vec(&state).unwrap();
        assert_eq!(serialized.len(), StoreState::SIZE);
    }

    #[test]
    fn test_anchor_history() {
        let mut state = StoreState::new(Pubkey::default());

        let root1 = [1u8; 32];
        let root2 = [2u8; 32];

        state.update_root(root1);
        assert!(state.is_valid_anchor(&root1));
        assert!(state.is_valid_anchor(&empty_tree_root())); // Old root in history

        state.update_root(root2);
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

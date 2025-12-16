# Light Protocol Integration Analysis

Based on [ZK Compression docs](https://www.zkcompression.com/compressed-pdas/create-a-program-with-compressed-pdas), [whitepaper](https://www.zkcompression.com/references/whitepaper), and [source code](https://github.com/Lightprotocol/light-protocol/blob/2ac09ccd724aa57938bd2ad5b1584636cbc6f7fb/program-libs/compressed-account/src/compressed_account.rs).

## Key Finding: Address CAN Be Set

From the Light Protocol source code, `CompressedAccount` has:

```rust
pub struct CompressedAccount {
    pub owner: Pubkey,          // Program that owns this account
    pub lamports: u64,          // Balance
    pub address: Option<[u8; 32]>,  // ← OPTIONAL address field!
    pub data: Option<CompressedAccountData>,
}

pub struct CompressedAccountData {
    pub discriminator: [u8; 8],
    pub data: Vec<u8>,
    pub data_hash: [u8; 32],  // ← Hash of data
}
```

**Critical insight:** The `address` field is **optional and can be set by the program!**

This means we can use **Scenario A**: `address = commitment`

## Account Hash Computation

From source, the account leaf hash is computed via Poseidon:

```rust
fn hash(&self, merkle_tree_pubkey: &[u8], leaf_index: &u32) -> [u8; 32] {
    let hash = Poseidon::hashv(&[
        &hashed_owner,       // owner pubkey (hashed to BN254)
        &leaf_index.to_le_bytes(),
        &merkle_tree_pubkey, // tree address (hashed to BN254)
        &data_hash,          // hash of account data
        &address,            // our address field!
        &lamports,
    ]);
}
```

**Important:** The leaf hash includes `leaf_index` and `merkle_tree_pubkey`, so:

- The full account hash is only known after insertion (includes position)
- But the **address** can be set beforehand!

## Our Strategy

### For Note Commitments

```
┌────────────────────────────────────────────────────────────────────┐
│  Create compressed account with:                                   │
│    address = commitment (our note commitment)                      │
│    data = {} (empty, or encrypted note if desired)                 │
│    owner = MASP program                                            │
│                                                                    │
│  Lookup: getCompressedAccount(address=commitment)                  │
│  Proof: getCompressedAccountProof(address=commitment)              │
└────────────────────────────────────────────────────────────────────┘
```

### For Nullifiers

Use Light Protocol's address tree for uniqueness:

```
┌────────────────────────────────────────────────────────────────────┐
│  Insert nullifier:                                                 │
│    Create compressed account with address = nullifier              │
│    If address already exists → AlreadySpent error                  │
│                                                                    │
│  Check spent:                                                      │
│    getCompressedAccount(address=nullifier) exists?                 │
└────────────────────────────────────────────────────────────────────┘
```

## Privacy Considerations

### What's Revealed

| Data                   | Privacy Level | Notes                           |
| ---------------------- | ------------- | ------------------------------- |
| `address` (commitment) | **Public**    | Commitment hides note contents  |
| `owner`                | **Public**    | = MASP program address          |
| `data`                 | **Public**    | Should be empty or encrypted    |
| `lamports`             | **Public**    | Can set to 0 for compressed     |
| Leaf hash              | **Public**    | Includes address                |
| Merkle path            | Via indexer   | Reveals which address you query |

### Privacy Tradeoffs

**Concern:** Querying `getCompressedAccountProof(commitment)` reveals which notes you might own.

**Mitigations:**

1. **Batch queries** - Request multiple proofs at once (some decoys)
2. **PIR** - Private Information Retrieval (future)
3. **Self-hosted indexer** - Run your own Helius-compatible node

**Key insight:** The commitment itself is privacy-preserving (hides note contents), so revealing it doesn't reveal value/recipient. But it does reveal _which notes you're interested in_.

## Implementation Plan

### Phase 1: Mock (Current)

```rust
// NoteCommitmentStore: identifier = commitment
// Uses in-memory Merkle tree
// MembershipWitness = MerklePath variant
```

### Phase 2: Light Protocol Integration

```rust
// NoteCommitmentStore: identifier = address = commitment
// Uses Light Protocol compressed accounts
// MembershipWitness = LightValidityProof variant
```

### Helius API Mapping

| Our Operation     | Helius/Light API                                            |
| ----------------- | ----------------------------------------------------------- |
| Insert commitment | Create compressed account with `address = commitment`       |
| Check exists      | `getCompressedAccount(address=commitment)`                  |
| Get witness       | `getCompressedAccountProof(address=commitment)`             |
| Batch proofs      | `getValidityProof(addresses=[...])`                         |
| Insert nullifier  | Create account with `address = nullifier` (fails if exists) |
| Check spent       | `getCompressedAccount(address=nullifier)` != null           |

## Open Questions (Resolved ✓)

- [x] Can we set address ourselves? **Yes** - address is optional field
- [x] What's dataHash? **Hash of account data** - separate from address
- [x] When is leaf hash computed? **On insertion** - includes leaf_index

## Remaining Questions

- [ ] What's the exact format for creating compressed accounts?
- [ ] How do we call Light Protocol from our Solana program?
- [ ] Cost comparison: compressed account vs PDA for nullifiers?
- [ ] What happens with concurrent insertions (same address)?

## Resources

- [Create a Program with Compressed PDAs](https://www.zkcompression.com/compressed-pdas/create-a-program-with-compressed-pdas)
- [Light Protocol Whitepaper](https://www.zkcompression.com/references/whitepaper)
- [Compressed Account Source](https://github.com/Lightprotocol/light-protocol/blob/main/program-libs/compressed-account/src/compressed_account.rs)
- [Program Examples](https://github.com/Lightprotocol/program-examples)

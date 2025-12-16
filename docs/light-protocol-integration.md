# Light Protocol Integration for MASP

This document describes how MASP integrates with Light Protocol for commitment storage and nullifier uniqueness.

## Key Insight: Hash-Based Identification

Light Protocol uses **data hashes** as identifiers, NOT positions:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Light Protocol Model                         │
├─────────────────────────────────────────────────────────────────┤
│  Account = { data, dataHash, leafIndex, tree, ... }             │
│                                                                 │
│  Primary key: hash (dataHash)                                   │
│  Secondary: leafIndex (position in tree)                        │
│                                                                 │
│  Lookup: getCompressedAccount(hash) → account data              │
│  Proof:  getCompressedAccountProof(hash) → merkle proof         │
└─────────────────────────────────────────────────────────────────┘
```

## MASP Flow with Light Protocol

### 1. Shield (Deposit)

```
Client                          Light/Chain                    Indexer
   │                                │                              │
   │  1. Create note               │                              │
   │  2. Compute commitment (cm)    │                              │
   │                                │                              │
   │  3. shield(cm, tokens)        │                              │
   │ ──────────────────────────────>│                              │
   │                                │                              │
   │                                │  4. Store cm in Light tree   │
   │                                │  5. Return tx_sig            │
   │ <──────────────────────────────│                              │
   │                                │                              │
   │  6. Store locally:             │                              │
   │     (note, cm, tx_sig)        │                              │
```

**What client stores after shield:**

- Note plaintext
- Commitment (cm) = hash = the identifier
- Transaction signature (for recovery)

### 2. Transfer (Spend + Output)

```
Client                          Helius RPC                     Chain
   │                                │                              │
   │  1. Know: cm (commitment)      │                              │
   │                                │                              │
   │  getCompressedAccountProof(cm) │                              │
   │ ──────────────────────────────>│                              │
   │ <──────────────────────────────│                              │
   │  { proof, root, leafIndex }    │                              │
   │                                │                              │
   │  2. Build ZK proof:            │                              │
   │     - Proves ownership (nk)    │                              │
   │     - Proves cm = H(note)      │                              │
   │     - Proves balance           │                              │
   │                                │                              │
   │  3. transfer(cm, lpProof, zkProof, nf, outputs)               │
   │ ─────────────────────────────────────────────────────────────>│
   │                                │                              │
   │                                │  4. Verify LP proof (cm in tree)
   │                                │  5. Verify ZK proof           │
   │                                │  6. Insert nf (uniqueness)    │
   │                                │  7. Insert output cms          │
   │                                │                              │
   │ <─────────────────────────────────────────────────────────────│
   │  (tx_sig, output_hashes)       │                              │
```

### 3. OOB Note Delivery

Sender tells recipient about payment:

```
Sender → Recipient (OOB channel):
{
  tx_sig: "abc123...",
  commitment: "def456...",    // This is the hash/identifier
  note_plaintext: {...},      // Encrypted or plain
}

Recipient verifies:
1. getCompressedAccount(commitment) → exists?
2. H(note_plaintext) == commitment?  → matches?
3. Store (note, commitment)
```

If recipient only has tx_sig (no commitment):

```
getTransactionWithCompressionInfo(tx_sig) → find commitment
```

## Helius API Mapping

| Our Operation        | Helius API                               | When                          |
| -------------------- | ---------------------------------------- | ----------------------------- |
| Get account data     | `getCompressedAccount(hash)`             | Verify note exists            |
| Get membership proof | `getCompressedAccountProof(hash)`        | Before spend                  |
| Get validity proof   | `getValidityProof(hashes[])`             | Batched proof for on-chain    |
| Find by tx           | `getTransactionWithCompressionInfo(sig)` | OOB recovery                  |
| Scan outputs         | `getCompressedAccountsByOwner(pubkey)`   | Won't work for us (encrypted) |

**Note:** `getCompressedAccountsByOwner` won't work for MASP because accounts are owned by the program, not users. We need ciphertext scanning instead.

## What We Submit to Program

```rust
struct TransferInstruction {
    // Input note membership
    input_commitment: [u8; 32],      // Hash = identifier
    light_validity_proof: Vec<u8>,   // From getValidityProof

    // Spend authorization
    nullifier: [u8; 32],
    zk_proof: Vec<u8>,               // UltraPlonk proof

    // Outputs
    output_commitments: Vec<[u8; 32]>,
    ciphertexts: Vec<Vec<u8>>,
}
```

**On-chain verification:**

1. Verify LP proof: `input_commitment` is in tree under `anchor`
2. Verify ZK proof: spender knows secret, balance correct
3. Insert `nullifier` via Light (uniqueness)
4. Insert `output_commitments` via Light

## Nullifier Uniqueness via Light Protocol

For nullifiers, we use Light's "address" mechanism:

```rust
// Conceptually:
fn insert_nullifier(nf: [u8; 32]) -> Result<(), AlreadyExists> {
    // Light enforces: can only create address once
    light_protocol::create_address(nf)?;
    Ok(())
}

fn is_nullifier_spent(nf: [u8; 32]) -> bool {
    // Check if address exists
    light_protocol::address_exists(nf)
}
```

## Local Mock Implementation

For testing before full Light Protocol integration:

```rust
struct MockLightState {
    // Commitment tree: hash → (data, leafIndex)
    commitments: HashMap<[u8; 32], (Vec<u8>, u64)>,

    // Merkle tree for proofs
    tree: InMemoryMerkleTree,

    // Nullifier set: hash → exists
    nullifiers: HashSet<[u8; 32]>,

    // Transaction log: tx_sig → hashes
    tx_log: HashMap<String, Vec<[u8; 32]>>,
}

impl MockLightState {
    fn insert_commitment(&mut self, cm: [u8; 32], data: Vec<u8>) -> u64 {
        let leaf_index = self.tree.append(cm);
        self.commitments.insert(cm, (data, leaf_index));
        leaf_index
    }

    fn get_proof(&self, cm: [u8; 32]) -> Option<LightProof> {
        let (_, leaf_index) = self.commitments.get(&cm)?;
        let merkle_proof = self.tree.get_witness(*leaf_index);
        Some(LightProof {
            hash: cm,
            leaf_index: *leaf_index,
            proof: merkle_proof.siblings,
            root: self.tree.root(),
        })
    }

    fn insert_nullifier(&mut self, nf: [u8; 32]) -> Result<(), AlreadySpent> {
        if self.nullifiers.contains(&nf) {
            return Err(AlreadySpent);
        }
        self.nullifiers.insert(nf);
        Ok(())
    }
}
```

## Identifier Strategy

| Approach              | Pros                                       | Cons                                            |
| --------------------- | ------------------------------------------ | ----------------------------------------------- |
| **Hash (commitment)** | Native to LP, immutable, content-addressed | Need to compute, store                          |
| Position (leafIndex)  | Simple integer                             | Can change with tree updates, not primary in LP |
| Transaction sig       | Easy to pass OOB                           | One tx can have multiple outputs                |

**Decision:** Use **commitment (hash)** as primary identifier:

- Matches Light Protocol's model
- Content-addressed (deterministic from note)
- Immutable once created
- Can always compute from note plaintext

Transaction signature is secondary:

- Used for OOB notification
- Used for recovery via `getTransactionWithCompressionInfo`
- Not the primary key

## Privacy Considerations

| Query                                    | What Helius Sees           | Mitigation                       |
| ---------------------------------------- | -------------------------- | -------------------------------- |
| `getCompressedAccountProof(hash)`        | Which hash you're proving  | PIR, batch queries               |
| `getTransactionWithCompressionInfo(sig)` | Which tx you're looking at | OOB should include hash directly |

**Key insight:** Since hash = commitment, and commitment hides note contents, revealing the hash doesn't reveal the note value or recipient.

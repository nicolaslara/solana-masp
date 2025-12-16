# MASP Data Structures

## Overview

The MASP uses two distinct on-chain data structures:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MASP State                                   │
├─────────────────────────────────┬───────────────────────────────────┤
│      Commitment Tree            │         Nullifier Set             │
│   (append-only Merkle tree)     │     (uniqueness structure)        │
├─────────────────────────────────┼───────────────────────────────────┤
│  Purpose: "Note exists"         │  Purpose: "Note not spent"        │
│  Proof: Membership              │  Proof: Non-membership / Insert   │
│  Operation: Append only         │  Operation: Insert once           │
│  Size: O(log n) per proof       │  Size: O(1) per check (with PDA)  │
└─────────────────────────────────┴───────────────────────────────────┘
```

---

## 1. Commitment Tree

### Purpose

Proves that a note **exists** (was created in some past transaction).

### Properties

- **Append-only**: New commitments added at next available position
- **Position**: Index where commitment was inserted (0, 1, 2, ...)
- **Immutable leaves**: Once added, never modified or removed
- **Deterministic root**: Root changes predictably with each append

### Operations

| Operation                               | Who              | When                    |
| --------------------------------------- | ---------------- | ----------------------- |
| **Append(cm)**                          | Chain (program)  | Shield, Transfer output |
| **GetWitness(pos)**                     | Indexer → Client | Before spending         |
| **VerifyMembership(cm, witness, root)** | Anyone           | Proof verification      |

### Why Append-Only Matters

```
Position 0: cm_a  ─┐
                   ├─► H(cm_a, cm_b) ─┐
Position 1: cm_b  ─┘                  │
                                      ├─► root
Position 2: cm_c  ─┐                  │
                   ├─► H(cm_c, 0)  ───┘
Position 3: (empty)┘

After inserting cm_d at position 3:

Position 0: cm_a  ─┐
                   ├─► H(cm_a, cm_b) ─┐
Position 1: cm_b  ─┘                  │
                                      ├─► root' (changed!)
Position 2: cm_c  ─┐                  │
                   ├─► H(cm_c, cm_d)──┘
Position 3: cm_d  ─┘
```

- Positions 0, 1, 2 have same witnesses (siblings unchanged)
- Position 3's witness is now valid
- Root changes, but old roots remain valid for spending (anchor history)

---

## 2. Nullifier Set

### Purpose

Ensures a note is **spent at most once** (prevents double-spend).

### Properties

- **Uniqueness**: Each nullifier can only be inserted once
- **No membership proofs needed**: Just check existence
- **No position tracking**: It's a set, not a tree

### Operations

| Operation        | Who             | When               |
| ---------------- | --------------- | ------------------ |
| **Insert(nf)**   | Chain (program) | Transfer, Unshield |
| **Contains(nf)** | Chain / Client  | Before spending    |

### Implementation Options

#### Option A: PDA per Nullifier (Current/Simple)

```rust
// On-chain: create PDA keyed by nullifier
let seeds = [b"nullifier", nullifier.as_ref()];
let (pda, _) = Pubkey::find_program_address(&seeds, &program_id);

// Insert = create account (fails if exists)
// Contains = account exists check
```

**Pros:** Simple, immediate
**Cons:** State growth (one account per spend)

#### Option B: Light Protocol Uniqueness

Light Protocol can enforce uniqueness via its state tree:

- Insert nullifier as "address" in Light state
- Duplicate insert fails deterministically

**Pros:** Compressed state, no rent per nullifier
**Cons:** Depends on Light Protocol, needs validity proof

---

## 3. Light Protocol Integration

**See [light-protocol-integration.md](light-protocol-integration.md) for full details.**

### Key Insight: Hash-Based Identification

Light Protocol uses **data hashes** as primary identifiers, NOT positions:

```
Lookup:  getCompressedAccount(hash) → account data
Proof:   getCompressedAccountProof(hash) → merkle proof
```

For MASP:

- **Commitment = hash = identifier**
- Client stores: `(note_plaintext, commitment, tx_sig)`
- To spend: `getCompressedAccountProof(commitment)` → LP proof

### How Light Protocol Maps to Our Structures

| Our Concept     | Light Protocol              | Notes                               |
| --------------- | --------------------------- | ----------------------------------- |
| Commitment      | dataHash                    | Primary identifier (not position!)  |
| Commitment Tree | State Tree                  | Append-only, hash-addressed         |
| Nullifier Set   | Address Tree (uniqueness)   | Insert-once via `create_address`    |
| Merkle Witness  | `getCompressedAccountProof` | Returns proof by hash               |
| Validity Proof  | `getValidityProof`          | Batched, constant-size for on-chain |

### Proof Types

```
┌─────────────────────────────────────────────────────────────────┐
│                       Proof Hierarchy                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  MembershipProof (commitment in tree)                           │
│    ├── MockProof (always valid, for testing)                    │
│    ├── MerklePathProof (explicit siblings, off-chain)           │
│    └── LightValidityProof (from getValidityProof, on-chain)     │
│                                                                 │
│  TransferProof (ZK proof of valid spend + output)               │
│    ├── MockProof (always valid, for testing)                    │
│    └── UltraPlonkProof (real circuit proof)                     │
│                                                                 │
│  NullifierInsert (uniqueness via Light address tree)            │
│    ├── MockInsert (in-memory HashSet)                           │
│    └── LightAddressInsert (Light create_address)                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Actor Responsibilities

### Client

```rust
trait ClientOperations {
    // Building transactions
    fn get_membership_proof(&self, position: u64) -> MembershipProof;
    fn check_nullifier_spent(&self, nf: Nullifier) -> bool;
    fn build_transfer_proof(&self, inputs: TransferInputs) -> TransferProof;

    // After transaction
    fn verify_commitment_added(&self, cm: Commitment, tx: &str) -> Option<u64>;
}
```

### Indexer

```rust
trait IndexerOperations {
    // Commitment tree
    fn get_current_root(&self) -> Anchor;
    fn get_membership_witness(&self, position: u64) -> MerkleWitness;

    // Scanning
    fn get_outputs_since(&self, position: u64) -> Vec<OutputCiphertext>;

    // OOB support
    fn get_position_by_tx(&self, tx_sig: &str, cm: Commitment) -> u64;
}
```

### On-Chain Program

```rust
trait ProgramOperations {
    // Commitment tree (append)
    fn append_commitment(&mut self, cm: Commitment) -> u64;
    fn verify_membership(&self, cm: Commitment, proof: MembershipProof, anchor: Anchor) -> bool;

    // Nullifier set (uniqueness)
    fn insert_nullifier(&mut self, nf: Nullifier) -> Result<(), AlreadySpent>;
    fn is_nullifier_spent(&self, nf: Nullifier) -> bool;

    // Anchor history
    fn is_valid_anchor(&self, anchor: Anchor) -> bool;

    // ZK verification
    fn verify_transfer_proof(&self, proof: TransferProof, public_inputs: &[Fr]) -> bool;
}
```

---

## 5. Identifier Strategy

### Hash (Commitment) vs Position

| Aspect           | Hash (Commitment)                 | Position (leafIndex)   |
| ---------------- | --------------------------------- | ---------------------- |
| **Primary key**  | ✅ Yes in Light Protocol          | No, secondary          |
| **Lookup API**   | `getCompressedAccount(hash)`      | Not directly           |
| **Proof API**    | `getCompressedAccountProof(hash)` | Included in response   |
| **Immutable**    | ✅ Yes (content-addressed)        | Yes (append-only tree) |
| **Computable**   | ✅ Yes, from note plaintext       | Only from LP response  |
| **OOB transfer** | ✅ Easy (hash the note)           | Need to query LP       |

**Decision:** Use **commitment (hash)** as primary identifier.

### Identifier Lifecycle

```
1. Shield: Client creates note
   └─► commitment = H(note_plaintext)
   └─► Chain stores commitment in Light tree
   └─► Returns tx_sig

2. Store: Client saves (note_plaintext, commitment, tx_sig)

3. Spend: Client needs proof
   └─► getCompressedAccountProof(commitment)
       └─► Returns { proof, root, leafIndex }

4. Verify: On-chain
   └─► verify_light_proof(commitment, proof, root)
```

### Transaction Signature Role

Transaction signature is **secondary** identifier:

- Used for OOB notification ("I paid you in tx X")
- Used for recovery: `getTransactionWithCompressionInfo(sig)` → find commitments
- One tx can have multiple commitments

```
OOB message (preferred):
{ tx_sig, commitment, note_plaintext }

OOB message (minimal):
{ tx_sig }
→ Recipient: getTransactionWithCompressionInfo(tx_sig)
→ Trial decrypt ciphertexts to find their note
```

---

## 6. Privacy Considerations

### Commitment Tree

| Operation          | Privacy Risk                      | Mitigation                     |
| ------------------ | --------------------------------- | ------------------------------ |
| `get_witness(pos)` | Reveals which notes you might own | PIR, decoys, own indexer       |
| `append(cm)`       | Public (on-chain)                 | OK - commitment hides contents |

### Nullifier Set

| Operation      | Privacy Risk                           | Mitigation                              |
| -------------- | -------------------------------------- | --------------------------------------- |
| `insert(nf)`   | Public (on-chain)                      | OK - nf is deterministic but unlinkable |
| `contains(nf)` | Reveals interest in specific nullifier | Query via ZK, batch queries             |

### Ciphertexts

| Operation          | Privacy Risk          | Mitigation                  |
| ------------------ | --------------------- | --------------------------- |
| `scan_outputs()`   | Reveals sync position | Always scan from 0, use PIR |
| Successful decrypt | Indexer doesn't see   | Client-side only            |

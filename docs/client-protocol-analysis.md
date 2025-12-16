# MASP Client Protocol Analysis

This document analyzes the client-side protocol flows, data requirements, and abstraction boundaries.

## Table of Contents

1. [Operation Flows](#operation-flows)
2. [Sync Mechanisms](#sync-mechanisms)
3. [Client Data Model](#client-data-model)
4. [Fees and Relayers](#fees-and-relayers)
5. [Abstraction Review](#abstraction-review)
6. [Privacy Analysis](#privacy-analysis)
7. [Recommendations](#recommendations)

---

## Operation Flows

### Shield (Deposit into Pool)

```
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Client  │         │  Chain  │         │ Indexer │
└────┬────┘         └────┬────┘         └────┬────┘
     │                   │                   │
     │  1. Create note   │                   │
     │  (self as rcpt)   │                   │
     │                   │                   │
     │  2. Compute cm    │                   │
     │                   │                   │
     │  3. shield(cm, tokens)                │
     │──────────────────>│                   │
     │                   │                   │
     │                   │  4. Verify deposit│
     │                   │  5. Add cm to tree│
     │                   │  6. Emit position │
     │                   │                   │
     │<──────────────────│                   │
     │  (tx_sig, pos)    │                   │
     │                   │                   │
     │  7. Store note    │                   │
     │  locally w/ pos   │                   │
     │                   │                   │
```

**What's public:** Token address, amount, commitment
**What's private:** Note plaintext (recipient address, randomness)

**Current gaps:**

- `Chain` trait missing `shield()` method
- No position returned from chain
- Shield circuit not integrated (for hiding amount at boundary)

---

### Transfer (Shielded → Shielded)

```
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Client  │         │  Chain  │         │ Indexer │
└────┬────┘         └────┬────┘         └────┬────┘
     │                   │                   │
     │  1. Select note(s) to spend           │
     │                   │                   │
     │  2. get_witness(position)             │
     │──────────────────────────────────────>│
     │<──────────────────────────────────────│
     │  (witness)        │                   │
     │                   │                   │
     │  3. Compute nf    │                   │
     │  4. Create output │                   │
     │  5. Create change │                   │
     │  6. Encrypt notes │                   │
     │  7. Generate proof│                   │
     │                   │                   │
     │  8. submit_tx(anchor, nfs, cms, proof, ciphertexts)
     │──────────────────>│                   │
     │                   │                   │
     │                   │  9. Verify anchor │
     │                   │  10. Check nfs    │
     │                   │  11. Verify proof │
     │                   │  12. Mark nfs spent│
     │                   │  13. Add cms      │
     │                   │  14. Store ciphertexts
     │                   │                   │
     │<──────────────────│                   │
     │  (tx_sig)         │                   │
     │                   │                   │
     │  15. Mark input spent                 │
     │  16. Add change note                  │
     │                   │                   │
```

**What's public:** Anchor, nullifiers, new commitments, ciphertexts (encrypted)
**What's private:** Which note spent, amounts, recipients, asset types

---

### Unshield (Withdraw from Pool)

```
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Client  │         │  Chain  │         │ Indexer │
└────┬────┘         └────┬────┘         └────┬────┘
     │                   │                   │
     │  1. Select note to spend              │
     │                   │                   │
     │  2. get_witness(position)             │
     │──────────────────────────────────────>│
     │<──────────────────────────────────────│
     │                   │                   │
     │  3. Compute nf    │                   │
     │  4. Generate proof│                   │
     │                   │                   │
     │  5. unshield(anchor, nf, proof, recipient, amount)
     │──────────────────>│                   │
     │                   │                   │
     │                   │  6. Verify proof  │
     │                   │  7. Mark nf spent │
     │                   │  8. Transfer tokens│
     │                   │                   │
     │<──────────────────│                   │
     │  (tx_sig)         │                   │
     │                   │                   │
     │  9. Mark note spent                   │
     │                   │                   │
```

**What's public:** Nullifier, recipient pubkey, amount (partially public at boundary)
**What's private:** Which specific note was spent

---

## Sync Mechanisms

### 1. Full Sync (Scanning)

Client trial-decrypts all ciphertexts to find owned notes.

```
┌─────────┐                              ┌─────────┐
│ Client  │                              │ Indexer │
└────┬────┘                              └────┬────┘
     │                                        │
     │  scan_outputs(last_synced_position)    │
     │───────────────────────────────────────>│
     │<───────────────────────────────────────│
     │  [OutputCiphertext { pos, cm, ct, epk }]
     │                                        │
     │  For each ciphertext:                  │
     │    try_decrypt(ivk, ct, epk)           │
     │    if success:                         │
     │      verify cm matches note            │
     │      store note with position          │
     │                                        │
```

**Privacy:** Indexer doesn't know which ciphertexts you successfully decrypt.
**Cost:** O(n) decryption attempts where n = outputs since last sync.

### 2. Out-of-Band (OOB) Note Delivery

Sender tells recipient about their note directly.

```
┌────────┐         ┌────────────┐         ┌──────────┐
│ Sender │         │ OOB Channel│         │ Recipient│
└───┬────┘         └─────┬──────┘         └────┬─────┘
    │                    │                     │
    │  After tx confirms:│                     │
    │                    │                     │
    │  send(tx_sig, note_plaintext, position)  │
    │───────────────────>│                     │
    │                    │────────────────────>│
    │                    │                     │
    │                    │  Recipient:         │
    │                    │  1. Verify cm       │
    │                    │  2. Verify inclusion│
    │                    │  3. Store note      │
    │                    │                     │
```

**Privacy:** No scanning needed, but requires trusted channel.
**Use cases:**

- Payment notifications
- Invoice flows where sender knows recipient
- Faster UX (no wait for sync)

### 3. Hybrid Approach

```rust
// Future client API
impl MaspClient {
    /// Full sync - trial decrypt everything
    async fn sync(&mut self) -> Result<Vec<OwnedNote>, Error>;

    /// OOB import - sender gave us the note directly
    async fn import_note(&mut self, note: Note, position: u64, tx_sig: &str) -> Result<(), Error>;

    /// Import with verification (fetch and verify inclusion)
    async fn import_and_verify(&mut self, note: Note, tx_sig: &str) -> Result<u64, Error>;
}
```

---

## Client Data Model

### What Client Stores

```rust
struct ClientState {
    // Keys (MUST persist securely)
    spending_key: SpendingKey,

    // Derived (can recompute, but cache for performance)
    fvk: FullViewingKey,

    // Notes (MUST persist)
    notes: Vec<OwnedNote>,

    // Sync state
    last_synced_position: u64,

    // Pending transactions (optional, for UX)
    pending_txs: Vec<PendingTransaction>,

    // Address book (optional)
    contacts: HashMap<String, Fr>,  // name -> pk_d
}

struct OwnedNote {
    note: Note,           // Full plaintext
    position: u64,        // Tree position (for witness)
    commitment: Fr,       // For verification
    spent: bool,          // Local tracking

    // Metadata (optional)
    tx_sig: Option<String>,    // Transaction that created this
    received_at: Option<u64>,  // Block height
    memo: Option<Vec<u8>>,     // Decrypted memo
}

struct PendingTransaction {
    tx_sig: String,
    spent_positions: Vec<u64>,
    new_notes: Vec<Note>,       // Notes we'll own after confirmation
    status: TxStatus,
}
```

### Data Sources

| Data            | Source                              | When                  |
| --------------- | ----------------------------------- | --------------------- |
| `spending_key`  | User                                | Initial setup         |
| `notes` (owned) | Sync OR OOB                         | Ongoing               |
| `position`      | Chain (via Indexer)                 | After tx confirmation |
| `commitment`    | Computed locally                    | When receiving note   |
| `spent`         | Local tracking + Chain verification | After spending        |

---

## Fees and Relayers

### Current State

**Not implemented.** Current design assumes user pays SOL directly.

### Fee Options

#### Option 1: Transparent Fees (Simplest, Worst Privacy)

```
User pays SOL directly for transaction fees.
```

**Privacy impact:** Links Solana account to shielded activity.

#### Option 2: Relayer with Shielded Reimbursement (Best Privacy)

```
┌────────┐       ┌─────────┐       ┌───────┐
│ Client │       │ Relayer │       │ Chain │
└───┬────┘       └────┬────┘       └───┬───┘
    │                 │                │
    │  1. Build tx with fee output     │
    │  (output to relayer address)     │
    │                 │                │
    │  send_to_relayer(tx_bundle)      │
    │────────────────>│                │
    │                 │                │
    │                 │  2. Verify fee │
    │                 │  3. Submit tx  │
    │                 │───────────────>│
    │                 │                │
    │                 │<───────────────│
    │                 │  (confirmation)│
    │<────────────────│                │
    │  (tx_sig)       │                │
```

**Transaction structure:**

- Input: User's note (e.g., 100 USDC)
- Output 1: Recipient (e.g., 90 USDC)
- Output 2: Relayer fee (e.g., 10 USDC)

#### Option 3: Protocol Fee Pool

```
Small % of each transaction goes to protocol treasury.
Treasury reimburses relayers.
```

### Client Changes for Fees

```rust
struct TransferData {
    // ... existing fields ...

    // Fee output (if using relayer)
    fee_output: Option<Note>,
}

impl MaspClient {
    fn build_transfer_with_fee(
        &mut self,
        spend_position: u64,
        recipient: Fr,
        amount: u64,
        relayer_address: Fr,
        fee_amount: u64,
    ) -> Result<TransferData, Error>;
}
```

---

## Abstraction Review

### Current `Chain` Trait

```rust
trait Chain {
    async fn is_nullifier_spent(&self, nullifier: &Nullifier) -> bool;
    async fn is_valid_anchor(&self, anchor: &Anchor) -> bool;
    async fn submit_transaction(&self, tx: PreparedTransaction) -> String;
    async fn get_current_root(&self) -> Anchor;
}
```

**Issues:**

1. Missing `shield()` - deposit tokens + add commitment
2. Missing `unshield()` - withdraw tokens
3. `submit_transaction()` is too generic - doesn't distinguish operations
4. No way to get commitment position after shield

**Recommendation:**

```rust
trait Chain {
    // Queries
    async fn is_nullifier_spent(&self, nf: &Nullifier) -> Result<bool, ChainError>;
    async fn is_valid_anchor(&self, anchor: &Anchor) -> Result<bool, ChainError>;
    async fn get_current_root(&self) -> Result<Anchor, ChainError>;

    // Operations (return position for new commitments)
    async fn shield(&self, data: ShieldData) -> Result<ShieldResult, ChainError>;
    async fn transfer(&self, data: TransferData) -> Result<TransferResult, ChainError>;
    async fn unshield(&self, data: UnshieldData) -> Result<UnshieldResult, ChainError>;
}

struct ShieldResult {
    tx_sig: String,
    commitment_position: u64,
}

struct TransferResult {
    tx_sig: String,
    output_positions: Vec<u64>,  // [output, change] positions
}

struct UnshieldResult {
    tx_sig: String,
}
```

**Production implementation:** Solana RPC + program client

### Current `Indexer` Trait

```rust
trait Indexer {
    async fn get_current_root(&self) -> Anchor;
    async fn get_witness(&self, position: u64) -> MerkleWitness;
    async fn scan_outputs(&self, from_position: u64) -> Vec<OutputCiphertext>;
}
```

**Issues:**

1. `get_current_root()` duplicated with Chain (should pick one)
2. `get_witness(position)` reveals which notes you own ⚠️
3. Missing: get transaction by signature (for OOB verification)

**Recommendation:**

```rust
trait Indexer {
    // Merkle tree operations
    async fn get_current_root(&self) -> Result<Anchor, IndexerError>;
    async fn get_witness(&self, position: u64) -> Result<MerkleWitness, IndexerError>;

    // Scanning
    async fn scan_outputs(&self, from_position: u64) -> Result<Vec<OutputCiphertext>, IndexerError>;

    // OOB support
    async fn get_commitment_position(&self, tx_sig: &str, cm: Commitment) -> Result<u64, IndexerError>;
    async fn verify_inclusion(&self, position: u64, cm: Commitment) -> Result<bool, IndexerError>;
}
```

**Production implementations:**

- Helius RPC (ZK compression APIs)
- Custom indexer
- Light Protocol RPC

---

## Privacy Analysis

### What Each Party Learns

| Party           | Learns                                                              | Doesn't Learn                                      |
| --------------- | ------------------------------------------------------------------- | -------------------------------------------------- |
| **Chain**       | Nullifiers, commitments, ciphertexts, anchors                       | Note values, recipients, which cm matches which nf |
| **Indexer**     | Which positions you request witnesses for ⚠️, your sync position ⚠️ | Which ciphertexts you decrypt                      |
| **Relayer**     | Transaction contents (but values hidden in proof)                   | Private inputs to circuit                          |
| **Other users** | Public inputs only                                                  | Everything else                                    |

### Privacy Concerns

#### 1. Witness Requests Leak Ownership

**Problem:** When you call `get_witness(position)`, indexer learns you might own that note.

**Mitigations:**

- Request witnesses for decoy positions
- Use PIR (Private Information Retrieval)
- Run your own indexer

#### 2. Sync Position Leaks Activity

**Problem:** `scan_outputs(from_position)` reveals when you last synced.

**Mitigations:**

- Always scan from position 0 (expensive)
- Use differential privacy (random starting points)
- Batch sync with other users

#### 3. Timing Correlation

**Problem:** Shield → immediate Transfer/Unshield reveals connection.

**Mitigations:**

- Wait random time before spending
- Use larger anonymity set
- Batch transactions

### Privacy-Preserving Indexer Interface (Future)

```rust
trait PrivateIndexer {
    /// PIR-based witness retrieval - indexer can't tell which position
    async fn get_witness_pir(&self, query: PirQuery) -> PirResponse;

    /// Oblivious scanning - indexer can't tell your sync position
    async fn scan_oblivious(&self, query: ObliviousScanQuery) -> Vec<OutputCiphertext>;
}
```

---

## Recommendations

### Immediate (Milestone 1)

1. **Split Chain operations** - Add `shield()`, `transfer()`, `unshield()` methods
2. **Return positions** - Chain operations should return commitment positions
3. **Add OOB import** - `import_note()` method on client
4. **Remove duplicate `get_current_root()`** - Keep only on Chain

### Short-term (Milestone 2-3)

1. **Fee support** - Add optional fee output to transfers
2. **Multi-input support** - Allow spending multiple notes in one tx
3. **Transaction batching** - Combine multiple operations

### Long-term (Milestone 6+)

1. **PIR for witnesses** - Privacy-preserving witness retrieval
2. **Relayer integration** - Trait for relayer submission
3. **Oblivious sync** - Privacy-preserving scanning

---

## Appendix: Multiple Notes in One Spend

### Current Limitation

Current design: 1 Action = 1 spend + 1 output (+ optional change)

### Extended Design

```rust
struct MultiTransferData {
    anchor: Anchor,

    // Multiple inputs
    spends: Vec<SpendInput>,

    // Multiple outputs
    outputs: Vec<Note>,

    // Single proof covering all
    proof: Vec<u8>,
}

struct SpendInput {
    nullifier: Nullifier,
    note: Note,
    witness: MerkleWitness,
}
```

**Circuit implications:**

- Fixed max inputs (e.g., 4)
- Fixed max outputs (e.g., 4)
- Padding with dummy values if fewer

**Client API:**

```rust
impl MaspClient {
    fn build_multi_transfer(
        &mut self,
        spend_positions: &[u64],   // Multiple inputs
        recipients: &[(Fr, u64)],  // (address, amount) pairs
    ) -> Result<MultiTransferData, Error>;
}
```

---

## Summary

| Component       | Current State | Gap                         | Priority |
| --------------- | ------------- | --------------------------- | -------- |
| Shield flow     | Incomplete    | Missing Chain.shield()      | High     |
| Transfer flow   | Works         | Needs proof generation      | High     |
| Unshield flow   | Incomplete    | Missing Chain.unshield()    | High     |
| Sync (scanning) | Stubbed       | Needs encryption impl       | Medium   |
| Sync (OOB)      | Not started   | Needs import method         | Medium   |
| Multi-input     | Not supported | Needs circuit + client work | Low      |
| Fees            | Not started   | Needs relayer design        | Low      |
| Privacy (PIR)   | Not started   | Future work                 | Future   |

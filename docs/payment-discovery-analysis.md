# Payment Discovery Analysis

**How do recipients discover they've been paid?**

This document compares different approaches to shielded payment discovery, analyzing our current implementation vs more scalable alternatives.

---

## The Core Problem

In transparent chains, discovering payments is trivial:

```
balance = chain.getBalance(address)
```

In shielded systems, **the chain doesn't know who received each payment**. This is the privacy guarantee! But it creates a discovery problem.

---

## Approach 1: Trial Decryption (Zcash, Our Current Design)

### How It Works

```
For each shielded output (epk, ciphertext):
    ss = ivk * epk                    # ECDH with ephemeral key
    key = KDF(ss)
    try:
        note = decrypt(key, ciphertext)
        if note.recipient == my_address:
            found_payment()
    except:
        continue  # Not for me
```

### Ephemeral Key (epk) in Our Design

```rust
// Encryption (sender)
esk = random()                        // Ephemeral secret (NEVER stored)
epk = esk * g_d                       // Ephemeral public key
ss = esk * pk_d                       // Shared secret
key = KDF(ss, epk)
ciphertext = encrypt(key, note)
store_on_chain(epk, ciphertext)       // epk is ON-CHAIN

// Decryption (recipient)
epk = fetch_from_chain()              // Always available!
ss = ivk * epk                        // Same shared secret
key = KDF(ss, epk)
note = decrypt(key, ciphertext)
```

### What Happens If esk (Ephemeral Secret) Is Lost?

**Key insight:** esk is ephemeral by design - it's used once and discarded.

```
Timeline:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Alice generates esk = random()                                   │
│ 2. Alice computes epk = esk * g_d                                   │
│ 3. Alice computes ss = esk * pk_d (shared secret)                   │
│ 4. Alice encrypts note with ss                                      │
│ 5. Alice broadcasts tx containing (epk, ciphertext)                 │
│ 6. Alice DISCARDS esk ← This is correct behavior!                   │
│ 7. Tx confirms on-chain                                             │
└─────────────────────────────────────────────────────────────────────┘
```

**Who needs esk?**

| Party | Needs esk? | Why |
|-------|-----------|-----|
| **Recipient (Bob)** | ❌ NO | Uses `ss = ivk * epk` (same result!) |
| **Sender (Alice)** | ❌ NO (after tx) | Only needed during encryption |
| **Anyone else** | ❌ NO | Can't derive without ivk or esk |

**The math:**

```
Alice:   ss = esk * pk_d = esk * (ivk * g_d)
Bob:     ss = ivk * epk  = ivk * (esk * g_d)

Both compute the same shared secret!
```

**Loss scenarios:**

| Scenario | Impact | Severity |
|----------|--------|----------|
| esk lost AFTER tx confirms | ✅ None - recipient can still decrypt | None |
| esk lost BEFORE tx sent | ❌ Can't create tx - just regenerate | None |
| esk lost DURING tx creation | ❌ Tx fails - retry with new esk | None |

**The Real Problem: Alice Can't Recover Sent Payments!**

You identified the critical issue: **Alice cannot decrypt notes she sent** because:

```
Encryption (Alice → Bob):
  esk = random()                    ← NOT derived from Alice's seed!
  ss = esk * pk_d_bob               ← Shared secret
  key = KDF(ss)
  ciphertext = Encrypt(key, note)
  
  esk is discarded after tx...

Alice tries to recover later:
  epk = from_chain                  ← Available
  ss = ??? * epk                    ← Alice can't compute ss!
  
  Alice's seed doesn't help because esk was RANDOM, not derived from seed.
```

**Bob can always decrypt** (uses `ivk * epk`), but **Alice cannot!**

This is why Zcash has **C_out (Outgoing Ciphertext)**:

```
Transaction contains TWO ciphertexts:

1. C_enc = Encrypt(ss, note)         ← For Bob (recipient)
   - ss = esk * pk_d_bob
   - Bob decrypts with ivk * epk ✅

2. C_out = Encrypt(ovk, esk || note) ← For Alice (sender)
   - ovk = outgoing viewing key (derived from Alice's seed!)
   - Alice can ALWAYS decrypt C_out ✅
   - C_out contains esk, so Alice can then decrypt C_enc too
```

**Why C_out works:**

```
Alice's key hierarchy:
  seed → sk → ovk (outgoing viewing key)
                ↑
                Alice can always derive this from her seed!

C_out encryption:
  ock = KDF(ovk, epk, pk_d_bob)     ← Deterministic from Alice's keys
  C_out = Encrypt(ock, esk || note_plaintext)
```

**Without C_out (our current state):**

- Alice loses wallet state → Alice cannot recover what she SENT
- Alice can still recover what she RECEIVED (uses ivk * epk)
- This is a significant UX gap for sender audit/recovery

**Our current implementation:** No C_out yet (on roadmap for Milestone 9)

### epk Storage

**epk CANNOT be lost** because:

1. ✅ **epk is stored on-chain** in transaction instruction data
2. ✅ **Transaction data is immutable** - always available
3. ✅ **No sender state required** - stateless per-payment

### Scaling Problem

```
Sync cost = O(N) where N = total shielded outputs ever

For 1M outputs:
- Download: ~228 MB (epk + ciphertext per output)
- Decrypt attempts: 1M ECDH + 1M AES operations
- Time on phone: Hours to days
```

**This is why Zcash sync is slow.**

---

## Approach 2: Tag-Based Discovery (Aztec/Article Design)

### How It Works

**First payment (Alice → Bob):**

```
// Alice and Bob do long-term key exchange
S = DH(alice_long_term_sk, bob_long_term_pk)

// Derive bidirectional tag streams
tag_stream_a_to_b = PRF(S, "alice->bob")
tag_stream_b_to_a = PRF(S, "bob->alice")
```

**Subsequent payments:**

```
// Alice's 6th payment to Bob
tag = tag_stream_a_to_b[6]            // Deterministic!
tx = create_payment(note, tag)
broadcast(tx)

// Bob's wallet (later)
expected_tag = tag_stream_a_to_b[6]   // Bob knows this!
tx_hash = PIR_query(indexer, expected_tag)  // O(1) lookup
note = fetch_and_decrypt(tx_hash)
```

### Key Differences

| Aspect | Trial Decryption | Tag-Based |
|--------|-----------------|-----------|
| **First payment** | Works immediately | Requires key exchange |
| **Subsequent payments** | Same O(N) scan | O(1) PIR lookup |
| **State required** | None (stateless) | Payment counters |
| **Recovery** | Full chain scan | Needs backup or fallback |
| **Indexer privacy** | High (local decrypt) | PIR-dependent |
| **epk needed?** | Yes (for ECDH) | No (uses long-term keys) |

### Tag-Based Advantages

1. **Scales to millions of users** - O(1) discovery
2. **Low bandwidth** - Only fetch relevant txs
3. **PIR hides queries** - Indexer doesn't learn which tag

### Tag-Based Disadvantages

1. **First payment problem** - Still needs OOB or test tx
2. **Stateful wallets** - Must track payment counts
3. **Recovery harder** - Can't just scan with mnemonic
4. **Long-term key exposure** - Compromising long-term key reveals all payments in stream

---

## Approach 3: Hybrid (Recommended for Production)

Combine both approaches:

```
┌─────────────────────────────────────────────────────┐
│                    First Payment                     │
│  Use OOB (payment link) OR trial decrypt small set  │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│              Long-term Key Exchange                  │
│  Derive shared secret S for tag streams             │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│              Subsequent Payments                     │
│  Tag-based discovery via PIR (O(1))                 │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│              Recovery Fallback                       │
│  - Encrypted cloud backup (default)                 │
│  - TEE/MPC sync service (privacy tradeoff)          │
│  - Full trial decrypt (expensive, last resort)      │
└─────────────────────────────────────────────────────┘
```

---

## Our Current Implementation

### What We Have (POC-appropriate)

```rust
// Trial decryption - simple, correct, doesn't scale
pub fn trial_decrypt<E: NoteEncryption>(
    encryption: &E,
    encrypted: &EncryptedNote,
    fvk: &FullViewingKey,
    diversifier_indices: impl Iterator<Item = u64>,
) -> Option<Note> {
    for idx in diversifier_indices {
        if let Ok(note) = encryption.try_decrypt(encrypted, fvk, idx) {
            return Some(note);
        }
    }
    None
}
```

### What We'd Need for Tag-Based

```rust
// New: Long-term key pair (separate from spending key)
pub struct TagKeyPair {
    sk: [u8; 32],  // Long-term secret
    pk: [u8; 32],  // Long-term public (shared in address)
}

// New: Shared secret with counterparty
pub struct TagStream {
    shared_secret: [u8; 32],
    direction: TagDirection,  // Incoming or Outgoing
    counter: u64,             // Current position in stream
}

impl TagStream {
    pub fn next_tag(&mut self) -> [u8; 32] {
        let tag = poseidon_hash(&[
            self.shared_secret,
            self.direction.to_field(),
            Fr::from(self.counter),
        ]);
        self.counter += 1;
        field_to_bytes(&tag)
    }
}

// New: PIR query to indexer
pub trait TagIndexer {
    fn pir_lookup(&self, tag: &[u8; 32]) -> Option<String>;  // Returns tx_sig
}
```

---

## Comparison: Ephemeral Key vs Tag-Based Key Management

### Ephemeral Key (Our Design)

```
Per-payment:
  esk = random()           ← Fresh randomness (DISCARDED after use)
  epk = esk * g_d          ← Public, stored on-chain
  ss = esk * pk_d          ← One-time shared secret
  
Key lifecycle:
  esk: Created → Used → DISCARDED (never stored!)
  epk: Created → Stored on-chain → Permanent
  
Properties:
  ✅ Forward secrecy (compromising one payment doesn't reveal others)
  ✅ Stateless (no counters)
  ✅ On-chain recovery (epk stored in tx, esk not needed!)
  ✅ esk loss is fine (recipient uses ivk * epk)
  ❌ O(N) discovery
```

### Tag-Based (Aztec)

```
Per-relationship:
  S = DH(my_lt_sk, their_lt_pk)  ← One-time setup
  
Per-payment:
  tag[i] = PRF(S, counter)       ← Deterministic from counter
  
Properties:
  ✅ O(1) discovery via PIR
  ✅ Low bandwidth sync
  ❌ No forward secrecy within stream (compromise S → all payments revealed)
  ❌ Stateful (must track counters)
  ❌ Recovery requires backup
```

### Best of Both Worlds?

```
Idea: Use epk for encryption, tag for discovery

Per-payment:
  esk = random()
  epk = esk * g_d
  ss_encrypt = esk * pk_d        ← For encryption (forward secrecy)
  
  tag = PRF(S_discovery, counter) ← For discovery (O(1) lookup)
  
Store on-chain: (tag, epk, ciphertext)

Discovery: PIR(tag) → tx_hash → fetch (epk, ciphertext) → decrypt with epk

Properties:
  ✅ Forward secrecy (epk-based encryption)
  ✅ O(1) discovery (tag-based)
  ❌ Still need counter state
  ❌ Still need backup for recovery
```

---

## Recommendations

### For POC (Current Phase)

Keep trial decryption. It's:

- Simple to implement ✅
- Correct ✅
- Fully recoverable from mnemonic ✅
- Doesn't scale ❌ (but fine for POC)

### For Production (Future)

1. **Add tag-based discovery** for O(1) sync
2. **Keep epk encryption** for forward secrecy
3. **Implement PIR** or use existing PIR service
4. **Add encrypted backup** for recovery
5. **Keep trial decrypt** as expensive fallback

### Migration Path

```
Phase 1 (POC): Trial decryption only
Phase 2: Add optional tag stream for repeat counterparties
Phase 3: PIR integration for scalable discovery
Phase 4: Encrypted backup service
Phase 5: TEE/FHE fallback for recovery
```

---

## Is Sender Audit Trail (C_out) Important?

### Use Cases for C_out

| Use Case | Without C_out | With C_out |
|----------|--------------|------------|
| **Tax reporting** | ❌ "I sent something?" | ✅ "I sent 100 USDC to Bob" |
| **Dispute resolution** | ❌ Can't prove details | ✅ Full payment proof |
| **Business accounting** | ❌ Incomplete records | ✅ Complete audit trail |
| **Multi-device sync** | ❌ Sent payments missing | ✅ Full history |
| **Wallet recovery** | ❌ Only see received | ✅ See sent AND received |

### Is it critical?

| Context | Importance |
|---------|------------|
| **POC** | Low - recipients work fine |
| **Consumer app** | Medium - nice to have |
| **Business/Enterprise** | High - required for compliance |
| **Exchanges** | Critical - must track all flows |

**Recommendation:** Defer to production, but design for it now.

---

## How Does Shielded Sync Work?

### Sync for RECEIVED Notes (Current)

```
For each (epk, C_enc) on chain:
    ss = ivk * epk                    # My incoming viewing key
    key = KDF(ss)
    
    try:
        note = Decrypt(key, C_enc)
        if note.recipient == my_address:
            # Found a note sent TO ME!
            store_received_note(note)
    except:
        continue  # Not for me
```

**Works because:** `ivk` is derived from my seed.

### Sync for SENT Notes (With C_out)

```
For each (epk, cm, C_out) on chain:
    ock = KDF(ovk, epk, cm)           # My outgoing viewing key
    
    try:
        (esk, pk_d, note) = Decrypt(ock, C_out)
        # Found a note I SENT!
        store_sent_note(note, recipient=pk_d)
    except:
        continue  # Not sent by me
```

**Works because:** `ovk` is derived from my seed.

### Detecting Spent Notes (Nullifier Check)

**Key insight:** You can only compute nullifiers for notes YOU OWN.

```
Nullifier = H(nk, nullifier_nonce)
                ↑
                └── Your nullifier key (from your seed)
```

**For notes you RECEIVED:**

```
1. Decrypt C_enc → get note with nullifier_nonce
2. Compute: nf = H(my_nk, note.nullifier_nonce)
3. Check: is nf in nullifier_set?
4. If yes → I already spent this note
5. If no → I still have this note (unspent)
```

**For notes you SENT:**

```
You CANNOT compute the nullifier!
- You know the note plaintext (from C_out)
- You DON'T know the recipient's nk
- So you can't compute their nullifier

But that's fine:
- You don't need to know if they spent it
- You only need to know you sent it (audit trail)
```

### Complete Shielded Sync Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    SHIELDED SYNC                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. SCAN RECEIVED NOTES                                     │
│     For each output on chain:                               │
│       - Try decrypt C_enc with ivk                          │
│       - If success → I received this note                   │
│                                                             │
│  2. CHECK WHICH RECEIVED NOTES ARE SPENT                    │
│     For each received note:                                 │
│       - Compute nullifier: nf = H(nk, nullifier_nonce)      │
│       - Query chain: is nf spent?                           │
│       - If spent → remove from wallet                       │
│       - If unspent → available balance                      │
│                                                             │
│  3. SCAN SENT NOTES (optional, needs C_out)                 │
│     For each output on chain:                               │
│       - Try decrypt C_out with ovk                          │
│       - If success → I sent this note                       │
│       - Store for audit trail                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Nullifier Check Cost Analysis

**The user correctly identified:** Nullifier checking can be expensive!

```
DISCOVERY COST:
  - Scan N outputs on chain
  - Trial decrypt each: O(N) decryptions
  - Find M notes that are mine

SPENT CHECK COST:
  - For each of M notes, compute nullifier
  - Check if nullifier is in on-chain set
  
  If nullifier set is:
    - PDA per nullifier: O(1) lookup per note → O(M) total ✅
    - Merkle tree: O(log K) with proof per note → O(M log K) ✅
    - Full scan: O(K) per note → O(M × K) ❌ Terrible!
```

**Good news:** On-chain nullifier sets typically use indexed storage (PDAs or Merkle), so each check is O(1) or O(log K), not O(K).

**Bad news:** You still need to know which notes you own first (requires trial decrypt).

### Light Protocol Nullifier Checking

Our design uses Light Protocol for nullifiers (not PDAs or our own Merkle tree).

**How it works:**

```rust
// Nullifier = compressed account "address" in Light Protocol
// Spending a note = creating an address with that nullifier
// Double-spend = address already exists → creation fails

fn is_nullifier_spent(nf: [u8; 32]) -> bool {
    light_protocol::address_exists(nf)  // O(1) indexed lookup
}
```

**Batch Checking via Helius API:**

```
Available endpoints (from docs/light-protocol-integration.md):

│ Operation              │ Helius API                        │ Batch? │
├────────────────────────┼───────────────────────────────────┼────────┤
│ Get single account     │ getCompressedAccount(hash)        │ No     │
│ Get membership proof   │ getCompressedAccountProof(hash)   │ No     │
│ Get validity proofs    │ getValidityProof(hashes[])        │ YES ✅ │
│ Get multiple accounts  │ getMultipleCompressedAccounts     │ YES ✅ │
```

**For nullifier batch check:**

```javascript
// Check which of my nullifiers are spent
const myNullifiers = myNotes.map(n => computeNullifier(nk, n.nullifierNonce));

// Single RPC call for all M nullifiers!
const results = await helius.getMultipleCompressedAccounts({
  addresses: myNullifiers
});

// Results tell us which exist (spent) vs which don't (unspent)
const spentNullifiers = results.filter(r => r.exists).map(r => r.address);
const unspentNotes = myNotes.filter(n => 
  !spentNullifiers.includes(computeNullifier(nk, n.nullifierNonce))
);
```

**Cost with Light Protocol:**

```
LIGHT PROTOCOL NULLIFIER CHECK:
  
  Off-chain (client sync):
    - Compute M nullifiers locally: O(M) hashes
    - Single batch RPC call: O(1) network round-trip
    - Response size: O(M) results
    - TOTAL: O(M) compute + O(1) network ✅
  
  On-chain (transaction):
    - Each nullifier needs validity proof
    - Light Protocol handles Merkle verification
    - ~100K CU per proof verification
    - TOTAL: O(M × 100K CU) per transaction
```

**Key insight:** Off-chain batch checking is cheap! The expensive part is:

1. Finding your notes in the first place (trial decrypt)
2. On-chain proof verification (CU cost)

---

## Light Protocol Proof Costs: Deep Dive

### Two Different Operations (Don't Confuse!)

```
┌─────────────────────────────────────────────────────────────────────┐
│  OPERATION 1: "Does nullifier X exist?" (SYNC)                      │
│                                                                     │
│  Context: Client checking which notes are spent                     │
│  Needs: Database lookup                                             │
│  Proof: NOT NEEDED ✅                                               │
│  API: getMultipleCompressedAccounts (returns existence only)        │
│  Speed: Fast (indexer database query)                               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  OPERATION 2: "Prove commitment C is in tree" (SPEND)               │
│                                                                     │
│  Context: Submitting transaction to spend a note                    │
│  Needs: Merkle inclusion proof                                      │
│  Proof: REQUIRED for on-chain verification                          │
│  API: getValidityProof (returns ZK proof)                           │
│  Speed: Slower (proof generation)                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### When Do We Need Proofs?

| Operation | Proof Needed? | Why |
|-----------|--------------|-----|
| **Sync: find my notes** | ❌ No | Just decrypting locally |
| **Sync: check if spent** | ❌ No | Just querying existence |
| **Spend: prove note exists** | ✅ Yes | On-chain verification |
| **Spend: prove nullifier new** | ✅ Yes | Light Protocol insertion |

### Batch Proofs: What `getValidityProof(hashes[])` Returns (and current limits)

```
Input:  [hash1, hash2, hash3, ..., hashM]  (accounts to prove)

Output options:
  Option A: M separate proofs     → M × verification cost 😱
  Option B: 1 batched proof       → 1 × verification cost ✅
  
Light Protocol supports batching, but the exact **batch shapes differ by proof type**.

**Important current constraint (2025-12):** for **non-membership / uniqueness** proofs (nullifier insert-once), batching is limited to **2 items per proof** (max).
```

**Practical implication for MASP nullifiers:**

- For N input nullifiers, you need approximately:
  - \(\lceil N / 2 \rceil\) non-membership proofs (under the “max 2 per proof” limit).
- This affects both:
  - **transaction size** (multiple proof payloads), and
  - **compute budget** (multiple Light verifications / CPIs).

### Performance Numbers (Estimates)

```
PROOF GENERATION (off-chain, by Photon indexer):
  
  Single proof: ~100-500ms
  Batched proof (M accounts): ~200-1000ms
    (Not M × single_proof_time!)
  
  Bottleneck: Usually not proof generation, but:
    - Network latency to indexer
    - Indexer queue/load

ON-CHAIN VERIFICATION:
  
  Single proof verification: ~100K CU
  Batched proof verification: ~100-200K CU (per proof, current estimates)
  
  Solana TX limit: ~1.4M CU
  → Upper bound depends on per-proof CU and proof system used for MASP
```

### For MASP Sync: No Proofs Needed

```
CLIENT SYNC FLOW:
  
  1. Trial decrypt outputs → find my notes
     Cost: O(N) local compute, no proofs
  
  2. Compute nullifiers for my notes
     Cost: O(M) local hashes, no proofs
  
  3. Query existence via getMultipleCompressedAccounts
     Cost: 1 RPC call, no proofs!
     Response: [exists: true/false, exists: true/false, ...]
  
  NO PROOFS NEEDED FOR SYNC!
```

### For MASP Spend: Proofs Needed

```
SPEND TRANSACTION:
  
  What needs proof:
  - Input note exists in commitment tree (getValidityProof)
  - Nullifier doesn't exist yet (Light Protocol handles)
  
  Typical spend: 1-2 input notes
  → non-membership batching fits naturally (1 proof for 1–2 nullifiers)
  → ~100-200K CU for Light verification
  → Leaves room for UltraPlonk proof (~500K CU)
```

### Risks and Mitigations

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Indexer latency** | Proof generation takes time | Cache proofs, prefetch |
| **Indexer downtime** | Can't get proofs if indexer is down | Multiple indexer endpoints |
| **Proof size** | Large proofs increase TX size | Light Protocol uses constant-size proofs |
| **Batching limits** | Non-membership/uniqueness proofs currently batch max 2 | For many inputs: multiple proofs, or split operation (non-atomic), or use a different proof system (e.g., Groth16) + proof buffering |
| **Stale proofs** | Tree changes invalidate proofs | Use recent anchor, retry if fails |
| **CU costs** | Multiple proofs exhaust budget | Batch proofs, limit inputs per TX |

### Summary: When Is It Slow?

```
FAST (no proofs):
  ✅ Checking if nullifiers exist (sync)
  ✅ Local nullifier computation
  ✅ Local trial decryption

MEDIUM (proof generation):
  ⚠️ Getting validity proof for 1-2 notes (~200ms)
  ⚠️ Batched proof for many notes (~500ms)

SLOW (compute bound):
  ❌ Trial decrypting O(N) outputs (recovery)
  ❌ Many proofs for many inputs (rare)
```

**Bottom line:**

- Sync doesn't need proofs → fast!
- Spending needs proofs → ~200ms generation + ~100K CU verification
- Batch proofs amortize cost → don't pay M× for M accounts

### Does C_out Help With Spent Detection?

**What C_out contains:**

```
C_out = Encrypt(ovk, {
    pk_d,      // Recipient address
    esk,       // Ephemeral secret
    note,      // Note plaintext (amount, asset, etc.)
})
```

**What C_out does NOT contain:**

- ❌ Which note was SPENT to fund this transaction
- ❌ The input nullifier

**But wait!** The nullifier is a PUBLIC INPUT to the ZK proof:

```
Transaction on-chain:
├── Public inputs: [anchor, NULLIFIER, new_commitment, ...]
├── Proof: [...]
├── C_enc: [...]  ← For recipient
└── C_out: [...]  ← For sender
```

So if you decrypt C_out for a transaction, you can:

1. Know you were the sender (C_out decrypts)
2. Look at the transaction's public inputs → see the nullifier
3. Correlate: "I spent note with nullifier X to create this payment"

**This helps with audit trail, but not with recovery!**

For recovery, you still need to:

1. Find notes you received (trial decrypt C_enc)
2. Compute their nullifiers
3. Check if spent

### Do Tags Solve Recovery?

**Tags solve DISCOVERY, not SPENT DETECTION or RECOVERY.**

| Problem | Tags Help? | Why |
|---------|-----------|-----|
| Find new payments | ✅ YES | O(1) PIR lookup instead of O(N) scan |
| Detect spent notes | ❌ NO | Still need nullifier check |
| Recovery from seed | ❌ NO | Tags require counter state |

```
ONGOING SYNC (with tags):
  1. Query: "Has Alice sent me payment #7?" → O(1) PIR ✅
  2. Decrypt the specific tx
  3. Check nullifier for any notes I spend

RECOVERY (no state):
  1. Don't know payment counters → can't use tags
  2. Must do full trial decrypt scan → O(N) ❌
  3. Then check nullifiers for each note → O(M) queries
```

### The Tag Recovery Problem (Critical!)

**Scenario:** Alice loses wallet state, does trial decryption recovery.

```
WHAT ALICE CAN RECOVER:
  ✅ Her notes (trial decrypt C_enc with ivk)
  ✅ Her spending ability (has seed → has sk)
  ✅ Her nullifiers (computed from notes + nk)
  
WHAT ALICE CANNOT RECOVER:
  ❌ Shared secrets with counterparties
  ❌ Payment counters for each relationship
  ❌ Tag streams
```

**The Desync Problem:**

```
BEFORE RECOVERY:
  Bob thinks: "I've sent Alice 10 payments, next tag = tag[11]"
  Alice knew: "Bob has sent me 10 payments, expect tag[11]"

AFTER RECOVERY:
  Bob thinks: "Next tag for Alice = tag[11]"
  Alice thinks: "Who is Bob? I have no tag state for him"

Bob sends payment with tag[11]
Alice looks for tag[1] (or doesn't know to look at all!)
→ Alice NEVER FINDS the payment via tags!
```

**Why Can't Alice Recover Shared Secrets?**

```
Shared secret: S = DH(alice_lt_sk, bob_lt_pk)
                              ↑           ↑
                        From seed     WHERE IS THIS?
                        (recoverable)  (NOT recoverable!)
```

Alice can derive her own long-term secret key from her seed.
But she needs Bob's long-term PUBLIC key to compute S.
Bob's public key isn't derivable from Alice's seed!

### Solutions to Tag Recovery Problem

**Solution 1: OOB Re-sync (Simple but Manual)**

```
Alice → Bob (out-of-band): "I lost my state, let's restart"
Bob resets counter for Alice to 0
Both start fresh

Problems:
  - Requires communication (defeats purpose of tags)
  - Bob might not know how to reach Alice
  - Multiple counterparties = multiple conversations
```

**Solution 2: Store Sender Info in Note (Recommended)**

```
Extended note plaintext:
{
  asset_id, amount, recipient, nullifier_nonce, randomness,
  
  // NEW: Tag recovery data
  sender_lt_pk: [u8; 32],    // Sender's long-term public key
  tag_counter: u64,          // Current counter in stream
}

Recovery flow:
  1. Alice trial decrypts to find her notes
  2. For each note, extract sender_lt_pk
  3. Compute S = DH(alice_lt_sk, sender_lt_pk)
  4. Extract tag_counter → know where in stream
  5. Resume tag-based discovery!
```

**Solution 3: Window Search (Fallback)**

```
Instead of looking for exactly tag[expected]:
  Check: tag[expected], tag[expected+1], ..., tag[expected+W]
  
If Alice is behind by K payments:
  - Check window of W tags
  - If K < W, she'll find the payment
  - Update counter to match

Cost: O(W) PIR queries instead of O(1)
      Still better than O(N) trial decrypt
```

**Solution 4: Beacon Tags (Periodic Resync)**

```
Every K payments, include a "beacon" that's discoverable:
  beacon = H(S, "beacon", floor(counter / K))

Alice can:
  1. Compute all possible beacons for known counterparties
  2. Query for beacons to find approximate position
  3. Then search narrow window

Cost: O(counterparties × beacons_per_period) queries
```

**Solution 5: Accept the Limitation**

```
Recovery policy:
  - Notes: Recovered via trial decrypt ✅
  - Tags: NOT recovered
  - Going forward: All counterparties treated as "first payment"
  
After recovery, Bob's payment with tag[11]:
  - NOT found via tag lookup
  - IS found via trial decrypt (slow but works)
  - Next payment from Bob: re-establish with new first payment
```

### Recommendation for MASP

```
┌─────────────────────────────────────────────────────────────────┐
│                    TAG RECOVERY STRATEGY                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SHORT TERM (POC):                                              │
│    - No tags, just trial decrypt                                │
│    - Recovery = full scan                                       │
│    - Simple, correct, doesn't scale                             │
│                                                                 │
│  MEDIUM TERM (Production):                                      │
│    - Tags with Solution 2 (store sender_lt_pk in note)          │
│    - Recovery extracts sender keys from decrypted notes         │
│    - Window search as fallback for missed payments              │
│                                                                 │
│  LONG TERM:                                                     │
│    - Encrypted backup (avoid recovery problem entirely)         │
│    - Tags as optimization for ongoing sync                      │
│    - Trial decrypt as rare fallback                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Cost Comparison

| Scenario | Discovery Cost | Recovery Cost |
|----------|---------------|---------------|
| **No tags** | O(N) scan | O(N) scan |
| **Tags, no recovery** | O(1) PIR | O(N) scan + tags broken |
| **Tags + Solution 2** | O(1) PIR | O(N) scan + tags restored |
| **Tags + backup** | O(1) PIR | O(1) restore |

### The Real Cost Breakdown (With Light Protocol)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FULL RECOVERY (no state)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: Find my notes                                          │
│    - Download all outputs: O(N) bandwidth                       │
│    - Trial decrypt each: O(N) crypto operations                 │
│    - Find M notes that are mine                                 │
│    ❌ This is the expensive part!                               │
│                                                                 │
│  Step 2: Check which are spent (CHEAP with Light Protocol!)     │
│    - Compute M nullifiers locally: O(M) hashes                  │
│    - Batch query via Helius: 1 RPC call!                        │
│      getMultipleCompressedAccounts(nullifiers)                  │
│    - Response tells us which exist (spent)                      │
│    ✅ O(1) network + O(M) local compute                         │
│                                                                 │
│  TOTAL: O(N) decrypt + O(1) network for spent check             │
│         The bottleneck is trial decrypt, NOT nullifier check!   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    INCREMENTAL SYNC (with state)                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Option A: Trial decrypt new outputs                            │
│    - Scan outputs since last sync: O(ΔN) decrypt                │
│    - Batch nullifier check: O(1) RPC                            │
│                                                                 │
│  Option B: Tags + PIR (if established)                          │
│    - PIR query for expected tag: O(1)                           │
│    - Decrypt specific tx: O(1)                                  │
│    - Batch nullifier check: O(1) RPC                            │
│                                                                 │
│  TOTAL: O(ΔN) or O(1) for discovery + O(1) for spent check      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### What Would Actually Help Recovery?

**Option 1: Encrypted Backup (Recommended)**

```
- Periodically backup wallet state (notes, counters, spent status)
- Encrypted to self (derived from seed)
- Store on cloud / IPFS / etc.
- Recovery: Download backup → decrypt → resume
```

**Option 2: Batch Nullifier Check via Light Protocol**

```
- Use getMultipleCompressedAccounts or getValidityProof
- Single RPC call for ALL nullifiers
- O(1) network round-trips instead of O(M)
- Already supported by Helius API!
```

**Option 3: Nullifier Bloom Filter (Further Optimization)**

```
- Indexer maintains bloom filter of all nullifiers
- Client downloads bloom filter (small!)
- For each note: check bloom filter locally
- Only do RPC call if bloom filter says "maybe spent"
- Reduces false positives to ~0 for unspent notes
```

**Option 3: TEE/FHE Sync Service (Privacy tradeoff)**

```
- Give viewing key to trusted service
- Service does expensive sync
- Returns: "here are your notes and spent status"
- Privacy risk: service learns your notes
```

**Option 4: Accept Expensive Recovery**

```
- Recovery is rare (device loss, corruption)
- Accept O(N) cost as one-time penalty
- Going forward: incremental sync is cheap
```

---

## Recovery Asymmetry: Sender vs Recipient

| Party | Can recover from seed? | How? |
|-------|----------------------|------|
| **Recipient (Bob)** | ✅ YES | `ss = ivk * epk` - ivk derived from seed |
| **Sender (Alice)** | ❌ NO (without C_out) | esk was random, not from seed |
| **Sender (Alice)** | ✅ YES (with C_out) | `ock = KDF(ovk, ...)` - ovk derived from seed |

**This is why C_out is important for production!**

---

## Summary

| Question | Answer |
|----------|--------|
| **Can esk be lost?** | Yes - and it breaks sender recovery! |
| **Can recipient still decrypt?** | ✅ Yes - uses `ivk * epk` |
| **Can sender recover sent notes?** | ❌ No (without C_out) |
| **What is C_out?** | Outgoing ciphertext, encrypted with sender's ovk |
| **Why does C_out help?** | Sender audit trail + links to spent nullifiers |
| **Does C_out help with spent detection?** | Partially - links tx to nullifier, not for discovery |
| **Is nullifier check expensive?** | No! Light Protocol supports batch queries |
| **Can we batch check nullifiers?** | ✅ Yes - getMultipleCompressedAccounts |
| **Does sync need proofs?** | ❌ No - just database queries |
| **Does spend need proofs?** | ✅ Yes - validity proof for input notes |
| **Is batch proof slow?** | ~200-500ms generation, ~100K CU verify |
| **Is it M proofs or 1?** | 1 batched proof (amortizes cost) |
| **Do tags help with recovery?** | ❌ No - tags need counter state which is lost |
| **Can tags be recovered?** | Partially - if sender_lt_pk stored in note |
| **Do tags help with ongoing sync?** | ✅ Yes - O(1) discovery instead of O(N) |
| **What if counterparty doesn't know I recovered?** | Desync! Their tag[N] won't match my tag[1] |
| **Solutions?** | Store sender_pk in note, window search, or OOB re-sync |
| **What helps recovery?** | Encrypted backups or accept O(N) one-time cost |
| **How does sync detect spent notes?** | Compute nullifier from nk + nonce, check if in set |
| **Can I see if notes I sent were spent?** | ❌ No - you don't have recipient's nk |
| **Can epk be lost?** | No - it's stored on-chain in tx data |
| **Why discard esk?** | Security - minimizes secret exposure |
| **Why use ephemeral keys?** | Forward secrecy, stateless |
| **Why doesn't this scale?** | O(N) trial decryption |
| **What's the alternative?** | Tag-based discovery + PIR (ongoing), backup (recovery) |

---

## References

- [Scaling Shielded Sync](https://hackmd.io/@aztec-network/scaling-shielded-sync) - Aztec's tag approach
- [Zcash Protocol Spec §4.19](https://zips.z.cash/protocol/protocol.pdf) - Note encryption
- [Private Information Retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval) - PIR basics
- [Tachyon](https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/) - Zcash scaling proposal

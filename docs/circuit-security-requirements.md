# Circuit Security Requirements

**CRITICAL: Keep this document updated as the protocol evolves.**

This document specifies everything that MUST be verified inside ZK circuits for the MASP to be secure. Missing any of these checks could lead to theft, double-spending, or other critical vulnerabilities.

See also:

- `docs/protocol.md` for the high-level protocol and responsibility split

---

## Overview

The MASP has three circuits, each with specific security requirements:

| Circuit | Purpose | Key Security Goal |
|---------|---------|------------------|
| **Shield** | Deposit transparent → shielded | Commitment integrity |
| **Transfer** | Shielded spend + output | Ownership + balance |
| **Unshield** | Withdraw shielded → transparent | Ownership + amount correctness |

---

## Responsibility Split (Who Checks What)

The protocol is safe only if **the circuit, chain, indexer, and client** each perform their required checks:

### In-circuit (ZK proof)

The circuit proves *private* statements and bindings that must hold for correctness and privacy:

- “I know the note plaintext that hashes to the commitment”
- “This note is a member of the commitment set for this anchor”
- “The nullifier is derived correctly from the owner’s key material”
- “Outputs are well-formed and balance is conserved”
- For unshield: “public withdrawal fields match the spent note”

### On-chain (program + verifier)

The chain enforces *public* state-transition rules:

- **Anchor validity**: anchor is in recent root history / valid state
- **Nullifier uniqueness**: reject double-spends (nullifier already present)
- **Proof verification**: verify the proof against the correct VK for the circuit
- **Token movements**: enforce SPL transfers in/out of the pool for shield/unshield

### Indexer / Client (note discovery + local integrity)

The client and indexer jointly enforce correct note discovery and wallet state:

- Indexer serves ciphertexts and witnesses (Merkle path / Light validity proof)
- Client verifies decrypted note plaintext ↔ commitment consistency before accepting a note
- Client checks spentness (nullifier) during sync/recovery before adding a note as spendable

---

## 1. Shield Circuit (Deposit)

**Public Inputs:**

- `new_commitment` - The note commitment being created
- `asset_id` - Which token (derived from mint address)
- `amount` - Deposit amount (public for matching with token transfer)

**Private Inputs:**

- `recipient` - Diversified address (pk_d.x)
- `nullifier_nonce` - Random, unique per note
- `note_randomness` - Random, hides note contents

### Required Constraints (Shield)

#### 1.1 Commitment Integrity ✅ CRITICAL

```text
commitment == Poseidon(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)
```

**Why:** Prevents creating commitments that don't correspond to valid notes.

### Who checks what (Shield)

- **Circuit must prove**
  - Commitment integrity (cm matches note fields)
  - Amount range check (u64)
  - Asset id binding (asset_id corresponds to the token being deposited)
- **Chain must enforce**
  - Actual SPL transfer of `(token_address, amount)` into the pool
  - Proof verification with `vk_shield`
  - Commitment append to the commitment set
- **Client/indexer must support**
  - Storing ciphertexts in transaction data for later scanning
  - Client-side commitment verification after decryption

#### 1.2 Amount Range Check ✅ CRITICAL

```text
amount < 2^64
```

**Why:** Prevents overflow attacks in balance conservation. Without this, an attacker could create a note with amount = p - 100 (where p is field modulus), which looks like a huge positive number but wraps to negative.

#### 1.3 Asset ID Derivation ✅ CRITICAL

```text
asset_id == Poseidon(DOM_ASSET, token_address)
```

**Why:** Binds the commitment to the actual token being deposited. Must match the public token being transferred on-chain.

#### 1.4 Recipient Format (Optional but Recommended)

```text
recipient is a valid field element (< field modulus)
```

**Why:** Prevents invalid addresses that could lock funds.

### Planned Statement Checklist (Shield)

The `shield` circuit entrypoint should be a clear audit trail that calls one function per statement:

- **Commitment preimage**: `new_commitment == H(asset_id, amount, recipient, nullifier_nonce, note_randomness)`
- **Amount range check**: `amount < 2^64`
- **Asset binding**: `asset_id` corresponds to the deposited token (program enforces SPL transfer)

---

## 2. Transfer Circuit (Shielded Spend + Output)

**Public Inputs:**

- `anchor` - Merkle root from history (proves tree state)
- `input_commitment` - Commitment being spent (binds membership witness to note preimage)
- `nullifier` - Reveals spent note (double-spend prevention)
- `new_commitment` - Output note commitment
- `tx_binding_hash` - Prevents transaction malleability

**Private Inputs (Spend side):**

- `note` - Full note plaintext being spent
- `merkle_path` - Siblings proving membership
- `spending_key` (or `ask`, `nsk`) - Proves ownership

**Private Inputs (Output side):**

- `output_note` - New note being created
- `output_randomness` - For commitment hiding

### Required Constraints (Transfer)

#### 2.1 Membership Proof ✅ CRITICAL

```text
merkle_root(note.commitment, merkle_path) == anchor
```

**Why:** Proves the input note exists in the commitment tree. Without this, an attacker could spend non-existent notes.

**Implementation note (Light Protocol):** in production, membership is expected to be proven by a **separate validity proof**
(e.g. Light Groth16) verified on-chain. In that model, the MASP spend circuit does **not** verify a Merkle path; instead it must
take `input_commitment` as a public input and prove knowledge of its preimage.

#### 2.2 Commitment Re-derivation ✅ CRITICAL

```text
input_commitment == Poseidon(DOM_NOTE_COMMIT, note.asset_id, note.amount, note.recipient, note.nullifier_nonce, note.note_randomness)
```

**Why:** Proves the spender knows the actual note contents, not just the commitment hash.

#### 2.3 Nullifier Derivation ✅ CRITICAL

```text
nullifier == Poseidon(DOM_NULLIFIER, nk, note.nullifier_nonce)
```

Where `nk` is derived from the spending key.

**Why:** Only the note owner can derive the correct nullifier. This proves ownership AND enables double-spend prevention.

#### 2.4 Ownership Authorization ✅ CRITICAL

```text
note.recipient == pk_d.x
pk_d == ivk * g_d
ivk == H(ak.x, nk.x)
ak == ask * G
nk == nsk * G
```

**Why:** Proves the spender owns the note (their address is the recipient).

#### 2.5 Output Commitment Integrity ✅ CRITICAL

```text
new_commitment == Poseidon(DOM_NOTE_COMMIT, output_note.asset_id, output_note.amount, output_note.recipient, output_note.nullifier_nonce, output_note.note_randomness)
```

**Why:** Output commitment must correspond to a valid note.

#### 2.6 Output Amount Range Check ✅ CRITICAL

```text
output_note.amount < 2^64
```

**Why:** Same overflow prevention as shield.

#### 2.7 Balance Conservation ✅ CRITICAL

**Single-asset (simple):**

```text
input_note.amount == output_note.amount + change_note.amount
```

**Multi-asset (with α-tags):**

```text
α = Poseidon(DOM_ASSET_ALPHA, tx_binding_hash)
tag_in = Poseidon(DOM_ASSET_TAG, α, input_note.asset_id)
tag_out = Poseidon(DOM_ASSET_TAG, α, output_note.asset_id)
tag_change = Poseidon(DOM_ASSET_TAG, α, change_note.asset_id)

input_note.amount * tag_in == output_note.amount * tag_out + change_note.amount * tag_change
```

**Why:** Prevents creating value from nothing or transferring between asset types.

#### 2.8 Asset Type Preservation ✅ CRITICAL (for single-asset transfer)

```text
input_note.asset_id == output_note.asset_id
input_note.asset_id == change_note.asset_id
```

**Why:** Prevents cross-asset transfers (unless explicitly designed for swaps).

#### 2.9 Nullifier Nonce Derivation ✅ CRITICAL

```text
output_note.nullifier_nonce == Poseidon(DOM_NULLIFIER_NONCE, input_commitment, output_index)
```

**Why:** Ensures each output note has a unique nullifier nonce derived from the transaction. Prevents nullifier collisions.

#### 2.10 Transaction Binding ✅ CRITICAL

```text
tx_binding_hash == Poseidon(DOM_TX_BINDING, anchor, nullifier, new_commitment, ...)
```

**Why:** Binds all transaction components together, preventing component substitution attacks.

### Planned Statement Checklist (Transfer)

The `transfer` circuit entrypoint should be a clear audit trail that calls one function per statement:

- **External membership**: membership witness is verified outside the circuit (Merkle path in mocks; Light validity proof on-chain in production).
  - Circuit must still bind `input_commitment` to note plaintext (preimage knowledge).
- **Input commitment preimage**: `input_commitment == H(note_fields...)`
- **Nullifier derivation / ownership binding**: `nullifier == H(nk, note_nullifier_nonce)` (+ later full Orchard/Sapling-style authorization)
- **Output commitments well-formed**: each `output_commitment_i == H(out_note_i_fields...)`
- **Output nullifier nonce derivation** (later): derive each output’s `nullifier_nonce` from transaction context to avoid collisions
- **Amount range checks**: all amounts < 2^64
- **Balance conservation**:
  - single-asset first
  - multi-asset later via α-tags
- **Transaction binding**: `tx_binding_hash` commits to the full action intent

### Who checks what (Transfer)

- **Circuit must prove**
  - Membership against `anchor`
  - Input commitment preimage (knowledge of note plaintext)
  - Nullifier derivation from `nk` and note nonce (ownership binding)
  - Output commitment preimages (outputs are real notes)
  - Amount range checks
  - Balance conservation (single-asset first; multi-asset later via α-tags)
  - Tx binding (proof is bound to the specific transaction intent)
- **Chain must enforce**
  - Anchor validity (root history policy)
  - Nullifier uniqueness (reject double-spends)
  - Proof verification with `vk_transfer`
  - Append output commitments + store ciphertexts
- **Client/indexer must support**
  - Indexer serving ciphertexts + witnesses
  - Client verifying ciphertext decrypts to a note matching the output commitment

---

## 3. Unshield Circuit (Withdraw)

**Public Inputs:**

- `anchor` - Merkle root
- `input_commitment` - Commitment being spent (binds membership witness to note preimage)
- `nullifier` - Spent note identifier
- `amount` - Amount being withdrawn (NOW PUBLIC)
- `recipient` - Transparent recipient address (NOW PUBLIC)
- `asset_id` - Which token (NOW PUBLIC)

**Private Inputs:**

- `note` - Full note plaintext
- `merkle_path` - Membership proof
- `spending_key` - Proves ownership

### Required Constraints (Unshield)

#### 3.1-3.4 Same as Transfer (Membership, Commitment, Nullifier, Ownership)

#### 3.5 Public Output Binding ✅ CRITICAL

```text
note.amount == public_amount
note.asset_id == public_asset_id
```

**Why:** The withdrawn amount and asset MUST match what's in the note. Otherwise, an attacker could withdraw more than they deposited.

### Planned Statement Checklist (Unshield)

The `unshield` circuit entrypoint should be a clear audit trail that calls one function per statement:

- **External membership**: membership witness is verified outside the circuit (Merkle path in mocks; Light validity proof on-chain in production).
  - Circuit must still bind `input_commitment` to note plaintext (preimage knowledge).
- **Input commitment preimage**: `input_commitment == H(note_fields...)`
- **Nullifier derivation / ownership binding**: `nullifier == H(nk, note_nullifier_nonce)` (+ later full authorization)
- **Public withdrawal binding**:
  - `note.amount == public_amount`
  - `note.asset_id == public_asset_id`
  - recipient encoding must match program semantics

### Who checks what (Unshield)

- **Circuit must prove**
  - Membership, input preimage, nullifier derivation, ownership authorization (same as transfer)
  - Public output binding:
    - `note.amount == public_amount`
    - `note.asset_id == public_asset_id`
    - (Recipient encoding decision must match program semantics)
- **Chain must enforce**
  - Anchor validity
  - Nullifier uniqueness
  - Proof verification with `vk_unshield`
  - SPL transfer of `(token_address, amount)` to `recipient`

---

## 4. Cross-Circuit Security

### 4.1 Domain Separation ✅ CRITICAL

All hash operations MUST use domain tags:

```text
DomainTag::NoteCommitment = 1
DomainTag::Nullifier = 2
DomainTag::AssetId = 3
DomainTag::MerkleNode = 4
... (see domain.rs for full list)
```

**Why:** Prevents cross-domain attacks where a hash from one context is reused in another.

### 4.2 Field Element Validation

All field elements MUST be < field modulus:

- BN254 scalar field: p ≈ 2^254
- Inputs from user are untrusted

**Why:** Malformed inputs could bypass checks.

### 4.3 Merkle Path Validation

Merkle path must be correct depth (32 levels):

```text
path.len() == TREE_DEPTH
```

**Why:** Wrong depth could allow fake membership proofs.

---

## 5. Out-of-Circuit Integrity (NOT in ZK, but MUST be enforced)

These are enforced by the on-chain program or client, not the circuit:

### 5.1 Nullifier Uniqueness (On-chain) ✅ CRITICAL

```text
nullifier NOT IN nullifier_set
```

**Enforced by:** Solana program (PDA or Light Protocol)

### 5.2 Anchor Validity (On-chain) ✅ CRITICAL

```text
anchor IN anchor_history
```

**Enforced by:** Solana program (ring buffer of recent roots)

### 5.3 Ciphertext-Commitment Binding (Client) ⚠️ IMPORTANT

```text
decrypt(ciphertext) → note_plaintext
H(note_plaintext) == commitment
```

**Enforced by:** Recipient client after decryption

**Attack if missing:** Sender encrypts wrong data → recipient can't spend (griefing, not theft)

### 5.4 Proof Verification (On-chain) ✅ CRITICAL

```text
verify(proof, public_inputs, vk) == true
```

**Enforced by:** Solana program (UltraPlonk verifier)

---

## 6. Security Invariants

### Must NEVER be possible

| Attack | Prevention |
|--------|-----------|
| Create value from nothing | Balance conservation check |
| Double-spend a note | Nullifier uniqueness (on-chain) |
| Spend someone else's note | Ownership proof (nullifier key) |
| Spend non-existent note | Merkle membership proof |
| Withdraw wrong amount | Public output binding |
| Cross-asset value transfer | Asset type preservation / α-tags |
| Replay old transaction | Anchor freshness + nullifier |
| Forge commitment | Commitment integrity check |

---

## 7. Testing Checklist

For each circuit, test:

- [ ] Valid transaction succeeds
- [ ] Wrong commitment fails
- [ ] Wrong nullifier fails
- [ ] Wrong Merkle path fails
- [ ] Wrong ownership (different key) fails
- [ ] Balance overflow fails
- [ ] Balance underflow fails
- [ ] Asset type mismatch fails (if applicable)
- [ ] Stale anchor fails (if not in history)

---

## 8. Audit Priorities

**P0 (Critical):**

1. Balance conservation
2. Nullifier derivation
3. Ownership verification
4. Merkle membership

**P1 (High):**
5. Range checks
6. Domain separation
7. Output commitment integrity

**P2 (Medium):**
8. Field element validation
9. Transaction binding

---

## 9. Change Log

| Date | Change | Affected Circuits |
|------|--------|------------------|
| 2024-12-16 | Initial document | All |

---

## 10. References

- [Zcash Protocol Spec §4-5](https://zips.z.cash/protocol/protocol.pdf)
- [knowledge.md](../knowledge.md) - Architecture decisions
- [domain.rs](../client/src/domain.rs) - Domain tag definitions

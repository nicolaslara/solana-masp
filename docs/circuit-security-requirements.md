# Circuit Security Requirements

**CRITICAL: Keep this document updated as the protocol evolves.**

This document specifies everything that MUST be verified inside ZK circuits for the MASP to be secure. Missing any of these checks could lead to theft, double-spending, or other critical vulnerabilities.

---

## Overview

The MASP has three circuits, each with specific security requirements:

| Circuit | Purpose | Key Security Goal |
|---------|---------|------------------|
| **Shield** | Deposit transparent → shielded | Commitment integrity |
| **Transfer** | Shielded spend + output | Ownership + balance |
| **Unshield** | Withdraw shielded → transparent | Ownership + amount correctness |

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

### Required Constraints

#### 1.1 Commitment Integrity ✅ CRITICAL

```
commitment == Poseidon(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)
```

**Why:** Prevents creating commitments that don't correspond to valid notes.

#### 1.2 Amount Range Check ✅ CRITICAL

```
amount < 2^64
```

**Why:** Prevents overflow attacks in balance conservation. Without this, an attacker could create a note with amount = p - 100 (where p is field modulus), which looks like a huge positive number but wraps to negative.

#### 1.3 Asset ID Derivation ✅ CRITICAL

```
asset_id == Poseidon(DOM_ASSET, token_address)
```

**Why:** Binds the commitment to the actual token being deposited. Must match the public token being transferred on-chain.

#### 1.4 Recipient Format (Optional but Recommended)

```
recipient is a valid field element (< field modulus)
```

**Why:** Prevents invalid addresses that could lock funds.

---

## 2. Transfer Circuit (Shielded Spend + Output)

**Public Inputs:**

- `anchor` - Merkle root from history (proves tree state)
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

### Required Constraints

#### 2.1 Membership Proof ✅ CRITICAL

```
merkle_root(note.commitment, merkle_path) == anchor
```

**Why:** Proves the input note exists in the commitment tree. Without this, an attacker could spend non-existent notes.

#### 2.2 Commitment Re-derivation ✅ CRITICAL

```
input_commitment == Poseidon(DOM_NOTE_COMMIT, note.asset_id, note.amount, note.recipient, note.nullifier_nonce, note.note_randomness)
```

**Why:** Proves the spender knows the actual note contents, not just the commitment hash.

#### 2.3 Nullifier Derivation ✅ CRITICAL

```
nullifier == Poseidon(DOM_NULLIFIER, nk, note.nullifier_nonce)
```

Where `nk` is derived from the spending key.

**Why:** Only the note owner can derive the correct nullifier. This proves ownership AND enables double-spend prevention.

#### 2.4 Ownership Authorization ✅ CRITICAL

```
note.recipient == pk_d.x
pk_d == ivk * g_d
ivk == H(ak.x, nk.x)
ak == ask * G
nk == nsk * G
```

**Why:** Proves the spender owns the note (their address is the recipient).

#### 2.5 Output Commitment Integrity ✅ CRITICAL

```
new_commitment == Poseidon(DOM_NOTE_COMMIT, output_note.asset_id, output_note.amount, output_note.recipient, output_note.nullifier_nonce, output_note.note_randomness)
```

**Why:** Output commitment must correspond to a valid note.

#### 2.6 Output Amount Range Check ✅ CRITICAL

```
output_note.amount < 2^64
```

**Why:** Same overflow prevention as shield.

#### 2.7 Balance Conservation ✅ CRITICAL

**Single-asset (simple):**

```
input_note.amount == output_note.amount + change_note.amount
```

**Multi-asset (with α-tags):**

```
α = Poseidon(DOM_ASSET_ALPHA, tx_binding_hash)
tag_in = Poseidon(DOM_ASSET_TAG, α, input_note.asset_id)
tag_out = Poseidon(DOM_ASSET_TAG, α, output_note.asset_id)
tag_change = Poseidon(DOM_ASSET_TAG, α, change_note.asset_id)

input_note.amount * tag_in == output_note.amount * tag_out + change_note.amount * tag_change
```

**Why:** Prevents creating value from nothing or transferring between asset types.

#### 2.8 Asset Type Preservation ✅ CRITICAL (for single-asset transfer)

```
input_note.asset_id == output_note.asset_id
input_note.asset_id == change_note.asset_id
```

**Why:** Prevents cross-asset transfers (unless explicitly designed for swaps).

#### 2.9 Nullifier Nonce Derivation ✅ CRITICAL

```
output_note.nullifier_nonce == Poseidon(DOM_NULLIFIER_NONCE, input_commitment, output_index)
```

**Why:** Ensures each output note has a unique nullifier nonce derived from the transaction. Prevents nullifier collisions.

#### 2.10 Transaction Binding ✅ CRITICAL

```
tx_binding_hash == Poseidon(DOM_TX_BINDING, anchor, nullifier, new_commitment, ...)
```

**Why:** Binds all transaction components together, preventing component substitution attacks.

---

## 3. Unshield Circuit (Withdraw)

**Public Inputs:**

- `anchor` - Merkle root
- `nullifier` - Spent note identifier
- `amount` - Amount being withdrawn (NOW PUBLIC)
- `recipient` - Transparent recipient address (NOW PUBLIC)
- `asset_id` - Which token (NOW PUBLIC)

**Private Inputs:**

- `note` - Full note plaintext
- `merkle_path` - Membership proof
- `spending_key` - Proves ownership

### Required Constraints

#### 3.1-3.4 Same as Transfer (Membership, Commitment, Nullifier, Ownership)

#### 3.5 Public Output Binding ✅ CRITICAL

```
note.amount == public_amount
note.asset_id == public_asset_id
```

**Why:** The withdrawn amount and asset MUST match what's in the note. Otherwise, an attacker could withdraw more than they deposited.

---

## 4. Cross-Circuit Security

### 4.1 Domain Separation ✅ CRITICAL

All hash operations MUST use domain tags:

```
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

```
path.len() == TREE_DEPTH
```

**Why:** Wrong depth could allow fake membership proofs.

---

## 5. Out-of-Circuit Integrity (NOT in ZK, but MUST be enforced)

These are enforced by the on-chain program or client, not the circuit:

### 5.1 Nullifier Uniqueness (On-chain) ✅ CRITICAL

```
nullifier NOT IN nullifier_set
```

**Enforced by:** Solana program (PDA or Light Protocol)

### 5.2 Anchor Validity (On-chain) ✅ CRITICAL

```
anchor IN anchor_history
```

**Enforced by:** Solana program (ring buffer of recent roots)

### 5.3 Ciphertext-Commitment Binding (Client) ⚠️ IMPORTANT

```
decrypt(ciphertext) → note_plaintext
H(note_plaintext) == commitment
```

**Enforced by:** Recipient client after decryption

**Attack if missing:** Sender encrypts wrong data → recipient can't spend (griefing, not theft)

### 5.4 Proof Verification (On-chain) ✅ CRITICAL

```
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

# Circuit Security Requirements

**CRITICAL: Keep this document updated as the protocol evolves.**

This document specifies everything that MUST be verified inside ZK circuits for the MASP to be secure. Missing any of these checks could lead to theft, double-spending, or other critical vulnerabilities.

See also:

- `docs/protocol-soundness.md` (**primary / normative**) for protocol soundness + privacy invariants
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
- `public_asset_id` - Which token (derived from mint address)
- `public_amount` - Deposit amount (public for matching with token transfer)
- `ct_hash` - Ciphertext binding hash (Option 1A weak binding)

**Private Inputs:**

- `recipient` - Diversified address (pk_d.x)
- `diversifier_index` - Index for address derivation
- `nullifier_nonce` - Random, unique per note
- `note_randomness` - Random, hides note contents

### Required Constraints (Shield)

#### 1.1 Commitment Integrity ✅ CRITICAL ✅ IMPLEMENTED

```text
commitment == Poseidon2(DOM_NOTE_COMMIT, asset_id, amount, recipient, diversifier_index, nullifier_nonce, note_randomness)
```

**Why:** Prevents creating commitments that don't correspond to valid notes.

**Implementation:** `circuits/masp/shield/src/main.nr` → `prove_note_preimage_hashes_to_commitment()`

#### 1.2 Amount Range Check ✅ CRITICAL ✅ IMPLEMENTED

```text
amount < 2^64
```

**Why:** Prevents overflow attacks in balance conservation.

**Implementation:** Enforced by Noir's `u64` type system (automatic range constraints).

#### 1.3 Asset ID Binding ⚠️ CHAIN-ENFORCED

```text
asset_id == Poseidon(DOM_ASSET, token_address)
```

**Current implementation:** `prove_asset_id_binding()` is a **no-op** in the circuit. The chain program MUST compute `asset_id = H(token_address)` from the actual SPL mint and use that value as the public input.

**Why this is safe:** The prover cannot choose an arbitrary `asset_id` — it's computed by the chain from the real token being deposited.

#### 1.4 Ciphertext Hash Binding ✅ IMPLEMENTED

```text
ct_hash != 0  (for enabled outputs)
```

**Why:** Binds the proof to a specific ciphertext (Option 1A weak binding). The wallet verifies `ct_hash == H(DOM_CIPHERTEXT, ciphertext_bytes)` when accepting notes.

**Implementation:** `circuits/masp/shield/src/main.nr` → `assert(public.ct_hash != 0)`

### Who checks what (Shield)

- **Circuit must prove**
  - Commitment integrity (cm matches note fields)
  - Amount range check (u64 type)
  - Ciphertext hash is non-zero
- **Chain must enforce**
  - Asset ID derivation from actual SPL mint
  - Actual SPL transfer of `(token_address, amount)` into the pool
  - Proof verification with `vk_shield`
  - Commitment append to the commitment set
- **Client/indexer must support**
  - Storing ciphertexts in transaction data for later scanning
  - Client-side commitment verification after decryption
  - Verify `ct_hash` matches fetched ciphertext bytes

---

## 2. Transfer Circuit (N→M Shielded Transfer)

The transfer circuit supports flexible **N inputs → M outputs** within fixed compile-time maxima.

- **MAX_INPUTS = 3**
- **MAX_OUTPUTS = 3**

Disabled slots are padded with zeros and gated by enable flags.

**Public Inputs:**

| Input | Type | Description |
|-------|------|-------------|
| `anchor` | Field | Shared Merkle root for all inputs |
| `nullifiers[3]` | [Field; 3] | Padded with 0 for disabled inputs |
| `output_commitments[3]` | [Field; 3] | Padded with 0 for disabled outputs |
| `input_count` | u32 | Number of enabled inputs (1–3) |
| `output_count` | u32 | Number of enabled outputs (1–3) |
| `ct_hashes[3]` | [Field; 3] | Ciphertext hashes (0 for disabled) |
| `tx_binding` | Field | Transaction binding hash |

**Private Inputs (per input slot):**

- `enabled` - Whether this slot is active
- `note_*` - Full note plaintext fields
- `spending_key` - Root secret (circuit derives `ask`, `nsk`)
- `siblings[32]`, `path_indices[32]` - Merkle path

**Private Inputs (per output slot):**

- `enabled` - Whether this slot is active
- `note_*` - Output note plaintext fields

**Private Input (shared):**

- `transfer_asset_id` - Single asset for all enabled inputs/outputs

### Required Constraints (Transfer)

#### 2.1 Membership Proof ✅ CRITICAL ✅ IMPLEMENTED

For each **enabled** input:

```text
merkle_root(input_commitment, siblings, path_indices) == anchor
```

**Implementation:** `circuits/masp/common/src/statements.nr` → `prove_merkle_membership()`

#### 2.2 Commitment Re-derivation ✅ CRITICAL ✅ IMPLEMENTED

For each **enabled** input:

```text
input_commitment == Poseidon2(DOM_NOTE_COMMIT, note_asset_id, note_amount, note_recipient, diversifier_index, nullifier_nonce, note_randomness)
```

**Implementation:** `compute_note_commitment()` in circuit

#### 2.3 Nullifier Derivation ✅ CRITICAL ✅ IMPLEMENTED

For each **enabled** input:

```text
nullifier == Poseidon2(DOM_NULLIFIER, nsk, note_nullifier_nonce)
```

**CRITICAL SECURITY:** Uses `nsk` (nullifier SECRET), NOT `nk.x` (public). This ensures FullViewingKey holders cannot spend.

**Implementation:** `prove_nullifier_derivation()` with `auth_result.nsk`

#### 2.4 Ownership Authorization ✅ CRITICAL ✅ IMPLEMENTED

Full EC-based spend authorization:

```text
ask = H(DOM_AUTH_SECRET, spending_key)
nsk = H(DOM_NULLIFIER_SECRET, spending_key)
ak = ask * G
nk = nsk * G
ivk = H(DOM_IVK, ak.x, nk.x)
g_d = H(diversifier_index) * G
pk_d = ivk * g_d
assert(note_recipient == pk_d.x)
```

**Implementation:** `prove_spend_authorization()` + `verify_inputs_same_owner()` (uses Grumpkin EC ops)

#### 2.5 Output Commitment Integrity ✅ CRITICAL ✅ IMPLEMENTED

For each **enabled** output:

```text
output_commitment == Poseidon2(DOM_NOTE_COMMIT, out_asset_id, out_amount, out_recipient, out_diversifier_index, out_nullifier_nonce, out_randomness)
```

**Implementation:** Recomputes and asserts against `public.output_commitments[j]`

#### 2.6 Amount Range Check ✅ CRITICAL ✅ IMPLEMENTED

All amounts are `u64` in Noir → automatic range constraints.

#### 2.7 Balance Conservation ✅ CRITICAL ✅ IMPLEMENTED

Single-asset semantics:

```text
Σ(enabled_input_amounts) == Σ(enabled_output_amounts)
```

All enabled inputs/outputs must share the same `asset_id`.

**Implementation:** `verify_balance_conservation()` in `transfer/src/main.nr`

#### 2.8 Output Nonce Derivation ✅ CRITICAL ✅ IMPLEMENTED

For each **enabled** output:

```text
out_nullifier_nonce == Poseidon2(DOM_NULLIFIER_NONCE, tx_binding, output_index)
```

**Why:** With multiple inputs, we can't use `input_commitment` for nonce derivation. Using `tx_binding` ensures uniqueness.

**Implementation:** `derive_output_nonce()` in circuit

#### 2.9 Transaction Binding ✅ CRITICAL ✅ IMPLEMENTED

```text
tx_binding == Poseidon2(DOM_TX_BINDING, 2, anchor, input_count, output_count, h_nf)
where h_nf = Poseidon2(nullifiers[0..MAX_INPUTS])
```

**Why:** Prevents relayers from reordering/splicing nullifiers across transactions.

**Implementation:** `compute_tx_binding()` in circuit

#### 2.10 Ciphertext Hash Binding ✅ IMPLEMENTED

For each **enabled** output: `ct_hashes[j] != 0`
For each **disabled** output: `ct_hashes[j] == 0`

**Implementation:** `verify_ct_hashes()` in circuit

#### 2.11 Count Correctness + Slot Gating ✅ IMPLEMENTED

```text
1 ≤ input_count ≤ MAX_INPUTS
1 ≤ output_count ≤ MAX_OUTPUTS
input_count == Σ(input_enabled[i])
output_count == Σ(output_enabled[j])
```

Disabled inputs: `public.nullifiers[i] == 0`
Disabled outputs: `public.output_commitments[j] == 0`

**Implementation:** `verify_counts()`, `verify_disabled_nullifiers()`, `verify_disabled_outputs()`

### Who checks what (Transfer)

- **Circuit must prove**
  - Membership against shared `anchor` for all enabled inputs
  - Input commitment preimage (note plaintext knowledge)
  - SpendingKey-only nullifier derivation (`nsk`, not `nk.x`)
  - Full EC spend authorization
  - Output commitment integrity
  - Deterministic output nonce derivation
  - Single-asset balance conservation
  - Transaction binding
  - Ciphertext hash binding
  - Count/gating correctness
- **Chain must enforce**
  - Anchor validity (root history policy)
  - Nullifier uniqueness for all non-zero nullifiers
  - Proof verification with `vk_transfer`
  - Append non-zero output commitments
- **Client/indexer must support**
  - Indexer serving ciphertexts + Merkle witnesses
  - Client verifying `ct_hash` before trial decryption
  - Client verifying plaintext ↔ commitment consistency

---

## 3. Unshield Circuit (Withdraw)

**Public Inputs:**

| Input | Type | Description |
|-------|------|-------------|
| `anchor` | Field | Merkle root for membership proof |
| `nullifier` | Field | Spent note identifier |
| `tx_binding` | Field | Transaction binding hash |
| `public_amount` | u64 | Amount being withdrawn |
| `public_recipient_limbs` | [u64; 4] | Recipient as 4×u64 LE limbs |
| `public_asset_id` | Field | Which token |

**Private Inputs:**

- `note_*` - Full note plaintext fields
- `spending_key` - Root secret (circuit derives `ask`, `nsk`)
- `siblings[32]`, `path_indices[32]` - Merkle path

### Required Constraints (Unshield)

#### 3.1 Membership Proof ✅ CRITICAL ✅ IMPLEMENTED

```text
merkle_root(input_commitment, siblings, path_indices) == anchor
```

**Implementation:** `prove_merkle_membership()` with private `input_commitment`

#### 3.2 Commitment Re-derivation ✅ CRITICAL ✅ IMPLEMENTED

```text
input_commitment == Poseidon2(DOM_NOTE_COMMIT, note_fields...)
```

**Implementation:** `prove_note_preimage_hashes_to_commitment()`

#### 3.3 Nullifier Derivation ✅ CRITICAL ✅ IMPLEMENTED

```text
nullifier == Poseidon2(DOM_NULLIFIER, nsk, note_nullifier_nonce)
```

**CRITICAL SECURITY:** Uses `nsk` (secret), NOT `nk.x` (public).

**Implementation:** `prove_nullifier_derivation()` with `auth_result.nsk`

#### 3.4 Ownership Authorization ✅ CRITICAL ✅ IMPLEMENTED

Same EC-based authorization as Transfer.

**Implementation:** `prove_spend_authorization()`

#### 3.5 Public Withdrawal Binding ✅ CRITICAL ✅ IMPLEMENTED

```text
note.amount == public_amount
note.asset_id == public_asset_id
```

**Implementation:** `check_public_withdraw_binding_single_asset_action()`

#### 3.6 Transaction Binding ✅ CRITICAL ✅ IMPLEMENTED

```text
tx_binding == Poseidon2(DOM_TX_BINDING, 3, anchor, nullifier, public_amount, 
                        limbs[0], limbs[1], limbs[2], limbs[3], public_asset_id)
```

**Why:** Binds the recipient address to the proof intent, preventing recipient swaps.

**CRITICAL:** `input_commitment` is NOT in `tx_binding` (it's private; proof binds via preimage knowledge).

**Implementation:** Inline Poseidon2 in `unshield/src/main.nr`

#### 3.7 Recipient Encoding ✅ IMPLEMENTED

Recipient is encoded as **4×u64 little-endian limbs**, NOT as a single Field.

**Why:** BN254 scalar field modulus p < 2^254, so `Fr::from_be_bytes_mod_order(32-byte pubkey)` is many-to-one. Distinct 32-byte recipients could collide to the same Field value.

**Implementation:** `public_recipient_limbs: [u64; 4]` as public inputs; chain recomputes limbs from actual recipient and rejects mismatches.

### Who checks what (Unshield)

- **Circuit must prove**
  - Membership against `anchor`
  - Input commitment preimage (note plaintext knowledge)
  - SpendingKey-only nullifier derivation (`nsk`, not `nk.x`)
  - Full EC spend authorization
  - Public withdrawal binding (amount, asset)
  - Transaction binding (includes recipient limbs)
- **Chain must enforce**
  - Anchor validity
  - Nullifier uniqueness
  - Proof verification with `vk_unshield`
  - Recompute `public_recipient_limbs` from actual recipient bytes and reject mismatch
  - SPL transfer of `(token_address, amount)` to `recipient`
- **Client/indexer must support**
  - Indexer serving Merkle witnesses
  - Client building correct `public_recipient_limbs` encoding

---

## 4. Cross-Circuit Security

### 4.1 Domain Separation ✅ CRITICAL

All hash operations MUST use domain tags:

```text
DomainTag::NoteCommitment = 1      // Note commitment
DomainTag::Nullifier = 2           // Nullifier derivation
DomainTag::AssetId = 3             // Asset ID binding
DomainTag::Ciphertext = 4          // ct_hash (client-side only)
DomainTag::TransactionBinding = 5  // tx_binding
DomainTag::NullifierNonce = 6      // Output nonce derivation
DomainTag::MerkleNode = 7          // Merkle tree internal nodes
DomainTag::IncomingViewingKey = 8  // IVK derivation
DomainTag::AuthorizationSecret = 9 // ask = H(9, spending_key)
DomainTag::NullifierSecret = 10    // nsk = H(10, spending_key)
```

**Source of truth:** `circuits/masp/common/src/statements.nr` (circuit), `client/src/domain.rs` (Rust)

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
| Cross-asset value transfer | Asset type preservation (current) / value-commitment-based enforcement (future) |
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

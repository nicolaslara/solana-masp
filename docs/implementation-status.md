# Implementation Status

This document tracks the implementation status of protocol statements from `docs/protocol-soundness.md` across **Rust mocks** and **Noir circuits**.

**Legend:**

- ✅ = Implemented (real constraints/checks)
- ⚠️ = Placeholder (interface exists, no-op implementation)
- ❌ = Not implemented
- n/a = Not applicable to this circuit/component

---

## Shield (S1–S5)

| ID | Statement | Mock | Circuit | Notes |
|----|-----------|------|---------|-------|
| **S1** | Transparent boundary correctness (token transfer) | ❌ | n/a | Chain-only; no SPL transfers in mocks yet |
| **S2** | Commitment integrity: `cm == H(note_fields...)` | ✅ | ✅ | `compute_note_commitment` |
| **S3** | Asset binding: `asset_id == H(token_address)` | ✅ | n/a | **Chain-only by design:** chain computes `asset_id` from SPL mint; circuit uses chain-provided value |
| **S4** | Amount range: `amount < 2^64` | ✅ | ✅ | Rust u64 type; Noir u64 type |
| **S5** | Output ciphertext hash binding (ct_hash) | ✅ | ✅ | Option 1A weak binding; `assert(ct_hash != 0)` |

### Mock Implementation Locations (Shield)

- **S2**: `client/src/proofs.rs` → `mock_check_shield()` checks `Note::commitment() == new_commitment`
- **S3**: `client/src/proofs.rs` → checks `pi.public_asset_id == private.note_asset_id`
- **S4**: Rust type system (`u64`)
- **S5**: `client/src/proofs.rs` → checks `pi.ct_hash` is non-zero

### Circuit Implementation Locations (Shield)

- **S2**: `circuits/masp/shield/src/main.nr` → calls `prove_note_preimage_hashes_to_commitment()`
- **S3**: Chain-enforced (not in circuit); `prove_asset_id_binding()` is a no-op placeholder for documentation
- **S4**: Noir type system (`u64`)
- **S5**: `circuits/masp/shield/src/main.nr` → `assert(public.ct_hash != 0)`

---

## Transfer (T1–T9)

| ID | Statement | Mock | Circuit | Notes |
|----|-----------|------|---------|-------|
| **T1** | Membership: Merkle path against anchor | ✅ | ✅ | `prove_merkle_membership` with Poseidon2 |
| **T2** | Spend authorization (SpendingKey-only) | ✅ | ✅ | Uses Grumpkin EC ops; derives `ask`/`nsk` from `spending_key` |
| **T2b** | Transaction binding hash | ✅ | ✅ | `tx_binding_transfer()` / `compute_tx_binding()` |
| **T2c** | Output ciphertext hash binding (ct_hashes) | ✅ | ✅ | Option 1A weak binding |
| **T3** | Input preimage knowledge: `cm == H(note_fields...)` | ✅ | ✅ | `compute_note_commitment` |
| **T4** | Nullifier correctness: `nf == H(nsk, nonce)` | ✅ | ✅ | **CRITICAL:** Uses `nsk` (SECRET), not `nk.x` (public) |
| **T5** | Output well-formedness: `out_cm == H(out_note...)` | ✅ | ✅ | Circuit recomputes and asserts |
| **T6** | Output nonce derivation: `nonce == H(tx_binding, idx)` | ✅ | ✅ | `derive_output_nonce_nm()` / `derive_output_nonce()` |
| **T7** | Value conservation (single-asset) | ✅ | ✅ | `verify_balance_conservation` |
| **T7b** | Count correctness + slot gating | ✅ | ✅ | `verify_counts` |
| **T8** | Nullifier uniqueness | ✅ | n/a | Chain-only; mock rejects duplicates |
| **T9** | Anchor validity | ✅ | n/a | Chain-only; mock checks `is_valid_anchor()` |

### Mock Implementation Locations (Transfer)

- **T1**: `client/src/proofs.rs` → `mock_check_transfer()` verifies Merkle path
- **T2**: `client/src/proofs.rs` → `mock_check_spend_authorization()` checks key derivation
- **T2b**: `client/src/tx_binding.rs` → `tx_binding_transfer()`
- **T3**: `client/src/proofs.rs` → recomputes commitment from note fields
- **T4**: `client/src/proofs.rs` → `compute_nullifier(nsk, nonce) == public.nullifiers[i]` (**uses nsk secret**)
- **T5**: `client/src/proofs.rs` → `note.commitment() == public.output_commitments[j]`
- **T6**: `client/src/proofs.rs` → `derive_output_nonce_nm(tx_binding, j)`
- **T7**: `client/src/proofs.rs` → integer sum comparison
- **T8**: `client/src/mock.rs` → `MockChain::insert_nullifier()` rejects duplicates

### Circuit Implementation Locations (Transfer)

- **T1**: `circuits/masp/common/src/statements.nr` → `prove_merkle_membership()`
- **T2**: `circuits/masp/common/src/statements.nr` → `prove_spend_authorization()` (full Grumpkin EC ops)
- **T2b**: `circuits/masp/transfer/src/main.nr` → `compute_tx_binding()`
- **T3**: `circuits/masp/transfer/src/main.nr` → `prove_note_preimage_hashes_to_commitment()`
- **T4**: `circuits/masp/common/src/statements.nr` → `prove_nullifier_derivation()`
- **T5**: `circuits/masp/transfer/src/main.nr` → `compute_note_commitment()` for outputs
- **T6**: `circuits/masp/transfer/src/main.nr` → `derive_output_nonce()`
- **T7**: `circuits/masp/transfer/src/main.nr` → `verify_balance_conservation()`
- **T7b**: `circuits/masp/transfer/src/main.nr` → `verify_counts()`

---

## Unshield (U1–U3)

| ID | Statement | Mock | Circuit | Notes |
|----|-----------|------|---------|-------|
| **U1** | Public withdrawal amount/asset binding | ✅ | ✅ | `check_public_withdraw_binding_single_asset` |
| **U2** | Public recipient binding via tx_binding | ✅ | ✅ | Poseidon2 inline in circuit |
| **U3** | Transparent withdrawal (SPL transfer) | ❌ | n/a | Chain-only; no SPL transfers in mocks yet |

### Mock Implementation Locations (Unshield)

- **U1**: `client/src/proofs.rs` → `mock_check_unshield()` checks amounts/asset match
- **U2**: `client/src/tx_binding.rs` → `tx_binding_unshield()`

### Circuit Implementation Locations (Unshield)

- **U1**: `circuits/masp/unshield/src/main.nr` → `check_public_withdraw_binding_single_asset_action()`
- **U2**: `circuits/masp/unshield/src/main.nr` → inline Poseidon2 `tx_binding` recomputation

---

## Shared Statements (All Circuits)

| Statement | Mock | Circuit | Notes |
|-----------|------|---------|-------|
| Membership (Merkle path) | ✅ | ✅ | Poseidon2 `merkle_hash` |
| Note commitment derivation | ✅ | ✅ | Poseidon2 `compute_note_commitment` |
| Nullifier derivation | ✅ | ✅ | Poseidon2 `compute_nullifier(nsk, nonce)` - **uses nsk SECRET** |
| Spend authorization | ✅ | ✅ | Grumpkin EC ops; derives `ask`/`nsk` from `spending_key` in-circuit |

---

## Wallet/Client Integrity Checks

These are NOT proven in-circuit but are required for wallet correctness:

| Check | Status | Location |
|-------|--------|----------|
| Ciphertext AEAD integrity | ✅ | `client/src/encryption.rs` |
| Recipient match (decrypted note) | ✅ | `client/src/client.rs` → `try_decrypt_output()` |
| Diversifier consistency | ✅ | `client/src/client.rs` |
| Ciphertext hash binding (ct_hash) | ✅ | `client/src/client.rs` → `try_decrypt_output()` |
| Commitment binding (plaintext↔cm) | ✅ | `client/src/client.rs` → `try_decrypt_output()` |
| Spentness filtering (nullifier) | ✅ | `client/src/client.rs` → `sync()` |

---

## Known Gaps / Future Work

| Gap | Priority | Notes |
|-----|----------|-------|
| **SPL token transfers (S1, U3)** | Medium | Chain integration; mocks bypass this |
| **Context binding (chain_id, program_id)** | Low | Production hardening; not in tx_binding yet |
| **Multi-asset balance (value commitments)** | Deferred | Milestone 5; single-asset only today |

### Recently Completed

- ✅ **Spend authorization in circuit** - Now uses Grumpkin (Noir's embedded curve) for EC operations. Derives `ask` and `nsk` from `spending_key` in-circuit.
- ✅ **Nullifier security fix** - Nullifiers now use `nsk` (the nullifier SECRET), not `nk.x` (the public key). This ensures FullViewingKey holders cannot compute nullifiers or spend notes.

---

## How to Update This Document

When implementing a new statement:

1. Update the mock in `client/src/proofs.rs` or `client/src/mock.rs`
2. Update the circuit in `circuits/masp/<circuit>/src/main.nr` or `circuits/masp/common/src/statements.nr`
3. Run tests: `cargo test` and `nargo execute` for each circuit
4. Update this table to mark the statement as ✅
5. Update `docs/protocol-soundness.md` if the normative spec changes

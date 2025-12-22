# Encryption Implementation Comparison

## Our Implementation vs Zcash-Style Design

### ✅ What We Match Well

| Aspect | Zcash Pattern | Our Implementation |
|--------|--------------|-------------------|
| **Hybrid Encryption** | ECDH + symmetric AEAD | ✅ ECDH + ChaCha20-Poly1305 |
| **Ephemeral Keypair** | Generate per-output | ✅ `esk, epk = esk * g_d` |
| **AEAD** | Authenticated encryption | ✅ ChaCha20-Poly1305 |
| **Trial Decryption** | Try decrypt each output | ✅ `trial_decrypt()` function |
| **Calldata Storage** | In instruction data | ✅ `EncryptedNote.to_bytes()` for calldata |
| **Program Never Decrypts** | ZK proof verification only | ✅ Encryption is client-side only |
| **Separate Commitment Tree** | Membership proofs | ✅ MockNoteStore / future Light |
| **Outgoing Ciphertext (`C_out`)** | Sender can recover what they sent | ⚠️ Implemented but not used (see below) |
| **AAD Binding** | `aad = (cm, epk, ...)` prevents swap attacks | ✅ AAD = epk (always available) |
| **KDF Context** | Include `(epk, pk_enc, domain, cm)` | ✅ `Poseidon(domain, ss.x, ss.y, epk_x)` |
| **OOB Communication Trait** | "Paid in tx SIG" notification | ✅ `OobChannel` trait in `src/oob.rs` |
| **Outgoing Viewing Key** | `ovk` for sender recovery | ✅ `FullViewingKey::ovk()` |
| **Batch Nullifier Checks** | For efficient sync | ✅ `Chain::batch_check_nullifiers()` |

### ⚠️ Remaining Gaps

| Gap | Zcash Design | Our Current | Priority |
|-----|-------------|-------------|----------|
| **Encryption Key Separation** | `pk_enc` separate from `pk_addr` | ⚠️ Using `pk_d` for both | Low |
| **Tag-Based Discovery** | `tag = H(ivk, g_d)` for O(1) lookup | ❌ Trial decryption only | Future (Milestone 7) |
| **PIR Support** | Private witness retrieval | ❌ Not implemented | Future (Milestone 7) |

### 💪 What We Did Better

1. **Trait-Based Design**: `NoteEncryption` trait allows swapping algorithms
   - Production: `ChaChaPolyEncryption`
   - Testing: `MockEncryption`
   - Future: Could add X25519-based impl

2. **Note Verification Utilities**: `verify_note_commitment()`, `verify_decrypted_note()`

3. **Clear Domain Separation**: Using Poseidon with domain tags throughout

4. **Integrated with Key Hierarchy**: Uses existing `FullViewingKey`, `DiversifiedAddress`

5. **Comprehensive Sync Methods**:
   - `sync_from_chain()` - Full wallet recovery
   - `sync_incremental()` - New outputs only
   - `sync_from_tx()` - OOB fast path
   - `refresh_spent_status()` - Update spent flags

6. **Sender Audit Trail**: C_out infrastructure ready (see note below)

---

## Current Usage: C_enc Only

**Important:** While C_out (outgoing ciphertext) is fully implemented in `encryption.rs`, the current client flows only use C_enc:

| Flow | Encryption Method | What's Produced |
|------|------------------|-----------------|
| `shield()` | `encrypt()` | C_enc only |
| `transfer_to()` | `encrypt()` | C_enc only |

### Who Can Decrypt What

| Ciphertext | Purpose | Decrypted By | Currently Used? |
|------------|---------|--------------|-----------------|
| **C_enc** | Recipient receives payment | Recipient's `ivk` | ✅ Yes |
| **C_out** | Sender recovers what they sent | Sender's `ovk` | ❌ No (infrastructure ready) |

### Enabling C_out

To enable sender recovery, change client flows to use `encrypt_with_outgoing()` instead of `encrypt()`:

```rust
// Current (C_enc only):
let encrypted = encryption.encrypt(&mut OsRng, &note, &recipient_addr);

// With C_out enabled:
let ciphertexts = encryption.encrypt_with_outgoing(
    &mut OsRng,
    &note,
    &recipient_addr,
    sender_fvk.ovk(),  // Sender's outgoing viewing key
);
// ciphertexts.c_enc → for recipient
// ciphertexts.c_out → for sender recovery
```

The `NoteEncryption` trait, `OutputCiphertexts` struct, and `try_decrypt_outgoing()` are all implemented and tested.

---

## Implementation Summary

### Key Derivation

```rust
// From spending key (sk)
ask = Poseidon(DOM_ASK, sk)       // spend authorization secret
nsk = Poseidon(DOM_NSK, sk)       // nullifier secret
ak = ask * G                       // authorization public key
nk = nsk * G                       // nullifier public key

// Viewing keys
fvk = (ak, nk)                     // full viewing key
ivk = Poseidon(DOM_IVK, ak.x, nk.x)  // incoming viewing key
ovk = Poseidon(DOM_OVK, ak.x, nk.x)  // outgoing viewing key

// Addresses
g_d = H(diversifier) * G           // diversifier base point
pk_d = ivk * g_d                   // diversified transmission key
```

### Encryption (C_enc for recipient)

```rust
// Sender (knows recipient's pk_d, g_d):
esk = random()
epk = esk * g_d
ss = esk * pk_d                    // shared secret
k = Poseidon(DOM_KDF, ss.x, ss.y, epk.x)
C_enc = ChaCha20Poly1305(k, nonce, note_plaintext, aad=epk)
```

### Ciphertext Binding (`ct_hash`) Note (Option 1A)

We use `ct_hash` to bind Tx B’s proof public inputs to the ciphertext bytes published in Tx A.

**Current implementation detail:** the wallet computes `ct_hash` over a blob constructed as:

```text
ct_blob = epk || encrypted_note_bytes
encrypted_note_bytes = diversifier_index || epk || nonce || aead_ciphertext
```

So `epk` is currently included twice in the hashed blob. This is not known-broken, but it’s a
slightly wasteful choice; when we finalize the canonical “ciphertext bytes” format, we should
simplify this to a single unambiguous byte string.

### Decryption

```rust
// Recipient (has ivk):
ss = ivk * epk                     // ivk * esk * g_d = esk * ivk * g_d = esk * pk_d
k = Poseidon(DOM_KDF, ss.x, ss.y, epk.x)
note_plaintext = ChaCha20Poly1305.decrypt(k, nonce, C_enc, aad=epk)
```

### C_out (for sender recovery) - Implemented, Not Currently Used

C_out allows senders to recover what they sent using their outgoing viewing key (`ovk`).
This is useful for wallet recovery and audit trails.

**Status:** Fully implemented in `encryption.rs` but not produced by current client flows.

```rust
// Sender (uses ovk derived from seed):
ock = Poseidon(DOM_OCK, ovk, epk.x, commitment)
C_out = ChaCha20Poly1305(ock, nonce, esk || note_plaintext, aad=commitment)

// Recovery (sender uses ovk from seed):
ock = Poseidon(DOM_OCK, ovk, epk.x, commitment)
(esk, note) = ChaCha20Poly1305.decrypt(ock, nonce, C_out, aad=commitment)
```

See `encrypt_with_outgoing()` and `try_decrypt_outgoing()` in `encryption.rs`.

---

## Testing Coverage

### E2E Tests

**C_enc (active in client flows):**

- **Shielded Sync Recovery**: `test_shielded_sync_full_recovery`
- **Incremental Sync**: `test_shielded_sync_incremental`
- **Batch Nullifier Refresh**: `test_refresh_spent_status`
- **OOB First Payment**: `test_oob_first_payment_encrypted`
- **OOB vs Sync Comparison**: `test_oob_vs_full_sync_semantics`

**C_out (tests infrastructure, not used in client flows):**

- **C_out Sender Recovery**: `test_c_out_sender_recovery`
- **C_out Access Control**: `test_c_out_only_decrypts_for_sender`

### Unit Tests

- Encryption round-trip for both schemes (C_enc)
- Wrong key/diversifier rejection
- Tampered ciphertext detection
- Commitment verification
- Note ownership verification
- C_out encrypt/decrypt round-trip (infrastructure tests)

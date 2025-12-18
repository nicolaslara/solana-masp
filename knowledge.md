# MASP Knowledge Base

This file captures learnings, design decisions, and discoveries as we develop the MASP system.

**Keep this file updated as we learn new things.**

---

## Status

**Phase:** Milestone 0 - Off-chain primitives (COMPLETE)
**Last Updated:** 2024-12-16

### Recent Completions

- ✅ C_out (Outgoing Ciphertext) for sender audit trail
- ✅ Outgoing Viewing Key (ovk) derivation
- ✅ Full shielded sync from chain
- ✅ Incremental sync
- ✅ Batch nullifier checking
- ✅ 33 E2E tests (7 new for advanced sync/encryption)
- ✅ Production-like indexing-latency hook: `Indexer::wait_for_update()` + `MaspClient::wait_for_indexer_update()`
- ✅ Protocol documentation + responsibility split:
  - `docs/protocol.md`
  - `docs/circuit-security-requirements.md` updated with “who checks what”
- ✅ Noir circuits refactored for auditability (Stage-0): `main` calls one function per required statement
- ✅ Membership proof model clarified:
  - Membership is verified **outside** MASP spend circuits (MerklePath in mocks; Light validity proof on-chain in production).
  - Spend circuits bind `input_commitment` (public) to note plaintext (preimage knowledge).
- ✅ Documented balance enforcement decision (in-circuit baseline; optional future value commitments + on-chain homomorphic check)

---

## Architecture Decisions ✅

### Indexer Latency Modeling (Reference Implementation)

**Decision:** Keep the `Indexer` trait read-only, but add an optional `wait_for_update(tx_sig)` hook with a **default no-op** implementation.

**Rationale:**

- In production, the indexer is an external observer (RPC/Helius/Light) and “waiting” is not a protocol requirement.
- In tests and demos, modeling indexing lag makes flows more realistic (submit → wait → scan) without building a full indexer.

**Client helper:** `MaspClient::wait_for_indexer_update()` forwards to the configured indexer.

### Witness & Proof Generation (Production: Mobile Prover)

**Decision:** In production, the wallet (mobile) must generate witnesses and proofs **programmatically in-process**, not by shelling out to `nargo`/`bb`.

**Why:**

- Mobile apps cannot rely on external CLI tooling.
- We need a stable, testable prover interface that works on device (FFI).

**Reference spike:** `../mobile-solana-e2e/` demonstrates the intended model:

- Parse Noir artifact JSON (contains ABI + ACIR bytecode)
- Build an initial witness from structured inputs via the ABI encoder
- Run **ACVM execution** (`execute`) to solve the full witness
- Produce proof bytes using the selected proving system:
  - **UltraPlonk**: Barretenberg ACIR proof generation
  - **Groth16**: ACVM → R1CS → Groth16 backend

**Implementation plan in this repo:**

- Keep the `SpendProver` trait as the protocol boundary.
- Provide two categories of implementations:
  - **Dev/CI (CLI)**: `nargo execute` + `bb OLD_API prove` (useful for fast bringup, not production)
  - **Mobile (library/FFI)**: embed ACVM + prover libs (no files; inputs passed as typed structs/bytes)

### Note Structure: Orchard-style Actions

**Decision:** Use **unified Actions** (1 spend + 1 output per action) rather than Sapling's separate Spend/Output descriptions.

**Rationale:**

- Fixed circuit size (predictable constraints)
- Simpler transaction format
- Matches modern MASP designs

### Note Plaintext Fields

A note MUST include:

| Field             | Type  | Description                                |
| ----------------- | ----- | ------------------------------------------ |
| `asset_id`        | Field | `H(DOM_ASSET, token_address)` - hides mint |
| `amount`          | u64   | Note value (range-checked in circuit)      |
| `recipient`       | Field | Diversified address (pk_d.x)               |
| `nullifier_nonce` | Field | Unique per note - ensures unique nullifier |
| `note_randomness` | Field | Hides note contents in commitment          |

**Naming rationale:**

- `rho` → `nullifier_nonce` - Clearer purpose: makes nullifiers unique per note
- `rseed` → `note_randomness` - Clearer purpose: randomizes commitment
- `mint_pubkey` → `token_address` - Solana terminology

### Commitment Scheme

**Decision:** Poseidon with domain separation (via light-poseidon crate)

```
cm = Poseidon(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)
```

**Why each field:**

- `asset_id` - Which token (hides actual mint address)
- `amount` - Value in the note
- `recipient` - Who can spend (pk_d.x)
- `nullifier_nonce` - Makes nullifier unique per note
- `note_randomness` - Makes commitment unique even for identical notes

### Nullifier Derivation

```
nf = Poseidon(DOM_NULLIFIER, nk, nullifier_nonce)
```

Where:

- `nk` = nullifier key (derived from spending key via Baby JubJub)
- `nullifier_nonce` = unique per note (committed in note)

**Why needed:** Nullifier must be unique per note and derivable only by owner.

### Asset Identifier

```
asset_id = Poseidon(DOM_ASSET, token_address)
```

- Boundary deposits/withdrawals expose `token_address` (public)
- Inside pool, `asset_id` remains private

### Multi-Asset Balance: Fiat-Shamir α Tags

**Decision:** Use random linear combination for balance checking

```
α = Poseidon(DOM_ASSET_ALPHA, tx_binding_hash)
tag_i = Poseidon(DOM_ASSET_TAG, α, asset_id_i)

Conservation: Σ(amount_in * tag_in) - Σ(amount_out * tag_out) - Σ(Δ_public * tag_public) = 0
```

**Rationale:** Single scalar equation proves balance across all assets without revealing which assets.

### Domain Separation Tags

```rust
enum DomainTag {
    NoteCommitment = 1,    // cm = H(DOM, note_fields...)
    Nullifier = 2,         // nf = H(DOM, nk, nonce)
    AssetId = 3,           // asset_id = H(DOM, token_address)
    MerkleNode = 4,        // node = H(DOM, left, right)
    AuthorizationSecret = 5,   // ask = H(DOM, spending_key)
    NullifierSecret = 6,       // nsk = H(DOM, spending_key)
    IncomingViewingKey = 7,    // ivk = H(DOM, ak.x, nk.x)
    AssetAlpha = 8,        // α = H(DOM, tx_binding_hash)
    AssetTag = 9,          // tag = H(DOM, α, asset_id)
    NullifierNonce = 10,   // nonce = H(DOM, spent_cm, index)
    TxBinding = 11,        // binding_hash = H(DOM, tx_fields...)
    Ciphertext = 12,       // c_hash = H(DOM, ciphertext...)
    // Future (Milestone 7+):
    LongTermKey = 13,      // lt_sk = H(DOM, spending_key)
    DiscoveryTag = 14,     // tag = H(DOM, shared_secret, direction, counter)
    OutgoingViewingKey = 15,   // ovk = H(DOM, spending_key)
    WalletBackup = 16,     // backup_key = H(DOM, spending_key)
}
```

### Client Architecture

**Decision:** Trait-based design separating concerns:

```
MaspClient<I: Indexer, C: Chain>
    ├── Keys (SpendingKey, ViewingKey) - local
    ├── Notes (OwnedNote) - local
    └── Operations via traits:
        ├── Indexer: get_witness, scan_outputs, exists
        └── Chain: submit_transaction, is_nullifier_spent
```

**Why traits:**

- Mock implementations for testing without network
- Clear boundary of what client needs from external services
- Easy to swap real implementations later

**What client does NOT own:**

- Merkle tree (on indexer)
- Nullifier set (on chain)
- Root history (on chain)

### Client Sync Patterns

**Sync Flow (Primary for POC):**

1. Client scans `indexer.scan_outputs_since(last_tx)` for new ciphertexts
2. Tries to decrypt each ciphertext with viewing key
3. For decrypted notes, verifies commitment via `indexer.exists()`
4. Checks nullifier via `chain.is_nullifier_spent()` to detect spent notes
5. Adds unspent notes to local state

**OOB Flow (Secondary):**

1. Sender provides tx_sig to receiver out-of-band (email, message, etc.)
2. Receiver calls `indexer.get_commitments_for_tx(tx_sig)` to find commitments
3. Sender also provides note plaintext (or receiver decrypts ciphertext)
4. Receiver verifies via `import_note()` which checks commitment exists

**Key insight:** Sync is more robust (works independently) but requires ciphertext storage. OOB requires less infrastructure but needs external communication.

### State Storage Strategy (Phased)

| Phase | Commitments                    | Nullifiers        | Notes                  |
| ----- | ------------------------------ | ----------------- | ---------------------- |
| M1    | On-chain Merkle (toy depth 16) | PDA per nullifier | Simple, works          |
| M3    | Light Protocol tree            | PDA per nullifier | Light for cm only      |
| M4    | Light Protocol tree            | Light uniqueness  | Full Light integration |

### Merkle Tree

- **Depth:** 32 levels (supports ~4 billion notes)
- **Hash:** Poseidon with domain tag
- **Anchor history:** Ring buffer of last K roots (allows stale witnesses)

### Ciphertext Storage

**Decision:** Store in transaction calldata (instruction data), NOT logs.

**Rationale:**

- Logs are not reliable DA layer
- Calldata is retained in ledger history
- Enables rescan recovery
- Retrievable via `getTransaction` RPC (Helius, standard Solana)

### Note Encryption Scheme

**Decision:** ECIES with ChaCha20-Poly1305 (matches Zcash Sapling pattern)

```text
Encryption (sender knows recipient's pk_d and g_d):
1. Generate ephemeral keypair: esk (random), epk = esk * g_d
2. ECDH: shared_secret = esk * pk_d
3. KDF: symmetric_key = Poseidon(DOM_CIPHERTEXT, ss.x, ss.y, epk.x)
4. AAD: ephemeral_key bytes (binds ciphertext to this encryption)
5. Encrypt: ChaCha20-Poly1305(symmetric_key, nonce, plaintext, aad=epk)
6. Output: (epk, nonce, ciphertext_with_tag)

Decryption (recipient has ivk):
1. Compute: shared_secret = ivk * epk
2. Same KDF to derive symmetric_key
3. Decrypt with ChaCha20-Poly1305 using epk as AAD
4. Verify recipient field matches
5. Optionally verify commitment if known
```

**Comparison with Zcash:**

| Aspect | Zcash | Our Implementation |
|--------|-------|-------------------|
| Key Exchange | X25519 | Baby JubJub ECDH |
| AEAD | ChaCha20-Poly1305 | ChaCha20-Poly1305 ✅ |
| KDF | Blake2b | Poseidon (ZK-native) |
| AAD | commitment | ephemeral key |
| Outgoing Ciphertext | Yes (C_out) | ✅ Implemented |
| Outgoing Viewing Key | Yes (ovk) | ✅ Implemented |
| Batch Nullifier Checks | Yes | ✅ Implemented |

**Why epk as AAD instead of commitment:**

- Allows trial decryption without knowing commitment
- Commitment verified after decryption
- Same security: epk is per-encryption, prevents swapping

**Trait-based design:**

- `NoteEncryption` trait allows swappable algorithms
- `ChaChaPolyEncryption` - production (authenticated encryption)
- `MockEncryption` - testing (fast XOR, insecure)
- `encrypt_with_outgoing()` - creates both C_enc and C_out

### Out-of-Band (OOB) Communication

**Decision:** Trait-based OOB channel for payment notifications

```rust
// Minimal notification (sender to recipient)
PaymentNotification {
    tx_sig: "5K8Z...",     // Transaction signature
    output_index: 0,        // Which output in tx
    commitment: Option<[u8; 32]>,  // For quick verification
}

// OOB Channel trait
trait OobChannel {
    async fn send(recipient_id, notification);
    async fn receive(recipient_id) -> Vec<PaymentNotification>;
}
```

**How it works:**

1. Alice pays Bob via shielded transfer
2. Alice sends `PaymentNotification` to Bob (Signal, email, QR, etc.)
3. Bob calls `indexer.get_commitments_for_tx(tx_sig)` to verify
4. Bob decrypts ciphertext or uses provided note plaintext
5. Bob imports note after verification

**Key insight:** OOB is complementary to sync:

- **Sync**: Scans all ciphertexts, slower but autonomous
- **OOB**: Targeted fetch, faster but needs external communication

### Payment Discovery Scaling (Future)

**Problem:** Trial decryption is O(N) where N = all shielded outputs.

**Current (POC):** Trial decryption - simple, correct, doesn't scale.

**Production (Future):** Tag-based discovery with PIR:

1. First payment: OOB key exchange to establish shared secret
2. Subsequent: Deterministic tags + PIR lookup (O(1))
3. Fallback: Trial decryption for recovery

**Why epk can't be lost:** It's stored on-chain in transaction data.

See `docs/payment-discovery-analysis.md` for full analysis.

### Sender Recovery Problem (C_out) ✅

**Critical insight:** Recipients can always recover, but senders cannot!

```
Recipient (Bob): ss = ivk * epk    ← ivk derived from seed ✅
Sender (Alice):  ss = esk * pk_d   ← esk was RANDOM, not from seed ❌
```

**Solution: Outgoing Ciphertext (C_out)** ✅ IMPLEMENTED

Each transaction includes TWO ciphertexts:

1. `C_enc` - For recipient, encrypted with `ss = esk * pk_d`
2. `C_out` - For sender, encrypted with `ovk` (outgoing viewing key)

Since `ovk` is derived from Alice's seed, she can always decrypt C_out.
C_out contains `esk || pk_d.x || note_plaintext`.

**Implementation:**

```rust
// Key derivation
ovk = Poseidon(DOM_OVK, ak.x, nk.x)

// Outgoing ciphertext key
ock = Poseidon(DOM_OCK, ovk, epk.x, commitment)

// C_out encryption
C_out = ChaCha20Poly1305(ock, nonce, esk || pk_d.x || note_plaintext, aad=commitment)
```

**Sync methods:**

- `sync_from_chain(scan_sent=true)` - Recovers sent notes via C_out
- `SyncResult.sent_notes` - Contains recovered `OutgoingPlaintext`

### Circuit Split (Separate Circuits)

**Decision:** Three separate circuits for different operations

1. **Shield circuit** - Deposit from transparent to shielded
2. **Transfer circuit** - Shielded spend + output (full Action)
3. **Unshield circuit** - Withdraw from shielded to transparent

**Rationale:**

- Smaller individual circuits = lower CU
- Simpler constraint logic per circuit
- Can optimize each independently

### Proof Abstractions

**Decision:** Trait-based proof system for flexibility

```rust
// Three proof types with implementations:
MembershipProof  // Commitment exists in tree
├── MockMembershipProof    // Testing
├── MerklePathProof        // Off-chain (explicit siblings)
└── LightValidityProof     // On-chain (constant-size)

TransferProof    // Valid shielded transfer
├── MockTransferProof      // Testing
└── UltraPlonkProof        // Production

UniquenessProof  // Nullifier not spent
├── MockUniquenessProof    // Testing
├── PdaExistenceCheck      // Simple on-chain
└── LightInsertProof       // Light Protocol
```

**Rationale:**

- Same code works for testing (mock) and production (real proofs)
- Clear separation: off-chain vs on-chain compatible
- Easy migration path: mock → local → Light Protocol

---

## Transaction Format

### Public Inputs (UltraPlonk)

Minimal public inputs:

- `anchor_root` - Merkle root from history
- `nullifiers[]` - Or commitment: `nf_root = Poseidon(nf_0, nf_1, ...)`
- `new_commitments[]` - Or commitment: `cm_root = Poseidon(cm_0, cm_1, ...)`
- `tx_binding_hash` - Prevents malleability

### Private Inputs

- Note plaintexts/secrets for spends
- Merkle paths proving inclusion
- Recipient data for outputs
- Randomness for commitments/encryption
- Multi-asset bookkeeping (α tags)

---

## Key Learnings

### From Sapling-Groth16 Spike

1. **Poseidon > BLAKE2s** - 70-100x more efficient (~200 vs ~21,000 constraints)
2. **Domain separation** - Constant field element prepended to inputs
3. **BN254 security** - ~100-bit security (acceptable)
4. **Baby JubJub** - Embedded curve for BN254
5. **Circuit size** - Sapling spend is ~46K constraints

### From Spec Analysis

1. **Light Protocol** - ~100K CU for validity proof verification
2. **TX size limit** - 1232 bytes on Solana
3. **Forester dependency** - Light queues need draining (liveness risk)
4. **Don't use Light nullifier queue** - Designed for compressed account lifecycle, not MASP spentness

### From E2E Testing

1. **Indexer is the source of truth** - Client verifies notes via indexer before adding them
2. **Sync vs OOB** - Two note discovery patterns:
   - **Sync**: Client scans ciphertexts from indexer, decrypts to find owned notes
   - **OOB**: Sender shares tx_sig, receiver fetches commitments from indexer
3. **Nullifier check on sync** - Restored clients must check `is_nullifier_spent()` before adding notes
4. **Multi-asset isolation** - Different tokens have separate balances (asset_id is key)
5. **Single tx_sig per transfer** - All output commitments (output + change) belong to same transaction

---

## Implementation Notes

### Poseidon Implementation

**Decision:** Use `light-poseidon` crate instead of custom implementation.

**Rationale:**

- Battle-tested (Light Protocol uses it in production)
- Matches Circom/Noir Poseidon output
- No maintenance burden

**API:**

```rust
use light_poseidon::{Poseidon, PoseidonBytesHasher};
let mut hasher = Poseidon::<Fr>::new_circom(input_count)?;
let result: [u8; 32] = hasher.hash_bytes_le(&inputs)?;
```

### UltraPlonk Constraints

From `../solana-ultraplonk-verifier/`:

- Single-TX verification (~500K-1M CUs)
- Uses `bb OLD_API` commands
- Noir v1.0.0-beta.3 + bb 0.82.2 toolchain

### Solana BN254 Syscalls

```rust
alt_bn128_addition       // G1 point addition
alt_bn128_multiplication // G1 scalar multiplication
alt_bn128_pairing        // Pairing check
```

All use big-endian byte format.

---

## Configurable Backends

Tests can run with different backends via environment variables:

```bash
# Default: all mocks
cargo test --test user_flows

# Show backend configuration
MASP_PRINT_CONFIG=1 cargo test -- --nocapture

# Chain backends (MASP_CHAIN)
MASP_CHAIN=mock           # In-memory mock (default)
MASP_CHAIN=surfpool       # Local Surfpool (http://127.0.0.1:8899)
MASP_CHAIN=devnet         # Solana devnet
MASP_CHAIN=testnet        # Solana testnet
MASP_CHAIN=mainnet        # Solana mainnet-beta

# Indexer backends (MASP_INDEXER)
MASP_INDEXER=mock         # In-memory mock (default)
MASP_INDEXER=light        # Light Protocol via Helius

# Encryption backends (MASP_ENCRYPTION)
MASP_ENCRYPTION=chacha    # ChaCha20-Poly1305 (default, production)
MASP_ENCRYPTION=mock      # Mock encryption (fast testing, INSECURE)
```

**Current Status:** All non-mock backends are scaffolds that use mock internally.
As real implementations are added, tests will automatically use them.

### Encryption Algorithm: ChaCha20-Poly1305

**Properties:**

- 256-bit key, 96-bit nonce
- Authenticated encryption (integrity + confidentiality)
- Fast in software (no AES-NI required)
- Standard IETF RFC 8439
- Used in: TLS 1.3, WireGuard, Noise Protocol, Zcash Sapling

**Why not AES-GCM?**

- ChaCha20 is faster on devices without AES hardware acceleration
- Constant-time implementation is easier (no cache timing attacks)
- AES-GCM can be added as an option later if needed

**Future options:**

- `AesGcm`: AES-256-GCM (hardware acceleration on modern CPUs)
- `XChaCha`: Extended nonce (192-bit) for safer random nonce generation
- `Aegis`: AEGIS-256 (very fast with AES-NI)

---

## Open Questions

1. ~~Note structure~~ → Actions (decided)
2. ~~Commitment scheme~~ → Poseidon (decided)
3. ~~Multi-asset~~ → α tags (decided)
4. ~~Key derivation~~ → Sapling-style on Baby JubJub (decided)
5. ~~Exact ciphertext format~~ → ECIES with ChaCha20-Poly1305 (decided)
6. Relayer fee structure details
7. Light Protocol integration patterns (Milestone 3)

---

## References Consulted

- [x] Zcash Protocol Spec (Sections 4 & 5)
- [x] Local sapling-groth16 spike
- [x] Light Protocol whitepaper
- [x] ZK Compression docs
- [ ] Namada MASP implementation (for multi-asset patterns)
- [ ] Zcash Orchard implementation (for Action structure)

---

## Design Documents

- **[Circuit Security Requirements](docs/circuit-security-requirements.md)** ⚠️ **CRITICAL**:

  - All constraints that MUST be enforced in ZK circuits
  - Shield, Transfer, Unshield circuit requirements
  - Out-of-circuit integrity checks (nullifier uniqueness, anchor validity)
  - Security invariants and audit priorities
  - **Keep updated when circuit constraints change**

- **[Encryption Comparison](docs/encryption-comparison.md)** - Zcash comparison:

  - How our ECIES implementation compares to Zcash
  - What we did better (trait-based, ZK-native KDF)
  - Gaps (C_out not implemented)

- **[Payment Discovery Analysis](docs/payment-discovery-analysis.md)** - Scaling sync:

  - Trial decryption vs tag-based discovery
  - Why epk can't be lost (on-chain)
  - PIR for O(1) payment lookup
  - Migration path from POC to production

- **[Light Protocol Integration](docs/light-protocol-integration.md)** - LP integration design:

  - Helius API mapping (`getCompressedAccountProof`, etc.)
  - Nullifier uniqueness via Light address tree
  - Mock implementation design

- **[Light Protocol Integration Analysis](docs/light-protocol-questions.md)** ⭐ Key findings:

  - **Address CAN be set** - `address = commitment` works!
  - Nullifiers via address tree uniqueness
  - Privacy considerations documented

- **[Data Structures](docs/data-structures.md)** - On-chain structures:

  - Commitment Tree (hash-addressed via Light Protocol)
  - Nullifier Set (Light Protocol address tree)
  - Identifier strategy (hash vs position)

- **[Client Protocol Analysis](docs/client-protocol-analysis.md)** - Protocol flows:

  - Shield, transfer, unshield operations
  - Sync mechanisms (scanning vs OOB)
  - Client data model
  - Fees and relayers
  - Privacy analysis

---

## Sapling Key Hierarchy

We follow Zcash Sapling terminology (ZIP-32, Protocol Spec §4.2.2):

```text
sk (SpendingKey) - root secret, can spend
 │
 ├─► ask = H(sk) ──► ak = ask * G  (public)
 │                         │
 └─► nsk = H(sk) ──► nk = nsk * G  (public)
                           │
        ┌──────────────────┘
        ▼
  fvk = (ak, nk)  ─── FullViewingKey (can view, CANNOT spend)
        │
        ▼
  ivk = H(ak.x, nk.x)
        │
        ▼
  pk_d = ivk * g_d  ─── DiversifiedAddress
```

**Key separation:**

- `SpendingKey` - has secrets (ask, nsk), can spend
- `FullViewingKey` - only public keys (ak, nk), can view but CANNOT spend
- Give FVK to auditors/watch-only wallets

| Sapling | Our Crate                 | Description                      |
| ------- | ------------------------- | -------------------------------- |
| `sk`    | `SpendingKey`             | Root secret (32 bytes)           |
| `ask`   | `SpendingKey.ask()`       | Spend authorization secret       |
| `nsk`   | `SpendingKey.nsk()`       | Nullifier secret                 |
| `ak`    | `FullViewingKey.ak`       | Authorization public key (point) |
| `nk`    | `FullViewingKey.nk`       | Nullifier public key (point)     |
| `ivk`   | `FullViewingKey.ivk()`    | Incoming viewing key (scalar)    |
| `g_d`   | `DiversifiedAddress.g_d`  | Diversifier base point           |
| `pk_d`  | `DiversifiedAddress.pk_d` | Diversified transmission key     |

---

## Glossary

| Term                | Definition                                                 |
| ------------------- | ---------------------------------------------------------- |
| **Note**            | A shielded unit of value (like a UTXO)                     |
| **Nullifier**       | Hash revealed when spending a note (prevents double-spend) |
| **Commitment**      | Hash hiding note contents (stored in Merkle tree)          |
| **Action**          | Unified spend+output operation (Orchard-style)             |
| **nullifier_nonce** | Unique per note, ensures unique nullifier (Sapling: ρ/rho) |
| **note_randomness** | Randomizes commitment (Sapling: rseed/rcm)                 |
| **ask**             | Spend authorization secret (in SpendingKey)                |
| **nsk**             | Nullifier secret (in SpendingKey)                          |
| **fvk**             | Full viewing key (ak, nk) - can view, cannot spend         |
| **ak**              | Authorization public key (in FullViewingKey)               |
| **nk**              | Nullifier public key (in FullViewingKey)                   |
| **ivk**             | Incoming viewing key (derived from fvk)                    |
| **g_d**             | Diversifier base point                                     |
| **pk_d**            | Diversified payment address (ivk \* g_d)                   |
| **MASP**            | Multi-Asset Shielded Pool                                  |
| **α**               | Fiat-Shamir challenge for multi-asset balance              |
| **tag**             | Asset-specific tag derived from α                          |
| **Indexer**         | Service providing Merkle witnesses and ciphertexts         |
| **Chain**           | Service for submitting transactions (Solana RPC)           |

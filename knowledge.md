# MASP Knowledge Base

This file captures learnings, design decisions, and discoveries as we develop the MASP system.

**Keep this file updated as we learn new things.**

---

## Status

**Phase:** Milestone 0 - Off-chain primitives (COMPLETE)
**Last Updated:** 2024-12-16

---

## Architecture Decisions ✅

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
}
```

### Client Architecture

**Decision:** Trait-based design separating concerns:

```
MaspClient<I: Indexer, C: Chain>
    ├── Keys (SpendingKey, ViewingKey) - local
    ├── Notes (OwnedNote) - local
    └── Operations via traits:
        ├── Indexer: get_witness, scan_outputs
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

## Open Questions

1. ~~Note structure~~ → Actions (decided)
2. ~~Commitment scheme~~ → Poseidon (decided)
3. ~~Multi-asset~~ → α tags (decided)
4. ~~Key derivation~~ → Sapling-style on Baby JubJub (decided)
5. Exact ciphertext format (ECIES? ChaCha20-Poly1305?)
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

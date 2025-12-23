# Solana MASP - Tasks

## Status: ✅ Circuits Complete + Verified → Ready for Solana Integration (Milestone 1)

**Current state:** All 3 circuits (shield, transfer, unshield) are implemented, match `docs/protocol-soundness.md`, and verified with real UltraPlonk proofs. Ready for on-chain integration.

## Before Starting

1. **Read `knowledge.md`** - Architecture decisions + gap analysis documented
2. **Read `docs/protocol-soundness.md`** - Normative protocol spec
3. **Update both files** as you make progress

---

## Overview

Building a Multi-Asset Shielded Pool (MASP) on Solana.

**Architecture:**

- UltraPlonk proofs via `../solana-ultraplonk-verifier/`
- N→M transfers (up to 3 inputs, 3 outputs) in a single proof
- Poseidon2 hashing (Noir stdlib + `taceo-poseidon2` in Rust)
- **Value rule (current)**: single-asset per transfer (hard-sound). Multi-asset deferred to Milestone 5.
- Trait-based client (Indexer + Chain abstractions)
- On-chain commitment-tree accumulator (anchors); membership proven via Merkle paths (privacy-preserving)
- Light Protocol for nullifier set (Milestone 4+)

**Circuits (all implemented):**

- Shield circuit — commitment integrity, amount range, ct_hash binding
- Transfer circuit — membership, nullifier derivation, spend auth (EC), balance conservation, output nonces
- Unshield circuit — same as transfer + public withdrawal binding (recipient limbs)

---

## Next Priority Order

**Completed in current sprint:**

1. ✅ Real prover testing (0.14.1) — all 3 circuits validated (transfer, shield, unshield)
2. ✅ Doc cleanup (0.14.3) — fixed drift in `docs/circuit-security-requirements.md` and `docs/implementation-status.md`
3. ✅ Shield/Unshield pipeline tests (0.14.1) — all 3 circuits have compile→prove→verify tests

**Next sprint:**

4. ⬅️ **Solana program (Milestone 1)** — proof verification + commitment accumulator + nullifier set + SPL transfers

---

## Phase 0: Scaffolding ✅

- [x] Project structure created
- [x] Cursor rules (development, references, workflow, knowledge)
- [x] Placeholder circuit that compiles
- [x] Placeholder program with stub instructions
- [x] Placeholder client structure
- [x] Build and deploy scripts
- [x] Knowledge base initialized

---

## Milestone 0: Off-chain Model ✅

**Goal:** Lock primitives before touching Solana. All in Rust, testable locally.

### 0.1 Core Primitives ✅

- [x] Domain separation constants (12 tags)
- [x] Note struct (asset_id, amount, recipient, nullifier_nonce, note_randomness)
- [x] Commitment derivation via Poseidon
- [x] Nullifier derivation
- [x] Asset ID derivation
- [x] Using `light-poseidon` crate (not custom implementation)

### 0.2 Merkle Tree ✅

- [x] In-memory Merkle tree in `MockIndexer`
- [x] Insert commitment
- [x] Get witness (siblings + path indices)
- [x] Compute/verify root

### 0.3 Nullifier Set ✅

- [x] In-memory nullifier set in `MockChain`
- [x] Check if spent
- [x] Mark as spent
- [x] Reject duplicates

### 0.4 Key Derivation ✅

- [x] SpendingKey → ViewingKey
- [x] authorization_secret → authorization_key (Baby JubJub)
- [x] nullifier_secret → nullifier_key (Baby JubJub)
- [x] Incoming viewing key derivation
- [x] Diversified address generation

### 0.5 Ciphertext Format ✅

- [x] ECIES encryption with ChaCha20-Poly1305
- [x] Note encryption/decryption
- [x] Trial decryption for scanning
- [x] `NoteEncryption` trait for swappable algorithms
- [x] `ChaChaPolyEncryption` (production)
- [x] `MockEncryption` (fast testing)
- [x] AAD (Additional Authenticated Data) with ephemeral key
- [x] KDF includes ephemeral key for binding
- [x] `try_decrypt_with_commitment()` for known-commitment path

### 0.5.1 OOB Communication ✅

- [x] `OobChannel` trait for payment notifications
- [x] `PaymentNotification` struct (tx_sig, output_index)
- [x] `PaymentDetails` struct (with optional note plaintext)
- [x] `MockOobChannel` for testing
- [x] `OobNotificationBuilder` helper

### 0.6 Client Architecture ✅

- [x] `Indexer` trait (witnesses, scanning)
- [x] `Chain` trait (submit, query)
- [x] `MockIndexer` implementation
- [x] `MockChain` implementation
- [x] `MaspClient<I, C>` with trait bounds

### 0.7 Exit Criteria ✅

- [x] Can create notes
- [x] Can spend notes
- [x] Nullifier set prevents double-spend
- [x] Balance bookkeeping is correct
- [x] All tests pass (85 tests: 52 unit + 33 E2E)

### 0.8 Proof System Traits ✅

- [x] `SpendProver` trait (client-side proof generation)
- [x] `ProofVerifier` trait (on-chain/client verification)
- [x] `MockSpendProver`/`MockProofVerifier` implementations
- [x] `NoteCommitmentStore` trait (membership proofs)
- [x] `NullifierSet` trait (double-spend prevention)
- [x] `MembershipWitness` enum (MerklePath vs LightValidityProof)

### 0.9 Configurable Backends ✅

- [x] Backend configuration via environment variables
- [x] `BackendConfig` struct with chain/indexer/encryption options
- [x] `SolanaChain` scaffold (uses mock internally)
- [x] `LightIndexer` scaffold (uses mock internally)
- [x] `ChaChaPolyEncryption` production implementation
- [x] `MockEncryption` for fast testing
- [x] `MASP_PRINT_CONFIG=1` for debugging

### 0.10 E2E Tests ✅

- [x] Test infrastructure (TestEnv with mock chain/indexer)
- [x] Basic flow: shield → transfer → unshield
- [x] Two user flow: Alice pays Bob → Bob unshields
- [x] **Multi-asset support** (USDC, SOL, BONK - separate balances)
- [x] Multi-asset transfer preserves token type
- [x] Multiple notes of same token
- [x] **Indexer sync: rebuild client from indexer**
- [x] Sync via `get_commitments_for_tx`
- [x] Sync detects spent notes via nullifier check
- [x] Sync with multiple output commitments (output + change)
- [x] Negative: double spend rejected
- [x] Negative: insufficient balance rejected
- [x] Negative: invalid anchor rejected
- [x] Negative: nonexistent note rejected
- [x] Negative: already spent note rejected
- [x] **Negative: can't spend others' notes (wrong nullifier key)**
- [x] OOB note import via tx_sig
- [x] OOB fake note rejected
- [x] Edge case: exact amount (no change)
- [x] Edge case: zero amount shield

### 0.10 Advanced Encryption ✅

- [x] `ovk` (Outgoing Viewing Key) derivation from FVK
- [x] `C_out` (Outgoing Ciphertext) for sender audit trail
- [x] `encrypt_with_outgoing()` creates both C_enc and C_out
- [x] `decrypt_outgoing()` for sender recovery
- [x] Sender-only C_out decryption (access control)
- [x] AAD binding with ephemeral key
- [x] KDF includes full context (domain, ss, epk)

### 0.11 Shielded Sync ✅

- [x] `sync_from_chain()` - Full wallet recovery from seed
- [x] `sync_incremental()` - New outputs since last sync
- [x] `sync_from_tx()` - OOB fast path (specific transaction)
- [x] `refresh_spent_status()` - Update spent flags from chain
- [x] `batch_check_nullifiers()` - Efficient nullifier checking
- [x] `scan_outputs_paginated()` - Paginated output scanning
- [x] `OutputCiphertext` with C_out support
- [x] `SyncResult` with sent note recovery

### 0.12 Shielded Sync E2E Tests ✅

- [x] Full wallet recovery from seed
- [x] Incremental sync (new outputs only)
- [x] Refresh spent status
- [x] C_out sender recovery
- [x] C_out access control (only sender can decrypt)
- [x] OOB first payment with encryption
- [x] OOB vs full sync comparison

---

## Milestone 0.13: Interface Review ✅ MOSTLY COMPLETE

**Goal:** Lock protocol-level interfaces so user flows stay stable while swapping internals.

### 0.13.1 Indexer/Chain APIs ✅

- [x] `Indexer` trait supports: ciphertext scanning, OOB fetch, witness retrieval, exists checks
- [x] Two-tx model (Tx A ciphertexts + Tx B state transition) implemented in mocks
- [x] Indexing latency hook: `Indexer::wait_for_update()` + `MaspClient::wait_for_indexer_update()`
- [x] OOB notification includes both `masp_tx_sig` and `ciphertext_tx_sig`

### 0.13.2 Store Abstractions (Deferred to Milestone 3/4)

Light Protocol integration deferred. Current model:
- Mock in-memory Merkle tree for commitments
- Mock in-memory set for nullifiers
- Abstractions exist (`MembershipWitness`, `Anchor`) for later swap

### 0.13.3 Key/Address Decisions ✅

- [x] Single root of trust (seed) — documented in `knowledge.md`
- [x] Baby JubJub for encryption (same curve as Noir embedded ops)

### 0.13.4 Production-Likeness Review ✅ MOSTLY COMPLETE

#### Encryption / Note Handling ✅

- [x] `NoteEncryption` trait with ChaCha20-Poly1305 AEAD
- [x] Baby JubJub ECDH (matches Noir embedded curve)
- [x] Client verifies `H(note_plaintext) == commitment` before accepting notes

#### Calldata Layout (Deferred to Milestone 1)

- [ ] Freeze byte layout for program instructions (depends on on-chain POC)
- [x] Indexer APIs expose ciphertext + epk + commitment + output index

#### Byte Budget + Calldata Optimization (Deferred to Milestone 2)

Circuits are stable. Optimize when building real on-chain transactions.

- [ ] Write tight byte budget for instruction data
- [ ] Implement Option 1A: Tx A posts ciphertext, Tx B has only `ct_hashes` + proof
- [ ] Remove `ephemeral_key` duplication
- [ ] Compress Baby JubJub points (64B → 32B)

#### Ciphertext DA + Binding (Option 1A) ✅ COMPLETE

- [x] `ct_hash = H(DOM_CIPHERTEXT, ciphertext_bytes)` with `DOM_CIPHERTEXT = 4`
- [x] `ct_hashes[MAX_OUTPUTS]` as explicit public inputs (not in `tx_binding`)
- [x] Two-tx model mocked: Tx A posts ciphertexts, Tx B binds via `ct_hash`
- [x] OOB notifications include both tx signatures
- [x] Indexer APIs: `get_ciphertext_by_hash()`, `get_ciphertext_for_output()`
- [x] Wallet verifies `ct_hash` before trial decryption
- [x] Client computes `ct_hash(es)` before proof generation
- [ ] Multi-tx submit flow (Jito bundling) — deferred, optional UX

#### Remaining Doc Cleanup (Move to 0.14)

- [ ] Reconcile `docs/encryption-comparison.md` with current decisions
- [ ] Update `knowledge.md` "Status/Recent Completions"

### 0.13.5 Protocol Soundness Review ✅ COMPLETE

- [x] `docs/protocol-soundness.md` — normative protocol spec
- [x] MockChain: bind membership witness root to anchor
- [x] MockSpendProver: enforce output nullifier nonce derivation
- [x] Spend authorization: `nsk` (secret) used for nullifiers, not `nk.x` (public)
- [x] `tx_binding` layout enforced in mocks and circuits
- [x] Client verifies `H(note_plaintext) == commitment` before accepting notes
- [ ] Transparent boundary checks (SPL transfers) — deferred to Milestone 1 on-chain

---

## Milestone 0.14: Real Prover Backend Bringup (Local) ✅ COMPLETE

**Goal:** Run the existing user flows with **real proofs**, while keeping chain/indexer mocked.

**Result:** All 3 circuits validated with real UltraPlonk proofs. Docs updated to match implementation.

### 0.14.1 Complete Pipeline Coverage ✅

- [x] Transfer circuit: compile → prove → verify (pipeline test)
- [x] Shield circuit: pipeline test added
- [x] Unshield circuit: pipeline test added
- [ ] Add negative tests: wrong public inputs should fail verification (deferred)

### 0.14.2 Toolchain & Version Hygiene (deferred)

- [ ] Pin toolchain versions (Noir v1.0.0-beta.3 + bb 0.82.2) in README
- [ ] Add `scripts/install-toolchain.sh` or document installation
- [ ] Update README with "newcomer path" to run proofs locally

### 0.14.3 Fix Doc Drift ✅

- [x] Update `docs/circuit-security-requirements.md` to match N→M transfer model
- [x] Update `docs/implementation-status.md` — spend-auth is implemented, not placeholder
- [x] Document that shield `prove_asset_id_binding()` is no-op (chain computes asset_id)

### 0.14.4 Groth16 Backend (Alternative Path - deferred)

**References:**
- `../noir-main/` — Noir fork with Groth16 support
- `../acvm-backend-groth16/` — ACVM backend for Groth16 proving
- `../mobile-solana-e2e/solana-groth16-verifier/` — Solana on-chain Groth16 verifier

**Tasks:**
- [ ] Study `../acvm-backend-groth16/` integration pattern
- [ ] Implement `Groth16Prover` for MASP circuits
- [ ] Ensure public inputs layout is consistent with UltraPlonk
- [ ] Benchmark: Groth16 proof size (~192B) vs UltraPlonk (~2KB)

### 0.14.5 Acceptance Criteria ✅

- [x] All 3 circuits have pipeline tests (compile → prove → verify)
- [x] `cargo test --features ultraplonk-verifier` passes with real proofs
- [x] Docs match implementation

---

## Decision: Full Solana Integration First ✅

**Chosen path:** Complete doc hygiene (0.14.3) → Solana program with UltraPlonk (Milestone 1)

**Rationale:** Validates the full on-chain protocol E2E before optimizing proof system. Groth16 can be added later if CU/size becomes a blocker.

---

## Feature-Based Configuration (Current Approach)

**Insight:** We don't need separate crates - one crate with feature flags works:

```toml
[features]
default = ["std", "prove", "verify", "backend-mock"]
std = []              # Standard library (client)
prove = []            # SpendProver trait (client)
verify = []           # ProofVerifier trait (client + program)
backend-mock = []     # Mock implementations (testing)
backend-light = []    # Light Protocol (production)
```

**Why this works:**

- Read operations (exists, root, get_witness) → both client and program
- Write operations (insert) → not traits, they're instruction handlers
- Proof generation → client only (`prove` feature)
- Proof verification → both, but different impls (`verify` feature)

**When to actually split crates:**

- If compile times become painful
- If we need truly independent versioning
- If no_std compatibility becomes complex

---

## Milestone 1: Minimal On-chain POC (No Light) ⬅️ CURRENT

**Goal:** First Solana program that verifies proofs E2E.

**Depends on:** Milestone 0.14 ✅ (real prover testing complete)

### 1.0 Circuits ✅ COMPLETE

All circuit constraints are implemented and tested with mock proofs.

- [x] Shield: commitment integrity, amount range (u64), ct_hash binding
- [x] Transfer: membership, nullifier (nsk), spend auth (EC), balance, output nonces, ct_hashes
- [x] Unshield: transfer checks + public withdrawal binding (recipient limbs)
- [x] Circuits organized with named statement-check functions (audit trail)
- [x] Protocol-level docs for responsibility split (circuit vs chain vs client/indexer)

### 1.1 Program State

- [ ] Commitment Merkle tree (program-owned accumulator)
- [ ] Anchor history ring buffer (recent roots)
- [ ] Nullifier PDAs (one per spent nullifier)
- [ ] Pool token accounts (for SPL transfers)

### 1.2 Program Instructions

- [ ] `initialize` - Create tree state + pool accounts
- [ ] `shield` - Verify proof, transfer SPL in, append commitment
- [ ] `transfer` - Verify proof, check nullifier, append commitment(s)
- [ ] `unshield` - Verify proof, check nullifier, transfer SPL out

### 1.3 Proof Verification Integration

- [ ] Integrate `ultraplonk-core` verifier into program
- [ ] Profile CU usage per circuit
- [ ] Handle VK loading (embedded vs account-based)

### 1.4 Client Updates

- [ ] Build real Solana transactions (not mock)
- [ ] Submit to Surfpool/devnet
- [ ] Handle transaction confirmation + indexing

### 1.5 E2E Test

- [ ] Deploy to Surfpool
- [ ] Shield → Transfer → Unshield flow with real proofs
- [ ] Verify double-spend rejected (nullifier uniqueness)
- [ ] Document newcomer workflow in `README.md`

---

## Milestone 2: Production Hardening

**Goal:** Production-ready verification and frozen formats.

### 2.1 Performance

- [ ] Profile CU usage for each circuit
- [ ] Add phased verification if needed (multi-TX)
- [ ] Optimize proof size / public input encoding

### 2.2 Freeze Protocol Formats

- [x] Domain separation tags (frozen in `client/src/domain.rs`)
- [x] Note format (frozen in `docs/protocol-soundness.md`)
- [ ] Ciphertext blob format (freeze before production)
- [ ] Transaction calldata layout (freeze before production)

### 2.3 Context Binding (P2)

- [ ] Add `chain_id` / `program_id` to `tx_binding` to prevent cross-environment replay
- [ ] Document migration path for existing proofs

### 2.4 CI/CD

- [ ] CI tests for proof verification
- [ ] Automated circuit compilation + VK generation

---

## Milestone 3: On-chain Commitment Tree ✅ DESIGN COMPLETE

**Goal:** Privacy-preserving commitment storage (no linkability trails).

**Status:** Design and circuits are complete. Implementation is part of Milestone 1.

- [x] Spends reveal **nullifiers + anchor**, not input commitment references
- [x] Commitment set is an append-only Merkle accumulator (not Light/content-addressed)
- [x] Circuits verify Merkle path membership against public `anchor`
- [x] `docs/protocol-soundness.md` documents the model
- [ ] **On-chain implementation** — moved to Milestone 1.1 (program state)

---

## Milestone 3.1: Note Consolidation / UTXO Management (Research → Reference Implementation)

**Goal:** make spending feasible under Solana limits when balances are fragmented across many small notes.

**Deliverables (reference implementation):**

- [ ] Add a **consolidation user flow** to `client/tests/user_flows.rs` (public API only)
- [ ] Implement a mock/reference “consolidate” action (N→1 or N→2) in the client + mock chain semantics
- [ ] Add a **Stage-0 Noir circuit scaffold** for consolidation (like transfer/unshield/shield)
- [ ] Document privacy tradeoffs + wallet heuristics in `docs/protocol-soundness.md` or a dedicated doc

---

## Milestone 4: Light Protocol for Nullifiers

**Goal:** Eliminate unbounded PDA growth.

- [ ] Implement nullifier uniqueness via Light (create-once)
- [ ] Deterministic failure on duplicate nullifier
- [ ] No more PDAs for spentness

---

## Milestone 5: Multi-Asset in Single Transfer

**Goal:** Allow multiple asset types within a single transfer (true MASP semantics).

**Current state:** Single-asset per transfer is enforced (hard-sound). Multi-asset deferred.

- [x] `asset_id = Poseidon(token_address)` in notes
- [x] Asset type is private inside pool
- [x] Single-asset balance conservation enforced in circuits
- [ ] Implement value commitments (Pedersen-style) for multi-asset-in-one-transfer
- [ ] Update circuit constraints for multi-asset balance conservation
- [ ] Support multiple SPL mints per transaction at boundary

---

## Milestone 6: Relayer + Shielded Fees

**Goal:** Production transaction submission.

- [ ] Mandatory relayer fee output note
- [ ] Relayer service (accepts signed request, submits TX)
- [ ] User can transact without paying SOL directly

---

## Milestone 7: Scalable Sync (Tag-Based Discovery) — Optimization (Deferred)

**Goal:** O(1) payment discovery instead of O(N) trial decryption.

**Status:** Explicitly deferred until after we have E2E with real proofs + a Solana program POC. This is a major scalability/UX optimization, not required to validate core correctness.

See `docs/payment-discovery-analysis.md` for full design.

---

### Current OOB Limitations

⚠️ **Current state:** OOB requires liveness of both parties for EVERY payment:

1. Bob shares address with Alice (OOB)
2. Alice sends payment
3. Alice tells Bob the tx_sig (OOB) ← Required each time!
4. Bob calls `receive_payment()` to discover the note

**After this milestone:** OOB is only needed for the FIRST payment between two parties:

1. Bob shares address + long-term public key (OOB, once)
2. Shared secret established via DH
3. All subsequent payments use deterministic tags
4. Bob discovers payments via tag lookup (no OOB needed, no liveness required)

### 7.1 Key Infrastructure

- [ ] Long-term tag keypair derivation from seed
  - `lt_sk = H(DOM_LONG_TERM_KEY, spending_key)`
  - `lt_pk = lt_sk * G` (Baby JubJub)
- [ ] Include `lt_pk` in shielded address format
  - `address = (pk_d, g_d, lt_pk)`
- [ ] Shared secret derivation
  - `S = DH(my_lt_sk, their_lt_pk)`

### 7.2 Tag Stream Implementation

- [ ] Tag derivation: `tag[i] = H(DOM_TAG, S, direction, i)`
- [ ] Bidirectional streams (Alice→Bob vs Bob→Alice)
- [ ] Counter state management per counterparty
- [ ] Tag persistence in wallet state

### 7.3 Extended Note Plaintext (For Recovery)

**Critical for tag recovery after wallet loss!**

- [ ] Add `sender_lt_pk` to note plaintext (32 bytes)
- [ ] Add `tag_counter` to note plaintext (8 bytes)
- [ ] Update commitment derivation to include new fields
- [ ] Update encryption to handle larger plaintext
- [ ] Update circuit constraints for new note format

```rust
// Extended note plaintext
struct NotePlaintext {
    asset_id: Field,
    amount: u64,
    recipient: Field,
    nullifier_nonce: Field,
    randomness: Field,
    // NEW: Tag recovery data
    sender_lt_pk: [u8; 32],  // Sender's long-term public key
    tag_counter: u64,        // Position in tag stream
}
```

### 7.4 Transaction Format

- [ ] Include tag in transaction calldata
- [ ] Tag position: alongside (epk, C_enc)
- [ ] Indexer extracts and indexes tag→tx_sig

### 7.5 PIR Integration

- [ ] PIR client implementation
- [ ] Indexer tag→tx_hash mapping
- [ ] PIR server selection strategy
- [ ] Fallback to direct query (privacy tradeoff)

### 7.6 First Payment Problem

- [ ] Zero-value "handshake" transaction option
  - Establishes shared secret without transferring value
  - Can be bundled with first real payment
- [ ] Payment link with embedded long-term public key
  - `masp://pay?addr=...&lt_pk=...`
- [ ] OOB channel for key exchange
  - Signal integration
  - QR code scanning

### 7.7 Tag Recovery (After Wallet Loss)

- [ ] Recovery flow implementation:
  1. Trial decrypt all notes (expensive, one-time)
  2. Extract `sender_lt_pk` from each note
  3. Compute `S = DH(my_lt_sk, sender_lt_pk)`
  4. Extract `tag_counter` to know stream position
  5. Resume tag-based discovery
- [ ] Window search fallback
  - If counter is stale, search tag[N..N+W]
  - Handle missed payments gracefully
- [ ] Re-sync protocol for counterparties
  - OOB notification: "I recovered, please use tag[X]"

### 7.8 Encrypted Backup (Preferred Recovery)

- [ ] Wallet state serialization
  - Notes, counters, shared secrets
- [ ] Encryption with key derived from seed
  - `backup_key = H(DOM_BACKUP, spending_key)`
- [ ] Cloud storage integration (optional)
- [ ] Periodic auto-backup

### 7.9 Testing

- [ ] Unit tests for tag derivation
- [ ] E2E test: tag-based payment discovery
- [ ] E2E test: first payment key exchange
- [ ] E2E test: recovery with tag restoration
- [ ] E2E test: window search for missed payments
- [ ] E2E test: backup/restore flow

---

## Milestone 8: Privacy Mitigations

**Goal:** Reduce information leakage to indexer.

### 8.1 Witness Privacy

- [ ] PIR for `get_witness()` (hide which note being spent)
- [ ] Decoy witness requests (request N positions, only use 1)
- [ ] Document: self-hosted indexer option

### 8.2 Timing Privacy

- [ ] Random delays before spending newly received notes
- [ ] Transaction batching to increase anonymity set

### 8.3 Metadata Protection

- [ ] IP masking recommendations (Tor/Nym)
- [ ] Sealed sender for OOB messages

---

## Milestone 9: Outgoing Ciphertext (C_out)

**Goal:** Sender can recover what they sent after wallet loss.

See `docs/payment-discovery-analysis.md` for why this matters.

### 9.1 Outgoing Viewing Key

- [ ] Derive `ovk` from spending key
  - `ovk = H(DOM_OUTGOING_VK, spending_key)`
- [ ] Add to FullViewingKey struct

### 9.2 C_out Encryption

- [ ] Encrypt for sender: `C_out = Encrypt(ock, esk || note)`
  - `ock = KDF(ovk, epk, pk_d_recipient)`
- [ ] Include in transaction alongside C_enc
- [ ] ~200 bytes additional per output (current C_out format; exact bytes depend on ciphertext encoding)

### 9.3 Sender Recovery

- [ ] Scan transactions for C_out
- [ ] Decrypt with ovk to recover sent payments
- [ ] Link C_out to public nullifier (audit trail)

### 9.4 Testing

- [ ] E2E test: sender recovers sent payments
- [ ] E2E test: audit trail (nullifier → sent note)

---

## Milestone 10: Multi-device Sync

**Goal:** Keep multiple devices in sync without manual recovery.

**Depends on:** Milestone 7 (Tag-Based Discovery)

⚠️ **Not yet designed.** This milestone will likely build on tag-based discovery.

### 10.1 Design Considerations

- [ ] Push notifications when new notes arrive
- [ ] Incremental sync via tag streams
- [ ] Conflict resolution for concurrent spends from different devices
- [ ] Shared state management (which device "owns" which notes)

### 10.2 Current Workaround

Until this is implemented, users can:

1. Use `recover()` to do a full wallet rescan
2. Treat each device as independent wallet with same seed
3. Accept that devices may have stale state

---

## Milestone 11+: Future

- Viewing key delegation (give auditor read access)
- Multi-input transactions (spend N notes at once)
- Cross-chain shielded transfers
- Atomic swaps within shielded pool

---

## Tech Debt / Cleanup (Low Priority)

- [ ] **Reorganize circuit statements into directory structure**:
  - Move `circuits/masp/common/src/statements.nr` → `circuits/masp/common/src/statements/`
  - Each statement becomes its own file (e.g., `membership.nr`, `nullifier.nr`, `spend_auth.nr`)
  - Co-locate tests with each statement file (`#[test]` in same module)
  - Update imports in `transfer/`, `unshield/`, `shield/` circuits

---

## Design Documents

- **[Light Protocol Integration Analysis](docs/light-protocol-questions.md)** ⭐ Key findings: address CAN be set!
- **[Light Protocol Integration](docs/light-protocol-integration.md)** - LP integration design
- **[Data Structures](docs/data-structures.md)** - Commitment tree, nullifier set, identifiers
- **[Client Protocol Analysis](docs/client-protocol-analysis.md)** - Operation flows, sync, fees

---

## References

### Protocol Specs

- Orchard: <https://zips.z.cash/protocol/protocol.pdf> (Section 5)
- Sapling: <https://zips.z.cash/protocol/protocol.pdf> (Section 4)
- ZIP-32 Key Derivation: <https://zips.z.cash/zip-0032>

### Local Implementations

- **Sapling-Groth16:** `../sapling-groth16/` (Poseidon patterns, ~46K constraints)
- **UltraPlonk Verifier:** `../solana-ultraplonk-verifier/`

### Infrastructure

- Light Protocol: <https://www.zkcompression.com/>
- Helius ZK Compression API: <https://www.helius.dev/docs/api-reference/zk-compression/>

---

## Quick Commands

```bash
# Build circuit
cd circuits/masp && nargo compile

# Build program
cd programs/solana-masp && cargo build-sbf

# Full build
./scripts/build.sh

# Run client tests (76 tests: 50 unit + 26 E2E)
cd client && cargo test

# Run E2E tests with output
cd client && cargo test --test e2e_tests -- --nocapture

# Deploy to Surfpool (must be running)
./scripts/deploy.sh
```

---

## Notes

- **Surfpool** is started manually (not via MCP)
- **Update `knowledge.md`** when you learn something new
- **Update this file** when completing tasks or discovering new ones


# Solana MASP - Tasks

## Status: ✅ Milestone 0 Complete - Ready for Milestone 1

## Before Starting

1. **Read `knowledge.md`** - Architecture decisions are documented
2. **Update both files** as you make progress

---

## Overview

Building a Multi-Asset Shielded Pool (MASP) on Solana.

**Architecture:**

- UltraPlonk proofs via `../solana-ultraplonk-verifier/`
- Orchard-style Actions (1 spend + 1 output)
- Poseidon hashing via `light-poseidon` crate
- Multi-asset via Fiat-Shamir α tags
- Trait-based client (Indexer + Chain abstractions)
- Light Protocol for state compression (Milestone 3+)

**Circuits:**

- Shield circuit (deposit)
- Transfer circuit (shielded action)
- Unshield circuit (withdraw)

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

## Milestone 0.13: Indexer/Chain/Store Interface Review (Before Real Proofs)

**Goal:** Lock the *protocol-level interfaces* so the user flows stay stable while we swap internals.

**Guiding principle:** In production, the **chain does not “update the indexer”**. The indexer observes the ledger. In mocks, we may keep in-memory stores, but the APIs should reflect real expectations.

### 0.13.1 Review Indexer API (Production-Shape)

- [ ] Audit `Indexer` trait: what data is needed to support realistic client flows?
  - ciphertext scanning (paginated)
  - fetch outputs by `tx_sig` (OOB fast path)
  - witness retrieval (membership proof / Merkle path / Light proof)
  - optional “exists” checks (commitment presence)
- [ ] Decide how to model “indexing latency” in the reference implementation:
  - Option A: `Indexer::wait_for_update()` (noop in real impl; sleeps/polls in mocks)
  - Option B: test-only helper (preferred if we want to keep `Indexer` pure/read-only)
  - Document the decision in `knowledge.md`
- [ ] Add a **client-side hook** to model real-world indexing delay:
  - `MaspClient::wait_for_indexer_update()` calls into the indexer (or is a noop)
  - In mocks: can advance an internal “indexed up to” cursor or simply sleep
  - In real impl: likely a noop or polling helper (indexer is external)
  - Goal: tests can be written in a production-like order without assuming immediate indexing

### 0.13.2 Store Abstractions for Light Protocol (No Implementation Yet)

**Goal:** Abstract “append + membership/non-membership proofs” so we can swap between:

- Mock in-memory store (tests)
- Light Protocol + Helius (production)
- (Optional experiment) a small Solana program store (for learning / local iteration)

- [ ] Define the minimal wrapper APIs we will need around Light Protocol calls:
  - commitment append + witness generation
  - nullifier uniqueness / spentness checks (including batch)
  - anchor/root validity (ring buffer expectations)
- [ ] Ensure these abstractions *do not* leak Solana-specific details into `MaspClient` (client only talks to `Chain`/`Indexer`)
- [ ] Ensure the store abstraction **hides witness/anchor validity complexity**:
  - “append” returns enough information for later membership proofs
  - “prove membership/non-membership” returns opaque proof objects
  - client only sees `MembershipWitness` / `Anchor` and never cares how they’re produced
- [ ] Optional experiment (low priority): a tiny Solana program implementing a commitment/nullifier store
  - Goal: learn the operational shape (roots, proof requests) without committing to it
  - Still expected to be replaced by Light Protocol + Helius

### 0.13.3 Document Key/Address Decisions

- [ ] Document whether we want separate keys for encryption vs spending/addressing (and why)
  - Default assumption: **one root of trust (seed) is enough**
  - If we choose separate keys, document the concrete benefit and migration plan

### 0.13.4 Production-Likeness Review Checklist (Decisions or Explicit Deferrals)

**Goal:** Before we implement real proofs/program/indexer, confirm that the *shape* of the current protocol matches the intended production architecture (or record why we’re deferring).

#### Encryption / Note Handling

- [ ] Review `NoteEncryption` for production-shape correctness:
  - ciphertext format is stable + versioned (if needed)
  - AAD binding strategy is correct and documented
  - domain separation + KDF context is sufficient
- [ ] Decide whether to keep Baby JubJub-based ECDH for encryption or move to X25519:
  - document tradeoffs (engineering complexity, interoperability, auditability)
  - document the decision and how it affects address format
- [ ] Ensure decrypted notes are always verified before being accepted:
  - verify note plaintext ↔ commitment (cm) consistency
  - verify “ownership” / recipient binding checks

#### Transaction Calldata Layout (Indexer Extraction)

- [ ] Define and freeze v0 “transaction calldata” byte layout for our instruction(s):
  - public data (cm, nf, anchor, etc.)
  - encrypted output payload(s) (epk, ciphertext, optional metadata)
- [ ] Ensure `Indexer` APIs expose enough information for clients to validate decrypted notes:
  - ciphertext + epk
  - the corresponding commitment (cm) and output index
  - tx signature and ordering
- [ ] Decide how we represent “indexing latency” in tests (ties to 0.13.1):
  - client calls `wait_for_indexer_update()` between submit and scan

#### Witness/Anchor Validity (Abstracted by Stores)

- [ ] Document the intended end state for anchors/witnesses:
  - who serves membership witnesses (indexer)
  - what the chain validates (anchor ring buffer)
  - how Light Protocol proofs map into our `MembershipWitness` type

#### Documentation Consistency

- [ ] Reconcile docs with code for any “production-like” claims:
  - `docs/encryption-comparison.md`
  - `docs/payment-discovery-analysis.md`
  - `knowledge.md` “Status/Recent Completions”
  - ensure they match current decisions (e.g., whether C_out is in-scope right now)

---

## Milestone 0.14: Real Prover Backend Bringup (Local) — Mocks Everywhere Else

**Goal:** Run the existing user flows with **real proofs**, while keeping chain/indexer mocked.

**Why now:** This validates the end-to-end ZK plumbing (inputs ↔ circuit ↔ proof bytes ↔ verifier) before we add Solana complexity.

### 0.14.1 Toolchain & Version Hygiene (Critical)

⚠️ UltraPlonk and Groth16 paths may require different Noir/bb versions.

- [ ] Pin toolchain versions (Noir + bb) per proof system and document them
- [ ] Add scripts/docs to switch toolchains safely (avoid local version drift)
- [ ] Update README with “newcomer path” to run proofs locally

### 0.14.2 Integrate ONE Proof System First

Pick the easiest first (likely UltraPlonk):

- [ ] Implement `UltraPlonkProver` using `../solana-ultraplonk-verifier/` (local proving)
- [ ] Implement matching local verifier and wire into `ProofVerifier::verify_local`
- [ ] Add tests that run via our `SpendProver` / `ProofVerifier` abstraction (no Solana yet)
- [ ] Review and adopt best build/test patterns from:
  - `../solana-ultraplonk-verifier/WORKFLOW.md`
  - `../mobile-solana-e2e/solana-groth16-verifier/` scripts
  - Goal: newcomers can run “prove → verify” with 1–2 commands
- [ ] Document and prototype **programmatic witness generation** (mobile requirement):
  - Inputs encoded via Noir ABI (no `Prover.toml` in production)
  - ACVM execution to solve witness in-memory
  - Prover backend produces proof bytes (UltraPlonk/Groth16)
  - Reference: `../mobile-solana-e2e/src/noir.rs`

### 0.14.3 Add Groth16 as Second Backend (After UltraPlonk Works)

- [ ] Implement `Groth16Prover` using `../mobile-solana-e2e/solana-groth16-verifier/` (local proving)
- [ ] Implement matching local verifier and wire into `ProofVerifier::verify_local`
- [ ] Ensure public inputs layout is consistent across backends (document differences)

### 0.14.4 Acceptance Criteria

- [ ] `cargo test` passes with `MASP_PROOF_SYSTEM=ultraplonk` using **real proofs**
- [ ] User flow tests pass with proofs real and everything else mocked

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

## Milestone 1: Minimal On-chain POC (No Light)

**Goal:** First Solana program that verifies something E2E.

⚠️ **Before implementing circuits, read `docs/circuit-security-requirements.md`!**

### 1.0 Circuit Scaffolding & Auditability (Noir)

**Goal:** Get a full end-to-end path compiling/proving/verifying with “noop” constraints first, then implement each required statement incrementally with targeted tests.

- [ ] Organize circuits so each security statement is a named function/module
- [ ] `main.nr` for each circuit should clearly call each statement-check function (audit trail)
- [ ] Stage 0 (noop): compile + prove + verify end-to-end with placeholder constraints
- [ ] Stage 1+: implement statement checks one-by-one with unit tests + E2E tests

### 1.1 Program State

- [ ] Commitment Merkle tree (toy depth 16)
- [ ] Root stored in PDA
- [ ] Nullifier PDAs (one per spent nullifier)

### 1.2 Shield Circuit (Noir)

- [ ] Stage 0 (noop): define inputs + generate VK + local prove/verify
- [ ] Implement: commitment integrity (recompute cm from note fields)
- [ ] Implement: amount range check (u64)
- [ ] Tests: per-statement + E2E

### 1.3 Transfer Circuit (Noir)

- [ ] Stage 0 (noop): define inputs + generate VK + local prove/verify
- [ ] Implement: membership proof against anchor
- [ ] Implement: nullifier correctness (nk, nullifier_nonce)
- [ ] Implement: balance conservation (single-asset first; multi-asset α tags later in Milestone 5)
- [ ] Tests: per-statement + E2E

### 1.4 Unshield Circuit (Noir)

- [ ] Stage 0 (noop): define inputs + generate VK + local prove/verify
- [ ] Implement: membership proof against anchor
- [ ] Implement: nullifier correctness
- [ ] Implement: public amount/recipient match expected
- [ ] Tests: per-statement + E2E

### 1.5 Program Instructions

- [ ] `initialize` - Create tree state account
- [ ] `shield` - Verify proof, append commitment
- [ ] `transfer` - Verify proof, check nullifier, append commitment
- [ ] `unshield` - Verify proof, check nullifier, release funds

### 1.6 Client

- [ ] Build shield transaction
- [ ] Build transfer transaction
- [ ] Build unshield transaction
- [ ] Note management (create, store, scan)

### 1.7 E2E Test

- [ ] Deploy to Surfpool
- [ ] Shield → Transfer → Unshield flow
- [ ] Verify double-spend rejected
- [ ] Add/extend scripts so iteration is easy as circuits change:
  - build circuit + regenerate artifacts + build program
  - deploy program to Surfpool
  - run user flows against Surfpool
  - document the full newcomer workflow in `README.md`

---

## Milestone 2: Production UltraPlonk Verification

**Goal:** Reliable proof verification within CU/tx limits.

- [ ] Profile CU usage for each circuit
- [ ] Add phased verification if needed (multi-TX)
- [ ] Freeze domain separation tags
- [ ] Freeze note format
- [ ] CI tests for verification

---

## Milestone 3: Light Protocol for Commitments

**Goal:** Stop storing big state ourselves.

- [ ] Replace on-chain Merkle with Light-backed structure
- [ ] Program stores only: anchor ring buffer + config
- [ ] Indexer serves witnesses
- [ ] Keep nullifiers as PDAs (for now)

---

## Milestone 4: Light Protocol for Nullifiers

**Goal:** Eliminate unbounded PDA growth.

- [ ] Implement nullifier uniqueness via Light (create-once)
- [ ] Deterministic failure on duplicate nullifier
- [ ] No more PDAs for spentness

---

## Milestone 5: Multi-Asset with α Tags

**Goal:** Real MASP - multiple asset types.

- [ ] Add asset_id to notes
- [ ] Add α/tag conservation equation to circuits
- [ ] Support multiple SPL mints at boundary
- [ ] Asset type private inside pool
- [ ] Decide whether `asset_id` should be `Poseidon(token_address)` (current plan) vs using token address directly; document tradeoffs and final decision

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
- [ ] ~64 bytes additional per output

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

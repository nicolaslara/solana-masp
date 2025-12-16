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

### 0.5 Ciphertext Format (Deferred)

- [ ] Define encryption scheme (ECIES or ChaCha20-Poly1305)
- [ ] Note encryption/decryption
- [ ] Trial decryption for scanning

**Note:** Deferred to Milestone 1 - not blocking circuit development.

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
- [x] All tests pass (36 tests)

### 0.8 Proof System Traits ✅

- [x] `SpendProver` trait (client-side proof generation)
- [x] `SpendVerifier` trait (on-chain/client verification)
- [x] `MockSpendProver`/`MockSpendVerifier` implementations
- [x] `NoteCommitmentStore` trait (membership proofs)
- [x] `NullifierSet` trait (double-spend prevention)
- [x] `MembershipWitness` enum (MerklePath vs LightValidityProof)

---

## Feature-Based Configuration (Current Approach)

**Insight:** We don't need separate crates - one crate with feature flags works:

```toml
[features]
default = ["std", "prove", "verify", "backend-mock"]
std = []              # Standard library (client)
prove = []            # SpendProver trait (client)
verify = []           # SpendVerifier trait (client + program)
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

### 1.1 Program State

- [ ] Commitment Merkle tree (toy depth 16)
- [ ] Root stored in PDA
- [ ] Nullifier PDAs (one per spent nullifier)

### 1.2 Shield Circuit (Noir)

- [ ] Public inputs: new_commitment
- [ ] Private inputs: note_plaintext, rcm
- [ ] Constraints: commitment matches claimed value
- [ ] Range check: amount is u64
- [ ] Generate VK

### 1.3 Transfer Circuit (Noir)

- [ ] Public inputs: anchor, nullifier, new_commitment, tx_binding_hash
- [ ] Private inputs: note, Merkle path, spending key, output note
- [ ] Constraints: membership, nullifier correctness, balance
- [ ] Generate VK

### 1.4 Unshield Circuit (Noir)

- [ ] Public inputs: anchor, nullifier, amount (public!), recipient (public!)
- [ ] Private inputs: note, Merkle path, spending key
- [ ] Constraints: membership, nullifier correctness, amount matches
- [ ] Generate VK

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

---

## Milestone 6: Relayer + Shielded Fees

**Goal:** Production transaction submission.

- [ ] Mandatory relayer fee output note
- [ ] Relayer service (accepts signed request, submits TX)
- [ ] User can transact without paying SOL directly

---

## Milestone 7: Privacy Mitigations

**Goal:** Reduce information leakage to indexer.

### 7.1 Witness Privacy

- [ ] PIR (Private Information Retrieval) for `get_witness()`
- [ ] Decoy witness requests (request N positions, only use 1)
- [ ] Document: self-hosted indexer option

### 7.2 Sync Privacy

- [ ] Oblivious sync protocol design
- [ ] Option to always sync from position 0
- [ ] Batched sync with random delays

### 7.3 Timing Privacy

- [ ] Random delays before spending newly received notes
- [ ] Transaction batching to increase anonymity set

---

## Milestone 8+: Future

- OOB note delivery (sender → recipient direct)
- Viewing key delegation
- Multi-input transactions (spend N notes at once)

---

## Design Documents

- **[Light Protocol Integration Analysis](docs/light-protocol-questions.md)** ⭐ Key findings: address CAN be set!
- **[Light Protocol Integration](docs/light-protocol-integration.md)** - LP integration design
- **[Data Structures](docs/data-structures.md)** - Commitment tree, nullifier set, identifiers
- **[Client Protocol Analysis](docs/client-protocol-analysis.md)** - Operation flows, sync, fees

---

## References

### Protocol Specs

- Orchard: https://zips.z.cash/protocol/protocol.pdf (Section 5)
- Sapling: https://zips.z.cash/protocol/protocol.pdf (Section 4)
- ZIP-32 Key Derivation: https://zips.z.cash/zip-0032

### Local Implementations

- **Sapling-Groth16:** `../sapling-groth16/` (Poseidon patterns, ~46K constraints)
- **UltraPlonk Verifier:** `../solana-ultraplonk-verifier/`

### Infrastructure

- Light Protocol: https://www.zkcompression.com/
- Helius ZK Compression API: https://www.helius.dev/docs/api-reference/zk-compression/

---

## Quick Commands

```bash
# Build circuit
cd circuits/masp && nargo compile

# Build program
cd programs/solana-masp && cargo build-sbf

# Full build
./scripts/build.sh

# Run client tests (36 tests)
cd client && cargo test

# Deploy to Surfpool (must be running)
./scripts/deploy.sh
```

---

## Notes

- **Surfpool** is started manually (not via MCP)
- **Update `knowledge.md`** when you learn something new
- **Update this file** when completing tasks or discovering new ones

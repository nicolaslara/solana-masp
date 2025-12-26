# Claude Code Configuration for Solana MASP

This repository implements a Multi-Asset Shielded Pool (MASP) on Solana, inspired by Zcash's Orchard/Sapling protocols and Namada's MASP.

## Current Work Context

**Primary Focus:** Solana MASP spike (`spikes/solana-masp/`)

**Current Phase:** Milestone 1 - Solana Integration (Circuits complete, moving to on-chain implementation)

**Status:**
- ✅ All 3 circuits (shield, transfer, unshield) implemented and verified with real UltraPlonk proofs
- ✅ Full client library with trait-based architecture (Chain, Indexer, NoteEncryption abstractions)
- ✅ ALL 9 user_flows tests pass with real UltraPlonk proofs on Surfpool!
- ✅ CPI-based verification architecture working (~1.2M CU per verification)
- 🚧 On-chain program scaffolded, needs full implementation

## Before Starting Any Work

**ALWAYS READ THESE FILES FIRST:**

1. **`spikes/solana-masp/tasks.md`** - Current phase, open tasks, priorities
2. **`spikes/solana-masp/knowledge.md`** - Learnings, decisions, open questions
3. **`spikes/solana-masp/docs/protocol-soundness.md`** ⚠️ CRITICAL - Normative protocol spec
4. **`spikes/solana-masp/docs/circuit-security-requirements.md`** ⚠️ CRITICAL for circuit work

**UPDATE THESE FILES** as you make progress, learn new things, or make decisions.

## Project Structure

```
privacy-infrastructure-sandbox/
└── spikes/solana-masp/          # Current focus
    ├── tasks.md                 # ← Track progress here
    ├── knowledge.md             # ← Record learnings here
    ├── README.md                # Project overview
    ├── circuits/masp/           # Noir circuits (UltraPlonk)
    │   ├── common/              # Shared types and statement functions
    │   ├── shield/              # Shield circuit (deposit)
    │   ├── transfer/            # Transfer circuit (shielded→shielded)
    │   └── unshield/            # Unshield circuit (withdraw)
    ├── programs/
    │   ├── solana-masp/         # Main MASP program
    │   ├── masp-verifier/       # Separate verifier program (CPI)
    │   └── mock-commitment-store/  # Mock stores for testing
    ├── client/                  # Rust client library
    │   ├── src/
    │   │   ├── backends/        # Chain/Indexer implementations
    │   │   ├── traits.rs        # Protocol boundaries
    │   │   └── client.rs        # MaspClient
    │   └── tests/
    │       ├── user_flows.rs    # Main integration tests
    │       └── test_env.rs      # Backend configuration
    ├── docs/
    │   ├── protocol-soundness.md          # ⚠️ CRITICAL
    │   ├── circuit-security-requirements.md # ⚠️ CRITICAL
    │   ├── implementation-status.md
    │   └── design-decisions/
    └── scripts/
        ├── build.sh             # Build circuits + program
        └── deploy.sh            # Deploy to Surfpool
```

## Development Principles

### Reference Implementation Philosophy

This is a **reference implementation**. Internals can be mocked initially, but **user-facing flows and protocol-level interfaces must remain production-shaped**.

**Production-shaped means:**
- Client flows stay stable: `shield()`, `transfer_to()`, `unshield()`, `receive_payment()`, `recover()`
- Mocks are in-memory, not "fake production"
- Indexer is external in production (chain does not "update the indexer")
- Traits are protocol boundaries - avoid churn in `Chain`/`Indexer`/`NoteEncryption`/`SpendProver`

### Decision Discipline

**Document-first changes** for:
- Indexer/store abstraction changes
- Note format changes
- Domain separation changes
- Proof public-input layout changes

When something gets hard, step back and reason from user flows downwards. Don't patch traits "just to make it work".

## Code Quality Standards

### Noir Circuit Development

⚠️ **ALWAYS read `docs/circuit-security-requirements.md` before modifying circuits!**

**Best practices:**
- Use Poseidon2 for hashing (BN254-native, ~200 constraints vs ~21K for BLAKE2s)
- Domain separation: prepend constant to hash inputs
- Prefer `Field` over `u64` when possible (native to ZK)
- Document expected constraints per component
- Test with `nargo test` before generating proofs

**Security requirements:**
- Commitment integrity: Always re-derive commitment from note fields
- Range checks: All amounts must be < 2^64 to prevent overflow
- Nullifier derivation: Must use `nsk` (secret), not `nk` (public)
- Balance conservation: Input amounts = output amounts (+ public delta)
- Membership proof: Verify Merkle path against anchor

### Rust Development

**Best practices:**
- Use `thiserror` for custom errors (not string errors)
- Prefer `&[u8]` over `Vec<u8>` for inputs
- Use `#[derive(Debug, Clone, PartialEq)]` liberally
- Add `#[cfg(test)]` unit tests alongside code
- Use `cargo clippy` and `cargo fmt` before committing
- Fix warnings whenever possible

### Solana Program Development

**Constraints:**
- Target <1.4M CU per transaction (hard limit)
- Stack limit is 4KB - use heap for large structures
- Never allocate unbounded `Vec` on-chain
- Use `msg!` for debugging, but remove in production (costs CU)

**Best practices:**
- Use custom errors with `thiserror`, not `ProgramError::Custom(n)`
- Log important values for debugging
- Validate all inputs
- Use borsh for serialization

## Toolchain

### Versions (Pinned)

```bash
# Noir + Barretenberg (UltraPlonk)
nargo --version   # v1.0.0-beta.3
bb --version      # 0.82.2

# Solana
solana --version  # Latest stable
```

### Installation

```bash
# Install Noir
noirup -v v1.0.0-beta.3

# Install Barretenberg
bbup  # Auto-installs bb 0.82.2

# Verify
nargo --version
bb --version
```

## Common Workflows

### Circuit Development

```bash
# 1. Edit circuit
vim circuits/masp/<circuit>/src/main.nr

# 2. Test locally
cd circuits/masp/<circuit>
nargo test

# 3. Compile
nargo compile  # → target/<circuit>.json

# 4. Generate VK (if needed)
bb OLD_API write_vk -b target/<circuit>.json -o vk.bin

# 5. Via script (builds all circuits + program)
./scripts/build.sh
```

### Solana Program Development

```bash
# 1. Edit program
vim programs/solana-masp/src/lib.rs

# 2. Format and lint
cd programs/solana-masp
cargo fmt
cargo clippy

# 3. Build for Solana
cargo build-sbf

# 4. Deploy to Surfpool (must be running)
solana program deploy target/deploy/solana_masp.so --url http://127.0.0.1:8899
```

### Client Development

```bash
cd client
cargo fmt
cargo clippy
cargo test
cargo build
```

### Running Tests

```bash
# Client tests only (fast, all mocks)
cd client && cargo test

# User flows (main integration tests)
cd client && cargo test --test user_flows

# With Surfpool (auto-deploys program)
MASP_CHAIN=surfpool cargo test -p masp-client \
  --features solana-backend,onchain-mock \
  --test user_flows -- --nocapture --test-threads=1

# With real UltraPlonk proofs
MASP_PROOF_SYSTEM=ultraplonk \
  cargo test -p masp-client --features ultraplonk-verifier \
  --test user_flows -- --nocapture

# Show backend configuration
MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
```

## Architecture Overview

### Core Components

**Circuits (Noir/UltraPlonk):**
- `shield` - Deposit from transparent to shielded
- `transfer` - Shielded spend + output (N→M, up to 3 inputs/outputs)
- `unshield` - Withdraw from shielded to transparent

**Programs (Solana):**
- `solana-masp` - Main MASP program (state transitions, CPI to verifier)
- `masp-verifier` - Separate verifier program (UltraPlonk verification)
- `mock-commitment-store` - Mock stores for local testing

**Client (Rust):**
- Trait-based architecture: `Chain`, `Indexer`, `NoteEncryption`, `SpendProver`
- Configurable backends via environment variables
- Wallet state management (notes, keys, sync)

### Key Abstractions

```rust
// Protocol boundaries (traits)
trait Chain {
    fn submit_transaction(...) -> Result<TxSig>;
    fn is_nullifier_spent(nf: &[u8; 32]) -> Result<bool>;
    fn get_current_anchor() -> Result<[u8; 32]>;
}

trait Indexer {
    fn get_witness(cm: &[u8; 32]) -> Result<MembershipWitness>;
    fn scan_outputs_since(tx_sig: &str) -> Result<Vec<OutputCiphertext>>;
    fn get_ciphertext_by_hash(ct_hash: &[u8; 32]) -> Result<Ciphertext>;
}

trait NoteEncryption {
    fn encrypt(note: &Note, pk_d: &Point) -> Result<Ciphertext>;
    fn try_decrypt(ct: &Ciphertext, ivk: &Scalar) -> Result<Note>;
}

trait SpendProver {
    fn prove_transfer(inputs: TransferInputs) -> Result<Proof>;
    fn prove_shield(inputs: ShieldInputs) -> Result<Proof>;
    fn prove_unshield(inputs: UnshieldInputs) -> Result<Proof>;
}
```

## Critical Design Decisions

### 1. CPI-Based Verification Architecture

**Problem:** Embedded UltraPlonk verification hits Solana's 4KB stack limit in MASP program.

**Solution:** Isolate verification in separate `masp-verifier` program, call via CPI.

**Flow:**
1. Client creates proof buffer (owned by `masp-verifier`)
2. Client uploads proof in chunks via verifier's `UploadChunk` instruction
3. Client calls MASP instruction with verifier program account
4. MASP CPIs to `masp-verifier.Verify` instruction
5. Verifier reads proof from buffer, verifies, returns success/failure

### 2. Two-Transaction Model (Ciphertext DA)

**Tx A (ciphertext posting):** Publishes output ciphertext bytes to ledger history
**Tx B (MASP state transition):** Includes proof + `ct_hash(es)` + commitments/nullifiers

- Ciphertexts stored in transaction calldata (archive-retrievable)
- Binding via `ct_hash = H(DOM_CIPHERTEXT, ciphertext_bytes)`
- Wallets MUST verify `ct_hash` matches fetched bytes before accepting outputs

### 3. Single-Asset Per Transfer (Current)

**Current:** Each transfer spends notes and creates outputs of the **same `asset_id`**
- Balance conservation: `input_amount == Σ(output_amounts)` (u64 integer equality)

**Future (Milestone 5):** Multi-asset via value commitments (Pedersen-style)

### 4. Chain/Indexer Synchronization

**LocalSync mode (Testing):**
- Chain holds `Arc<MockStore>`, updates it after TX success
- Indexer is the **same Arc** - sees updates immediately

**External mode (Production):**
- Chain does NOT hold store
- External indexer (Helius/Light) observes ledger independently
- Client polls via `wait_for_indexer_update(tx_sig)`

### 5. Key Hierarchy (Sapling-style)

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
- Nullifiers use `nsk` (secret), not `nk` (public) - critical for spend authorization

## Known Issues and Gotchas

### 1. EC Operations Under Predicates (Noir/bb)

**Problem:** EC blackbox functions inside conditional blocks cause verification failures when the condition is false.

**Root cause:** Known issue in Noir ↔ Barretenberg pipeline around ACIR predicates.

**Solution:** Pattern A - Compute unconditionally, gate only asserts:

```noir
// BAD: EC ops inside conditional - FAILS when enabled=false
if enabled {
    let result = compute_point(ivk, diversifier_index);
    assert(recipient == result);
}

// GOOD: Compute unconditionally, use gated assert
let result = compute_point(ivk, diversifier_index);
// assert_eq_if: enforces (a == b) only when enabled
fn assert_eq_if(enabled: bool, a: Field, b: Field) {
    let e = enabled as Field;
    assert((a - b) * e == 0);
}
assert_eq_if(enabled, recipient, result);
```

**Trade-off:** We pay for MAX_INPUTS EC derivations regardless of how many are enabled.

### 2. Surfpool RPC Performance

**Default commitment level:** `finalized` waits for 31 confirmations (~5s per TX)

**Solution:** Use `confirmed` commitment (1 confirmation, ~8x faster):

```rust
let config = RpcSendTransactionConfig {
    skip_preflight: false,
    preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
    ..Default::default()
};
```

## Environment Variables

### Backend Configuration

```bash
# Chain backend
MASP_CHAIN=mock          # In-memory mock (default)
MASP_CHAIN=surfpool      # Local Surfpool (http://127.0.0.1:8899)
MASP_CHAIN=devnet        # Solana devnet
MASP_CHAIN=<url>         # Custom RPC URL

# Indexer backend
MASP_INDEXER=mock        # In-memory mock (default)
MASP_INDEXER=light       # Light Protocol via Helius

# Encryption backend
MASP_ENCRYPTION=chacha   # ChaCha20-Poly1305 (default, production)
MASP_ENCRYPTION=mock     # Mock encryption (fast testing, INSECURE)

# Proof system
MASP_PROOF_SYSTEM=mock       # Mock proofs (default)
MASP_PROOF_SYSTEM=ultraplonk # Real UltraPlonk proofs
MASP_PROOF_SYSTEM=groth16    # Groth16 (future)

# Verification location
MASP_PROOF_VERIFY=local      # Local verification (default)
MASP_PROOF_VERIFY=onchain    # On-chain verification

# Program configuration
MASP_PROGRAM_ID=<pubkey>     # Use this program ID (skip auto-deploy)
MASP_VERIFIER_ID=<pubkey>    # Verifier program ID (enables CPI mode)
MASP_SKIP_BUILD=1            # Skip rebuild check
MASP_PROGRAM_FEATURES=...    # Override build features

# Debugging
MASP_PRINT_CONFIG=1          # Print backend configuration
MASP_KEEP_PROOF_ARTIFACTS=1  # Keep proof artifacts after tests
```

## Critical Documentation

**Must-read before making changes:**

1. **`spikes/solana-masp/docs/protocol-soundness.md`**
   - Normative protocol specification
   - What is checked where (client/chain/indexer/circuits)
   - Security invariants and privacy guarantees

2. **`spikes/solana-masp/docs/circuit-security-requirements.md`**
   - All constraints that MUST be enforced in ZK circuits
   - Shield, Transfer, Unshield circuit requirements
   - Audit priorities

3. **`spikes/solana-masp/knowledge.md`**
   - Design decisions with rationale
   - Learnings and discoveries
   - Open questions

4. **`spikes/solana-masp/tasks.md`**
   - Current phase and priorities
   - Implementation tracking
   - Next steps

## Common Commands Reference

```bash
# Build circuits
cd circuits/masp/<circuit> && nargo compile

# Build program
cd programs/solana-masp && cargo build-sbf

# Full build (circuits + program)
./scripts/build.sh

# Run client tests
cd client && cargo test

# Run E2E tests with output
cd client && cargo test --test user_flows -- --nocapture

# Deploy to Surfpool
./scripts/deploy.sh

# Start Surfpool
surfpool start

# Check Surfpool health
curl http://127.0.0.1:8899 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
```

## Next Priority Tasks (from tasks.md)

**Current sprint (Milestone 1.6-1.9):**

1. **Protocol Shape Freeze + Codec Layer (P0)**
   - Freeze instruction byte layouts
   - Introduce `masp-protocol` crate for encoding/decoding
   - Single source of truth for `ct_hash` canonicalization

2. **Implement Tx A Ciphertext Posting on SolanaChain (P0.5)**
   - Submit ciphertext posting transaction
   - Update client flows to post ciphertexts before MASP Tx B

3. **Stop "Chain updates Indexer" in Surfpool/Devnet tests (P1)**
   - Add mock "RPC ledger indexer"
   - Switch to External indexer mode
   - Chain and indexer are separate actors

4. **External-mode Chain Reads (P1)**
   - Implement `get_current_anchor()` by reading on-chain TreeState
   - Implement `is_nullifier_spent()` by checking PDA existence
   - Implement `batch_check_nullifiers()` via batched account fetch

## Communication and Updates

**ALWAYS update documentation as you work:**

1. **After completing work:**
   - Update `tasks.md` - check off completed tasks, add new discoveries
   - Update `knowledge.md` - record learnings, decisions, findings

2. **When changing interfaces:**
   - Update protocol docs (`protocol-soundness.md`, `circuit-security-requirements.md`)
   - Record rationale in `knowledge.md`

3. **Before making protocol changes:**
   - Document the change in `tasks.md` with rationale
   - Get alignment on approach before implementation

## Key Contacts and References

**References consulted:**
- Zcash Protocol Spec (Sections 4 & 5) - Sapling and Orchard protocols
- Local `sapling-groth16` spike - Poseidon patterns, constraint counts
- Light Protocol whitepaper - ZK compression on Solana
- Namada MASP - Multi-asset patterns

**Related spikes in this repo:**
- `spikes/sapling-groth16/` - Circom implementation, Poseidon patterns
- `spikes/solana-ultraplonk-verifier/` - UltraPlonk verification on Solana
- `spikes/mobile-solana-e2e/` - Mobile proof generation patterns

## Working with Claude Code

**When you ask me to work on this codebase:**

1. I will read `tasks.md` and `knowledge.md` to understand current state
2. I will check the relevant design docs before making changes
3. I will update documentation as I make progress
4. I will follow the decision discipline (document-first for protocol changes)
5. I will maintain the reference implementation philosophy (production-shaped interfaces)

**If you ask me to implement something:**

1. I'll check if it aligns with current priorities in `tasks.md`
2. I'll read relevant security docs before touching circuits
3. I'll maintain trait boundaries and avoid protocol churn
4. I'll write tests alongside implementation
5. I'll update `tasks.md` and `knowledge.md` when done

**If you ask me questions:**

1. I'll reference the documentation to give you accurate answers
2. I'll point you to relevant files and line numbers
3. I'll explain design decisions with rationale from `knowledge.md`
4. I'll help you understand the architecture and trade-offs

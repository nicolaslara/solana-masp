# Solana MASP (Multi-Asset Shielded Pool)

> **Reference implementation / exploratory project.** This is a research spike exploring the feasibility of building a MASP on Solana. It is not audited, not production-ready, and APIs/circuits may change without notice.

A Multi-Asset Shielded Pool on Solana, inspired by Zcash's Orchard/Sapling protocols and Namada's MASP.

## Status

- All 3 circuits (shield, transfer, unshield) implemented with real UltraPlonk proofs
- Full client library with trait-based backend architecture
- All 8 user flow integration tests pass (mock and Surfpool backends)
- CPI-based on-chain verification working (~1.2M CU per verification)
- Light Protocol integration in progress (nullifier compression via ZK)
- See [`docs/implementation-status.md`](docs/implementation-status.md) for detailed security statement tracking (S1-U3)

## Protocol Summary

The protocol implements private value transfers on Solana using an Orchard-inspired commitment/nullifier model. For the full normative spec, see [`docs/protocol-soundness.md`](docs/protocol-soundness.md).

### State Model

- **Commitment tree**: an append-only Merkle tree (depth 32) of note commitments. The program maintains a rolling set of recent **anchors** (roots) for spend context.
- **Nullifier set**: a set with insert-once semantics. Spending a note reveals its nullifier; duplicates are rejected. Production target uses Light Protocol address trees for compressed on-chain storage.

### Note Structure

Each shielded note is a commitment to:

```
cm = H(DOM_NOTE_COMMIT, asset_id, amount, recipient, diversifier_index, nullifier_nonce, note_randomness)
```

Notes are discovered by recipients via trial decryption of on-chain ciphertexts (ChaCha20-Poly1305 AEAD).

### Operations

| Operation | Description | Key checks |
|-----------|-------------|------------|
| **Shield** | Deposit transparent tokens into the pool | Token transfer verified, commitment integrity, asset binding |
| **Transfer** | Move value between shielded notes (N-to-M, max 3x3) | Merkle membership, spend authorization (SpendingKey-only), nullifier correctness, value conservation, tx binding |
| **Unshield** | Withdraw from pool to a public address | Same as transfer + public amount/asset/recipient binding |

### Security Properties

- **No inflation**: value cannot be created inside the pool
- **No double-spend**: each note spent at most once (nullifier uniqueness)
- **No unauthorized spend**: only the SpendingKey holder can spend (FullViewingKey cannot)
- **Correct boundaries**: shield deposits and unshield withdrawals match actual token transfers

### Spend Authorization

Ownership is proven entirely in ZK (no external signatures). The spend proof demonstrates knowledge of a `spending_key` that derives the note's recipient address and nullifier secret key (`nsk`). This is what makes "view-only wallets can see but cannot spend" possible.

### Ciphertext Data Availability

Output ciphertexts are posted in a separate transaction (Tx A) and bound to the state transition (Tx B) via hash commitment (`ct_hash`). Ciphertexts are published for outputs only; input ciphertexts are never published (privacy property). See [`docs/design-decisions/ciphertext-da-and-binding.md`](docs/design-decisions/ciphertext-da-and-binding.md).

## Circuit Security Checks

Each circuit enforces a specific set of constraints inside ZK proofs to guarantee correctness and privacy. The on-chain program and client handle additional checks outside the circuits. For the full formal specification, see [`docs/circuit-security-requirements.md`](docs/circuit-security-requirements.md).

### Shield (Deposit)

When a user deposits tokens into the shielded pool, the circuit proves:

- **Commitment integrity** — the published commitment is the correct hash of the note's fields (asset, amount, recipient, nonces, randomness). Without this, a prover could create a commitment that doesn't correspond to any real note, letting them later "spend" fabricated value.
- **Amount range** — the deposit amount fits in 64 bits. This prevents arithmetic overflow tricks that could break balance checks later.
- **Ciphertext hash binding** — the proof is tied to a specific encrypted note payload (non-zero `ct_hash`). This ensures the recipient can discover and decrypt the note.

The chain separately verifies the actual SPL token transfer, derives the `asset_id` from the real mint address, and appends the commitment to the tree.

### Transfer (Shielded N→M)

The transfer circuit is the most complex, handling up to 3 inputs and 3 outputs in a single proof:

- **Merkle membership** — each spent note's commitment exists in the commitment tree at the claimed root (`anchor`). This prevents spending notes that were never deposited.
- **Commitment re-derivation** — the prover knows the full plaintext of each input note (not just the commitment hash). This proves actual knowledge of the note's contents.
- **Nullifier derivation** — each nullifier is correctly derived from the owner's nullifier secret key (`nsk`), not the public nullifier key. This is critical: it means someone with only a FullViewingKey can see transactions but cannot spend funds.
- **Ownership authorization** — a full elliptic-curve spend proof demonstrates that the prover holds the `spending_key` that derives the note's recipient address. This is the core "only the owner can spend" guarantee.
- **Output commitment integrity** — each new output note's commitment is correctly formed, so recipients will be able to find and spend them.
- **Amount range** — all input and output amounts fit in 64 bits, preventing overflow exploits.
- **Balance conservation** — the sum of input amounts equals the sum of output amounts, and all notes use the same asset type. No value is created or destroyed.
- **Output nonce derivation** — each output note's nullifier nonce is deterministically derived from the transaction binding and output index. This guarantees uniqueness without requiring external randomness.
- **Transaction binding** — a binding hash locks together the anchor, nullifiers, and input/output counts. This prevents relayers or intermediaries from reordering or splicing parts of different transactions.
- **Ciphertext hash binding** — enabled outputs have non-zero ciphertext hashes; disabled slots have zero. This ties each proof to its encrypted payloads.
- **Count correctness and slot gating** — the declared input/output counts match the actual number of enabled slots, and disabled slots are properly zeroed. This prevents hidden inputs or outputs.

The chain enforces anchor freshness, nullifier uniqueness (preventing double-spends), and proof verification.

### Unshield (Withdraw)

When withdrawing from the pool to a public address, the circuit proves everything needed to spend a note, plus public binding:

- **Merkle membership** — the spent note exists in the tree (same as transfer).
- **Commitment re-derivation** — the prover knows the note's full plaintext.
- **Nullifier derivation** — correctly derived from `nsk` (secret key, not public key).
- **Ownership authorization** — full EC spend proof, same as transfer.
- **Public withdrawal binding** — the note's amount and asset type match the public withdrawal parameters. This prevents withdrawing a different amount or token than what the note actually contains.
- **Transaction binding** — locks the proof to the specific anchor, nullifier, withdrawal amount, recipient address, and asset. Notably, the recipient is encoded as 4×u64 limbs (not a single field element) to avoid collisions from field modular reduction of 32-byte public keys.

The chain recomputes the recipient limb encoding from the actual Solana address and rejects mismatches, then executes the SPL token transfer.

### Cross-Circuit Protections

- **Domain separation** — every hash operation uses a unique domain tag (10 distinct tags for commitments, nullifiers, asset IDs, etc.). This prevents an attacker from taking a hash output from one context and reusing it in another.
- **Field element validation** — all inputs must be valid field elements (< BN254 scalar field modulus). Malformed inputs could bypass constraints.
- **Merkle path depth** — paths are fixed at 32 levels. A wrong depth could enable fake membership proofs.

### What the Chain Enforces (Not in ZK)

Some critical checks happen outside the circuits:

| Check | Why | Enforced by |
|-------|-----|-------------|
| **Nullifier uniqueness** | Prevents double-spending the same note | On-chain program (PDA or Light Protocol) |
| **Anchor validity** | Ensures the Merkle root is recent and legitimate | On-chain program (ring buffer of recent roots) |
| **Proof verification** | The ZK proof actually verifies against the correct verification key | On-chain UltraPlonk verifier |
| **Ciphertext-commitment binding** | Decrypted note matches its commitment (griefing prevention) | Recipient client after decryption |

## Architecture

```text
+------------------------------------------------------------------+
|                          Client                                   |
|  +-----------+  +-----------+  +---------------------------+     |
|  | Spending  |  | Viewing   |  | Transaction Builder       |     |
|  | Key       |  | Key       |  | - Build proofs            |     |
|  +-----------+  +-----------+  | - Encrypt notes           |     |
|                                | - Generate witnesses      |     |
|                                +---------------------------+     |
+------------------------------------------------------------------+
                                   |
                                   v
+------------------------------------------------------------------+
|                      Solana Programs                              |
|  +-----------------------------+  +-------------------------+    |
|  |       MASP Program          |  |  UltraPlonk Verifier    |    |
|  |  +-----------------------+  |  |  +-----------------+    |    |
|  |  | Shield                |  |--|  | Verify          |    |    |
|  |  | - Add commitment      |  |  |  | - BN254 syscalls|    |    |
|  |  | - Verify proof (CPI)  |  |  |  | - ~1.2M CUs    |    |    |
|  |  +-----------------------+  |  |  +-----------------+    |    |
|  |  +-----------------------+  |  |                         |    |
|  |  | Transfer              |  |  |                         |    |
|  |  | - Check nullifiers    |  |  |                         |    |
|  |  | - Add commitments     |  |  |                         |    |
|  |  | - Record nullifiers   |  |  |                         |    |
|  |  +-----------------------+  |  |                         |    |
|  |  +-----------------------+  |  |                         |    |
|  |  | Unshield              |  |  |                         |    |
|  |  | - Check nullifier     |  |  |                         |    |
|  |  | - Transfer tokens     |  |  |                         |    |
|  |  +-----------------------+  |  |                         |    |
|  +-----------------------------+  +-------------------------+    |
+------------------------------------------------------------------+
```

## Project Structure

```text
solana-masp/
├── circuits/masp/              # Noir circuits
│   ├── common/                 # Shared library (constants, statements)
│   ├── shield/                 # Deposit circuit
│   ├── transfer/               # Shielded transfer (N→M, max 3×3)
│   └── unshield/               # Withdrawal circuit
├── programs/
│   ├── solana-masp/            # Main MASP on-chain program
│   ├── masp-verifier/          # UltraPlonk verifier program (CPI target)
│   └── mock-commitment-store/  # Helper program for testing
├── masp-protocol/              # Shared protocol types (no_std, used by both client and program)
│   └── src/
│       ├── domain.rs           # Domain separation tags
│       ├── instructions.rs     # ShieldData, TransferData, UnshieldData
│       └── public_inputs.rs    # Public input layouts, MAX_INPUTS/OUTPUTS=3
├── client/                     # Client library
│   ├── src/
│   │   ├── client.rs           # MaspClient (note + key management)
│   │   ├── keys.rs             # Key derivation (Spending, Viewing, Diversified)
│   │   ├── proofs.rs           # Proof generation and verification
│   │   ├── encryption.rs       # ChaCha20-Poly1305 note encryption
│   │   └── backends/           # Pluggable backends (chain, indexer, proof system)
│   └── tests/
│       ├── user_flows.rs       # Main integration tests (8 flows)
│       ├── test_env.rs         # Backend configuration and setup
│       ├── e2e_tests.rs        # Extended E2E tests
│       ├── photon_devnet.rs    # Light Protocol devnet tests
│       └── surfpool_e2e.rs     # Direct Surfpool program tests
├── docs/                       # Protocol specs and design docs
│   ├── protocol-soundness.md   # Normative protocol spec (authoritative)
│   ├── circuit-security-requirements.md
│   ├── implementation-status.md # Security statement tracking (S1-U3)
│   └── ...
├── scripts/
│   ├── build.sh                # Build circuits + program
│   └── deploy.sh               # Deploy to Surfpool
└── tasks.md                    # Implementation tracking
```

## Quick Start

### Prerequisites

#### For Rust tests only

- Rust toolchain (standard `cargo` install)

#### For circuit proof pipeline (Noir + bb)

```bash
# Install Noir (UltraPlonk-compatible)
noirup -v v1.0.0-beta.3

# Install Barretenberg
bbup  # Auto-installs bb 0.82.2

# Verify
nargo --version   # v1.0.0-beta.3
bb --version      # 0.82.2
```

### Run Tests

```bash
# Run the full Rust test suite (client + program unit tests)
cargo test

# Run only the client tests
cd client
cargo test
```

## User Flow Tests

The `user_flows` tests are the primary integration tests. They exercise complete user journeys
(shield, transfer, unshield, recover) and can run against different backend configurations.

### Quick Start

```bash
cd client

# Default: all mocks (fastest, no external dependencies)
cargo test --test user_flows

# Show which backends are selected
MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
```

### Backend Configuration

Tests are configured via environment variables. Each backend dimension can be configured independently:

| Variable | Options | Default | Description |
|----------|---------|---------|-------------|
| `MASP_CHAIN` | `mock`, `surfpool`, `devnet`, `testnet`, `mainnet`, `<url>` | `mock` | Chain backend |
| `MASP_INDEXER` | `mock`, `light` | `mock` | Indexer backend |
| `MASP_ENCRYPTION` | `chacha`, `mock` | `chacha` | Note encryption |
| `MASP_PROOF_SYSTEM` | `mock`, `ultraplonk`, `groth16` | `mock` | Proof system |
| `MASP_PROOF_VERIFY` | `local`, `onchain` | `local` | Where proofs are verified |
| `MASP_PRINT_CONFIG` | `1` | unset | Print backend selection |

### Backend Status

| Backend | Status | Notes |
|---------|--------|-------|
| **Chain: mock** | Working | In-memory, fast, default |
| **Chain: surfpool** | Working | Auto-deploys program; requires Surfpool running |
| **Chain: devnet/testnet/mainnet** | Scaffold | Requires deployed program |
| **Indexer: mock** | Working | In-memory, default |
| **Indexer: light** | Scaffold | Photon RPC client + PDA derivation implemented; CPI integration pending |
| **Encryption: chacha** | Working | ChaCha20-Poly1305, production default |
| **Encryption: mock** | Working | INSECURE - testing only |
| **Proofs: mock** | Working | Real Rust checks, fake proof bytes |
| **Proofs: ultraplonk** | Working | CLI-based (nargo + bb) |
| **Proofs: groth16** | Scaffold | Not yet implemented |

### Example Configurations

#### 1. Default (All Mocks) - Fastest

```bash
cd client
cargo test --test user_flows
```

#### 2. With Surfpool (Local Solana)

Tests auto-deploy the program if `MASP_PROGRAM_ID` is not set:

```bash
# Terminal 1: Start Surfpool
surfpool start

# Terminal 2: Run tests (auto-builds + auto-deploys!)
MASP_CHAIN=surfpool \
MASP_PRINT_CONFIG=1 \
  cargo test -p masp-client --features solana-backend,onchain-mock \
  --test user_flows -- --nocapture --test-threads=1
```

Auto-deploy behavior:

- If `MASP_PROGRAM_ID` is set, uses that program ID (no build/deploy)
- If `.so` is missing or source changed, rebuilds with `cargo build-sbf`
- Deploys via `solana program deploy` and sets `MASP_PROGRAM_ID`
- Uses `--features local-testing,mock-proofs` by default

| Variable | Description |
|----------|-------------|
| `MASP_PROGRAM_ID` | Skip build/deploy, use this program ID |
| `MASP_SKIP_BUILD` | Skip rebuild check (use existing .so) |
| `MASP_PROGRAM_FEATURES` | Override build features |

#### 2b. With Surfpool - Manual Deploy

```bash
# Build once
cargo build-sbf -p solana-masp --features "local-testing,mock-proofs"

# Deploy and run with explicit program ID
solana-keygen new --no-passphrase -o /tmp/masp.json --force
PROGRAM_ID=$(solana program deploy target/deploy/solana_masp.so \
  --url http://127.0.0.1:8899 --program-id /tmp/masp.json \
  | grep "Program Id:" | awk '{print $3}')

MASP_CHAIN=surfpool MASP_PROGRAM_ID=$PROGRAM_ID \
  cargo test -p masp-client --features solana-backend,onchain-mock \
  --test user_flows -- --nocapture --test-threads=1
```

#### 3. With Real UltraPlonk Proofs

```bash
# Requires: nargo v1.0.0-beta.3 + bb 0.82.2
cd circuits/masp/transfer && nargo compile && cd ../../..

cd client
MASP_PROOF_SYSTEM=ultraplonk \
MASP_PRINT_CONFIG=1 \
  cargo test --features ultraplonk-verifier --test user_flows -- --nocapture
```

#### 4. Production-like Stack (Surfpool + Mock Proofs)

The most production-like configuration that works today:

```bash
# Terminal 1: Start Surfpool
surfpool start

# Terminal 2: Run with real Solana chain, real encryption, mock proofs
MASP_CHAIN=surfpool \
MASP_PRINT_CONFIG=1 \
  cargo test -p masp-client --features solana-backend,onchain-mock \
  --test user_flows -- --nocapture --test-threads=1
```

Notes:

- Uses `--test-threads=1` to avoid parallel RPC issues
- All 8 user flow tests pass in ~2-3 seconds
- `onchain-mock` feature enables the Keccak256-based mock prover compatible with on-chain mock verifier

### What the Tests Cover

| Test | Description |
|------|-------------|
| `flow_shield_deposit_tokens` | Deposit tokens into shielded pool |
| `flow_transfer_send_to_recipient` | Send to another user |
| `flow_unshield_withdraw` | Withdraw to public address |
| `flow_oob_first_payment` | Out-of-band payment discovery |
| `flow_multiasset_portfolio` | Multiple token types |
| `flow_recovery_from_seed` | Recover wallet from seed |
| `flow_recovery_then_spend` | Spend after recovery |
| `flow_multidevice_sync` | Multi-device sync via recovery |

### Real UltraPlonk Proving (CLI-based)

This repo supports real UltraPlonk proving by shelling out to `nargo` + `bb` CLI tools:

- Uses the installed `nargo`/`bb` toolchain (v1.0.0-beta.3 + 0.82.2)
- Creates timestamped directories for proof artifacts: `client/target/masp_proofs/<circuit>-<timestamp>/`
- Auto-cleans directories on success (set `MASP_KEEP_PROOF_ARTIFACTS=1` to keep)

| Variable | Default | Description |
|----------|---------|-------------|
| `MASP_BB_PATH` | `~/.bb/bb` if exists, else `bb` in PATH | Path to `bb` binary |
| `MASP_NARGO_PATH` | `nargo` in PATH | Path to `nargo` binary |
| `MASP_KEEP_PROOF_ARTIFACTS` | unset | Set to `1` to keep proof artifacts |

### Build and Deploy

```bash
# Build circuits + program
./scripts/build.sh

# Or build program only
cargo build-sbf -p solana-masp --features "local-testing,mock-proofs"

# Deploy to Surfpool
surfpool start
solana program deploy target/deploy/solana_masp.so --url http://127.0.0.1:8899
```

## References

- [Orchard Protocol](https://zips.z.cash/protocol/protocol.pdf) (Section 5)
- [Sapling Protocol](https://zips.z.cash/protocol/protocol.pdf) (Section 4)
- [Namada MASP](https://github.com/anoma/masp)
- [Tachyon](https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/)
- [ZIP-32: Key Derivation](https://zips.z.cash/zip-0032)

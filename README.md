# Solana MASP (Multi-Asset Shielded Pool)

A spike exploring building a MASP system on Solana, inspired by Zcash's Orchard/Sapling protocols and Namada's MASP.

## Status (Current)

- **Milestone 0 complete**: off-chain model + client flows + mocks + encryption + sync tests.
- **Circuits are production-shaped** with most security statements implemented. See [`docs/implementation-status.md`](docs/implementation-status.md) for a detailed tracking table.
- **Proofs use MockSpendProver** by default (real checks in Rust). UltraPlonk mode is available via `MASP_PROOF_SYSTEM=ultraplonk`.

## Overview

This project implements shielded transfers on Solana using:

- **Noir** circuits compiled with **UltraPlonk**
- **Solana BN254 syscalls** for efficient on-chain verification
- **Orchard-inspired** note and nullifier schemes

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Client                                   │
│  ┌───────────┐  ┌───────────┐  ┌───────────────────────────┐   │
│  │ Spending  │  │ Viewing   │  │ Transaction Builder       │   │
│  │ Key       │  │ Key       │  │ - Build proofs            │   │
│  └───────────┘  └───────────┘  │ - Encrypt notes           │   │
│                                 │ - Generate witnesses      │   │
│                                 └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Solana Programs                             │
│  ┌─────────────────────────────┐  ┌─────────────────────────┐  │
│  │       MASP Program          │  │  UltraPlonk Verifier    │  │
│  │  ┌───────────────────────┐  │  │  ┌─────────────────┐    │  │
│  │  │ Shield                │  │──│  │ Verify          │    │  │
│  │  │ - Add commitment      │  │  │  │ - BN254 syscalls│    │  │
│  │  │ - Verify proof (CPI)  │  │  │  │ - ~500K-1M CUs  │    │  │
│  │  └───────────────────────┘  │  │  └─────────────────┘    │  │
│  │  ┌───────────────────────┐  │  │                         │  │
│  │  │ Transfer              │  │  │                         │  │
│  │  │ - Check nullifiers    │  │  │                         │  │
│  │  │ - Add commitments     │  │  │                         │  │
│  │  │ - Record nullifiers   │  │  │                         │  │
│  │  └───────────────────────┘  │  │                         │  │
│  │  ┌───────────────────────┐  │  │                         │  │
│  │  │ Unshield              │  │  │                         │  │
│  │  │ - Check nullifier     │  │  │                         │  │
│  │  │ - Transfer tokens     │  │  │                         │  │
│  │  └───────────────────────┘  │  │                         │  │
│  └─────────────────────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```text
solana-masp/
├── circuits/masp/          # Noir circuits (multiple packages)
│   ├── shield/             # masp_shield (Stage 0)
│   ├── transfer/           # masp_transfer (Stage 0)
│   └── unshield/           # masp_unshield (Stage 0)
├── programs/solana-masp/   # Solana program
│   ├── src/lib.rs
│   └── Cargo.toml
├── client/                 # Client library
│   ├── src/lib.rs
│   └── Cargo.toml
├── scripts/
│   ├── build.sh            # Build circuits + program (requires noir/bb)
│   └── deploy.sh           # Deploy to Surfpool
├── tasks.md                # Implementation tracking
└── README.md
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

### Run Tests (Recommended)

```bash
# Run the full Rust test suite (client + program unit tests)
cargo test

# Run only the client tests
cd client
cargo test
```

## User Flow Tests

The `user_flows` tests are the primary integration tests. They exercise complete user journeys
(shield → transfer → unshield → recover) and can run against different backend configurations.

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
| **Chain: mock** | ✅ Working | In-memory, fast, default |
| **Chain: surfpool** | 🚧 Scaffold | Requires Surfpool running + `MASP_PROGRAM_ID` |
| **Chain: devnet/testnet/mainnet** | 🚧 Scaffold | Requires deployed program |
| **Indexer: mock** | ✅ Working | In-memory, default |
| **Indexer: light** | 🚧 Scaffold | Uses mock internally (Helius/Light integration pending) |
| **Encryption: chacha** | ✅ Working | ChaCha20-Poly1305, production default |
| **Encryption: mock** | ✅ Working | ⚠️ INSECURE - testing only |
| **Proofs: mock** | ✅ Working | Real Rust checks, fake proof bytes |
| **Proofs: ultraplonk** | 🚧 Scaffold | CLI-based (nargo + bb) |
| **Proofs: groth16** | 🚧 Scaffold | Not yet implemented |

### Example Configurations

#### 1. Default (All Mocks) - Fastest

```bash
cd client
cargo test --test user_flows
```

#### 2. With Surfpool (Local Solana)

```bash
# Terminal 1: Start Surfpool
surfpool start

# Terminal 2: Deploy program and run tests
cd programs/solana-masp
cargo build-sbf --features "local-testing,mock-proofs"
solana program deploy target/deploy/solana_masp.so --url http://127.0.0.1:8899
# Note the program ID

# Terminal 2: Run tests
cd ../client
MASP_CHAIN=surfpool \
MASP_PROGRAM_ID=<program_id> \
MASP_PRINT_CONFIG=1 \
  cargo test --features solana-backend --test user_flows -- --nocapture
```

#### 3. With Light Protocol Indexer (Scaffold)

```bash
cd client
MASP_INDEXER=light \
MASP_PRINT_CONFIG=1 \
  cargo test --test user_flows -- --nocapture
```

Note: Currently uses mock store internally. Real Helius/Light integration is pending.

#### 4. With Real UltraPlonk Proofs

```bash
# Requires: nargo v1.0.0-beta.3 + bb 0.82.2
cd circuits/masp/transfer && nargo compile && cd ../../..

cd client
MASP_PROOF_SYSTEM=ultraplonk \
MASP_PRINT_CONFIG=1 \
  cargo test --features ultraplonk-verifier --test user_flows -- --nocapture
```

#### 5. Mock Encryption (Fast Tests)

```bash
cd client
MASP_ENCRYPTION=mock \
  cargo test --test user_flows
```

⚠️ **Warning:** Mock encryption is INSECURE. Only use for testing.

#### 6. Full Production-like Stack (Future)

```bash
# Not yet implemented - this is the target configuration
cd client
MASP_CHAIN=devnet \
MASP_INDEXER=light \
MASP_PROOF_SYSTEM=ultraplonk \
MASP_PROOF_VERIFY=onchain \
MASP_PROGRAM_ID=<deployed_program> \
HELIUS_API_KEY=<key> \
  cargo test --features solana-backend,ultraplonk-verifier --test user_flows -- --nocapture
```

### Indexer Modes

When using `SolanaChain`, the indexer can operate in two modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| **LocalSync** | Chain shares `MockStore` with indexer | Tests, local dev |
| **External** | Indexer observes ledger independently | Production |

In tests, LocalSync mode is used automatically - the chain and indexer share the same
`Arc<MockStore>`, so updates are instant. In production, an external indexer (Helius/Light)
would poll the ledger asynchronously.

### Test Files

```text
client/tests/
├── user_flows.rs       # Main integration tests (8 flows)
├── test_env.rs         # Backend configuration and setup
└── surfpool_e2e.rs     # Direct Surfpool program tests (requires running Surfpool)
```

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

### Circuit Proof Pipeline Smoke Test (UltraPlonk)

There is an **ignored** test that runs the real toolchain loop against our Stage-0 MASP transfer circuit:

```bash
cd client
cargo test --features ultraplonk-tools --test masp_ultraplonk_pipeline -- --ignored --nocapture
```

This requires `nargo` + `bb` on your PATH.

### Real UltraPlonk Proving (CLI-based)

This repo supports real UltraPlonk proving by shelling out to `nargo` + `bb` CLI tools:

- Uses the installed `nargo`/`bb` toolchain (v1.0.0-beta.3 + 0.82.2)
- Creates timestamped directories for proof artifacts: `client/target/masp_proofs/<circuit>-<timestamp>/`
- Auto-cleans directories on success (set `MASP_KEEP_PROOF_ARTIFACTS=1` to keep)

**Environment variables for CLI tools:**

| Variable | Default | Description |
|----------|---------|-------------|
| `MASP_BB_PATH` | `~/.bb/bb` if exists, else `bb` in PATH | Path to `bb` binary |
| `MASP_NARGO_PATH` | `nargo` in PATH | Path to `nargo` binary |
| `MASP_KEEP_PROOF_ARTIFACTS` | unset | Set to `1` to keep proof artifacts |

#### 1) Compile the circuit artifact (Noir)

```bash
cd circuits/masp/transfer
nargo compile
```

This produces: `circuits/masp/transfer/target/masp_transfer.json`

#### 2) Run the real-proof E2E test

```bash
cd client
MASP_PROOF_SYSTEM=ultraplonk \
  cargo test --features ultraplonk-verifier --test real_ultraplonk_transfer_e2e -- --ignored --nocapture
```

Notes:

- The test is `#[ignore]` because it requires `nargo`/`bb` and the compiled circuit.
- This targets the Stage-0 `transfer` circuit (single output commitment).
- Proof artifacts are auto-cleaned on success. Set `MASP_KEEP_PROOF_ARTIFACTS=1` to keep them for debugging.

#### Cleaning old proof artifacts

```bash
# Remove all proof artifact directories
rm -rf client/target/masp_proofs/
```

### Build (Circuits + Program)

```bash
# Requires: nargo + bb
./scripts/build.sh

# Program build (Solana)
cd programs/solana-masp
cargo build-sbf
```

### Deploy to Surfpool

```bash
# Start Surfpool
surfpool start

# Build program with mock proofs for testing
cd programs/solana-masp
cargo build-sbf --features "local-testing,mock-proofs"

# Deploy
solana program deploy target/deploy/solana_masp.so --url http://127.0.0.1:8899
```

## Operations

### Shield

Deposit transparent SOL/tokens into the shielded pool:

1. Client generates a note with recipient address
2. Client creates commitment and proof
3. Program verifies proof and adds commitment to tree
4. SOL/tokens transferred to pool

### Transfer

Move value between shielded notes:

1. Client selects notes to spend
2. Client creates new notes for recipients
3. Client proves: ownership, Merkle membership, value balance
4. Program verifies, records nullifiers, adds new commitments

### Unshield

Withdraw from shielded pool to transparent address:

1. Client selects note to spend
2. Client creates proof of ownership
3. Program verifies, records nullifier, transfers to recipient

## References

- [Orchard Protocol](https://zips.z.cash/protocol/protocol.pdf) (Section 5)
- [Sapling Protocol](https://zips.z.cash/protocol/protocol.pdf) (Section 4)
- [Namada MASP](https://github.com/anoma/masp)
- [Tachyon](https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/)
- [ZIP-32: Key Derivation](https://zips.z.cash/zip-0032)

## Status

Currently in **scaffolding phase**. See [tasks.md](./tasks.md) for progress.

# Solana MASP (Multi-Asset Shielded Pool)

A spike exploring building a MASP system on Solana, inspired by Zcash's Orchard/Sapling protocols and Namada's MASP.

## Status (Current)

- **Milestone 0 complete**: off-chain model + client flows + mocks + encryption + sync tests.
- **Circuits are Stage 0 scaffolds**: production-shaped inputs, minimal/no-op constraints. The focus is validating the toolchain loop (compile → witness → prove → verify) before implementing each security statement.
- **Proofs in client flows are still mocked** by default. We’re now starting to plug in real UltraPlonk proving/verifying.

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
│   ├── deploy.sh           # Deploy to Surfpool
│   └── test_e2e.mjs        # JS E2E (scaffolding; Rust tests are the main suite today)
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

#### Running with different backends (tests)

Tests can be configured via env vars (see `client/tests/test_env.rs`):

```bash
cd client
MASP_PRINT_CONFIG=1 cargo test --test user_flows -- --nocapture
```

### Circuit Proof Pipeline Smoke Test (UltraPlonk)

There is an **ignored** test that runs the real toolchain loop against our Stage-0 MASP transfer circuit:

```bash
cd client
cargo test --test masp_ultraplonk_pipeline -- --ignored --nocapture
```

This requires `nargo` + `bb` on your PATH.

### Build (Circuits + Program)

```bash
# Requires: nargo + bb
./scripts/build.sh

# Program build (Solana)
cd programs/solana-masp
cargo build-sbf
```

### Test on Surfpool (Program Scaffolding)

The JS script is still scaffolding and not the main test suite. The primary tests today are Rust integration/user-flow tests in `client/tests/`.

```bash
# Start Surfpool (via MCP)
# Use: start_surfnet

# Deploy
./scripts/deploy.sh

# Run E2E tests
node scripts/test_e2e.mjs
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

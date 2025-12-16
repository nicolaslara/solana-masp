# Solana MASP (Multi-Asset Shielded Pool)

A spike exploring building a MASP system on Solana, inspired by Zcash's Orchard/Sapling protocols and Namada's MASP.

## Overview

This project implements shielded transfers on Solana using:

- **Noir** circuits compiled with **UltraPlonk**
- **Solana BN254 syscalls** for efficient on-chain verification
- **Orchard-inspired** note and nullifier schemes

## Architecture

```
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

```
solana-masp/
├── circuits/masp/          # Noir circuits
│   ├── src/main.nr         # Shield/Transfer/Unshield circuits
│   ├── Nargo.toml
│   └── Prover.toml
├── programs/solana-masp/   # Solana program
│   ├── src/lib.rs
│   └── Cargo.toml
├── client/                 # Client library
│   ├── src/lib.rs
│   └── Cargo.toml
├── scripts/
│   ├── build.sh            # Build circuit + program
│   ├── deploy.sh           # Deploy to Surfpool
│   └── test_e2e.mjs        # E2E tests
├── tasks.md                # Implementation tracking
└── README.md
```

## Quick Start

### Prerequisites

```bash
# Install Noir (UltraPlonk-compatible)
noirup -v v1.0.0-beta.3

# Install Barretenberg
bbup  # Auto-installs bb 0.82.2

# Verify
nargo --version   # v1.0.0-beta.3
bb --version      # 0.82.2
```

### Build

```bash
# Build everything
./scripts/build.sh

# Or step by step:
cd circuits/masp
nargo compile
bb OLD_API write_vk -b target/circuit.json -o vk.bin

cd ../../programs/solana-masp
cargo build-sbf
```

### Test on Surfpool

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

#!/bin/bash
# Deploy MASP program to Surfpool
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"

echo "=== Deploying MASP Program ==="
echo "RPC: $RPC_URL"

solana program deploy \
    "$PROJECT_DIR/programs/solana-masp/target/deploy/solana_masp.so" \
    --url "$RPC_URL"

echo ""
echo "=== Deploy Complete ==="


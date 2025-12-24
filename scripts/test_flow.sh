#!/bin/bash
# Test a single flow with a fresh program deployment
#
# Usage: ./scripts/test_flow.sh <flow_name>
# Example: ./scripts/test_flow.sh flow_shield_deposit_tokens

set -e

FLOW_NAME="${1:-flow_shield_deposit_tokens}"

echo "🔧 Deploying fresh program for test: $FLOW_NAME"

# Generate new keypair and deploy
solana-keygen new --no-passphrase -o /tmp/masp_test.json --force 2>/dev/null
PROGRAM_ID=$(solana program deploy target/deploy/solana_masp.so \
  --url http://127.0.0.1:8899 \
  --program-id /tmp/masp_test.json 2>&1 | grep "Program Id:" | awk '{print $3}')

if [ -z "$PROGRAM_ID" ]; then
  echo "❌ Deploy failed"
  exit 1
fi

echo "✅ Deployed: $PROGRAM_ID"
echo ""
echo "🧪 Running test: $FLOW_NAME"
echo "=================================================="

MASP_CHAIN=surfpool \
MASP_PROGRAM_ID="$PROGRAM_ID" \
cargo test -p masp-client --features solana-backend,onchain-mock --test user_flows -- --nocapture "$FLOW_NAME"


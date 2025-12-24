#!/usr/bin/env bash
# Self-contained devnet airdrop script
# Does NOT change your global Solana CLI config

set -e

DEVNET_KEYPAIR="$HOME/.config/solana/devnet-keypair.json"
DEVNET_URL="https://api.devnet.solana.com"
AMOUNT="${1:-2}"  # Default 2 SOL, or pass as argument

if [ ! -f "$DEVNET_KEYPAIR" ]; then
    echo "Error: Devnet keypair not found at $DEVNET_KEYPAIR"
    echo "Generate one with: solana-keygen new --outfile $DEVNET_KEYPAIR"
    exit 1
fi

PUBKEY=$(solana-keygen pubkey "$DEVNET_KEYPAIR")

echo "=== Devnet Airdrop ==="
echo "Keypair: $DEVNET_KEYPAIR"
echo "Public Key: $PUBKEY"
echo "Amount: $AMOUNT SOL"
echo ""

echo "Requesting airdrop..."
solana airdrop "$AMOUNT" "$PUBKEY" --url "$DEVNET_URL"

echo ""
echo "Current balance:"
solana balance "$PUBKEY" --url "$DEVNET_URL"


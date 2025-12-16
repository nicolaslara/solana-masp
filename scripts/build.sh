#!/bin/bash
# Build MASP circuit and program
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Building MASP Circuit ==="
cd "$PROJECT_DIR/circuits/masp"
nargo compile
echo "Circuit compiled."

echo ""
echo "=== Generating VK ==="
bb OLD_API write_vk -b target/masp.json -o vk.bin
echo "VK generated."

echo ""
echo "=== Building Solana Program ==="
cd "$PROJECT_DIR/programs/solana-masp"
cargo build-sbf
echo "Program built."

echo ""
echo "=== Build Complete ==="


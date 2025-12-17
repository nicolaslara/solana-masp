#!/usr/bin/env bash
set -euo pipefail

# Generate a local `.srs` (bincode) sized to the MASP transfer circuit.
#
# This is required for programmatic (no CLI) proving via `noir-rs-prover`.
#
# What it does:
# - compiles the transfer circuit (nargo compile)
# - computes required SRS points from the circuit bytecode
# - downloads only the required prefix of transcript00.dat
# - generates `circuits/masp/transfer/target/masp_transfer.srs`
#
# Note: Uses a standalone tool (tools/srs-generator) outside the main workspace
# to avoid base64ct version conflict between noir-rs and solana-program.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CIRCUIT_DIR="$REPO_ROOT/circuits/masp/transfer"
CIRCUIT_JSON="$CIRCUIT_DIR/target/masp_transfer.json"
OUT_SRS="$CIRCUIT_DIR/target/masp_transfer.srs"
SRS_TOOL_DIR="$REPO_ROOT/tools/srs-generator"

TRANSCRIPT_URL="https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat"

echo "==> Compiling transfer circuit (nargo compile)"
(cd "$CIRCUIT_DIR" && nargo compile)

echo "==> Building SRS generator tool (standalone, outside workspace)"
(cd "$SRS_TOOL_DIR" && cargo build --release --quiet)

echo "==> Computing required SRS points from circuit bytecode"
POINTS="$("$SRS_TOOL_DIR/target/release/generate_local_srs" --circuit "$CIRCUIT_JSON" --print-points)"
echo "    points = $POINTS"

# Bytes needed for transcript prefix: [0..(28 + points*64 - 1)]
END_BYTE=$((28 + POINTS * 64 - 1))
TMP_DAT="$(mktemp -t transcript00_prefix.XXXXXX.dat)"
trap 'rm -f "$TMP_DAT"' EXIT

echo "==> Downloading transcript00.dat prefix (0-$END_BYTE) to $TMP_DAT"
echo "    url = $TRANSCRIPT_URL"
curl -L --fail --silent --show-error -H "Range: bytes=0-$END_BYTE" "$TRANSCRIPT_URL" -o "$TMP_DAT"

echo "==> Generating local .srs (bincode) into $OUT_SRS"
"$SRS_TOOL_DIR/target/release/generate_local_srs" \
  --circuit "$CIRCUIT_JSON" \
  --dat "$TMP_DAT" \
  --out "$OUT_SRS"

echo "==> Done. SRS size:"
ls -lh "$OUT_SRS"




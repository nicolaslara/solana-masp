#!/bin/bash
# Benchmark MASP proof generation times

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CIRCUITS_DIR="$PROJECT_ROOT/circuits/masp"

echo "=========================================="
echo "MASP Proof Generation Benchmark"
echo "=========================================="
echo ""
echo "Toolchain:"
nargo --version
bb --version
echo ""

benchmark_circuit() {
    local circuit_name=$1
    local circuit_dir="$CIRCUITS_DIR/$circuit_name"
    
    echo "----------------------------------------"
    echo "Circuit: $circuit_name"
    echo "----------------------------------------"
    
    cd "$circuit_dir"
    
    # Clean previous artifacts
    rm -rf target/*.bin target/*.gz 2>/dev/null || true
    
    # Compile (warm cache)
    echo "  Compiling..."
    local compile_start=$(python3 -c 'import time; print(time.time())')
    nargo compile 2>&1 | head -3
    local compile_end=$(python3 -c 'import time; print(time.time())')
    local compile_time=$(python3 -c "print(f'{$compile_end - $compile_start:.2f}')")
    echo "  Compile time: ${compile_time}s"
    
    # Execute (witness generation)
    echo "  Generating witness..."
    local execute_start=$(python3 -c 'import time; print(time.time())')
    nargo execute 2>&1 | head -3
    local execute_end=$(python3 -c 'import time; print(time.time())')
    local execute_time=$(python3 -c "print(f'{$execute_end - $execute_start:.2f}')")
    echo "  Witness generation time: ${execute_time}s"
    
    local artifact="target/masp_${circuit_name}.json"
    local witness="target/masp_${circuit_name}.gz"
    
    # Generate VK
    echo "  Generating VK..."
    local vk_start=$(python3 -c 'import time; print(time.time())')
    bb OLD_API write_vk -b "$artifact" -o target/vk.bin 2>&1 | head -3
    local vk_end=$(python3 -c 'import time; print(time.time())')
    local vk_time=$(python3 -c "print(f'{$vk_end - $vk_start:.2f}')")
    echo "  VK generation time: ${vk_time}s"
    
    # Generate proof (the main metric)
    echo "  Generating proof..."
    local prove_start=$(python3 -c 'import time; print(time.time())')
    bb OLD_API prove -b "$artifact" -w "$witness" -o target/proof.bin 2>&1 | head -3
    local prove_end=$(python3 -c 'import time; print(time.time())')
    local prove_time=$(python3 -c "print(f'{$prove_end - $prove_start:.2f}')")
    echo "  PROOF GENERATION TIME: ${prove_time}s ⭐"
    
    # Verify proof locally
    echo "  Verifying proof..."
    local verify_start=$(python3 -c 'import time; print(time.time())')
    bb OLD_API verify -p target/proof.bin -k target/vk.bin 2>&1 | head -3
    local verify_end=$(python3 -c 'import time; print(time.time())')
    local verify_time=$(python3 -c "print(f'{$verify_end - $verify_start:.2f}')")
    echo "  Verification time: ${verify_time}s"
    
    # File sizes
    local vk_size=$(stat -f%z target/vk.bin 2>/dev/null || stat -c%s target/vk.bin 2>/dev/null || echo "?")
    local proof_size=$(stat -f%z target/proof.bin 2>/dev/null || stat -c%s target/proof.bin 2>/dev/null || echo "?")
    echo ""
    echo "  VK size: ${vk_size} bytes"
    echo "  Proof size: ${proof_size} bytes"
    echo ""
    
    cd "$PROJECT_ROOT"
}

# Run benchmarks
benchmark_circuit "shield"
benchmark_circuit "transfer"
benchmark_circuit "unshield"

echo "=========================================="
echo "Benchmark Complete"
echo "=========================================="


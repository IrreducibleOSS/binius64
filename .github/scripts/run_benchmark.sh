#!/bin/bash
# Copyright 2025 Irreducible Inc.
# Helper script to run both Criterion and Perfetto benchmarks

set -euo pipefail

# Arguments
BENCH=$1
ARGS=${2:-""}  # Optional benchmark arguments

echo "=== Running benchmark: ${BENCH} ==="
echo "Arguments: ${ARGS}"

# Print relevant environment variables for this benchmark
echo "Environment variables:"
env | grep -E "^(HASH_MAX_BYTES|LOG_INV_RATE|N_SIGNATURES|MESSAGE_MAX_BYTES|XMSS_TREE_HEIGHT|WOTS_SPEC|RUSTFLAGS)=" | sort || true

# Multi-threaded Criterion
echo "::group::📊 Criterion - ${BENCH} (multi-threaded)"
# Clean criterion directory before run
rm -rf target/criterion
cargo bench -p binius-examples --bench ${BENCH}
# Move all results to benchmark-specific directory
mkdir -p criterion_results/${BENCH}_mt
mv target/criterion/* criterion_results/${BENCH}_mt/
echo "::endgroup::"

# Single-threaded Criterion
echo "::group::📊 Criterion - ${BENCH} (single-threaded)"
# Clean criterion directory before run
rm -rf target/criterion
cargo bench -p binius-examples --bench ${BENCH} --no-default-features
# Move all results to benchmark-specific directory
mkdir -p criterion_results/${BENCH}_st
mv target/criterion/* criterion_results/${BENCH}_st/
echo "::endgroup::"

# Multi-threaded Perfetto
echo "::group::🔍 Perfetto - ${BENCH} (multi-threaded)"
if [ -n "${ARGS}" ]; then
    cargo run --release --features perfetto --example ${BENCH} -- ${ARGS}
else
    cargo run --release --features perfetto --example ${BENCH}
fi
echo "::endgroup::"

# Single-threaded Perfetto
echo "::group::🔍 Perfetto - ${BENCH} (single-threaded)"
if [ -n "${ARGS}" ]; then
    cargo run --release --features perfetto --example ${BENCH} --no-default-features -- ${ARGS}
else
    cargo run --release --features perfetto --example ${BENCH} --no-default-features
fi
echo "::endgroup::"

echo "✅ Completed benchmark: ${BENCH}"
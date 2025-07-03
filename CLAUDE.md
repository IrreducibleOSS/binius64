# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Building
```bash
cargo build                    # Debug build
cargo build --release          # Release build (with optimizations)
```

### Testing
```bash
cargo test --release           # Run all tests with optimizations (recommended)
cargo test                     # Run tests without optimizations (faster compilation)
cargo test <testname>          # Run specific test
cargo test -p <crate-name>     # Test specific crate only
cargo test --doc               # Run doc tests
```

### Linting and Formatting
```bash
cargo fmt -- --check           # Check formatting
cargo fmt                      # Fix formatting
cargo clippy --all --all-features --tests --benches --examples -- -D warnings  # Run clippy
typos                          # Check for typos
```

### Benchmarks
```bash
cargo bench                    # Run all benchmarks
cargo bench --bench <name>     # Run specific benchmark
```

### Pre-commit Hooks
```bash
pre-commit install             # Install git hooks
pre-commit run --all-files     # Run all checks manually
```

### Performance Optimization
For optimal performance, export this environment variable before building:
```bash
export RUSTFLAGS="-C target-cpu=native"
```

Check for GFNI instruction support (Intel processors):
```bash
rustc --print cfg -C target-cpu=native | grep gfni
```

## Architecture Overview

Monbijou is a zero-knowledge proof system that proves an input vector satisfies a constraint system without revealing private inputs.

## Protocol Overview

This codebase implements **Binius64**, a simplified SNARK protocol that leverages binary field arithmetic to efficiently prove computations on 64-bit words. The protocol is formally specified in `../writeups/binius64/main.tex`.

Key aspects of Binius64:
- Designed specifically for 64-bit word operations (not bit-level)
- Uses a customizable constraint system inspired by SuperSpartan (not AIR tables like original Binius)
- Achieves 64-fold reduction in constraint complexity compared to bit-level approaches
- Native encoding of bitwise operations through **shifted value indices**
- Targets modern 64-bit CPUs with SIMD instructions (especially ARM64 NEON)

### Core Crates

- **`binius-field`**: Binary field arithmetic with platform-specific optimizations (x86_64, aarch64)
- **`binius-frontend`**: Circuit construction API
  - `circuits/`: Pre-built circuits (SHA256, base64, equality)
  - `compiler/`: Constraint system generation
- **`binius-prover`**: Proof generation
- **`binius-verifier`**: Proof verification
- **`binius-transcript`**: Fiat-Shamir non-interactive proofs
- **`binius-utils`**: Common utilities
- **`binius-maybe-rayon`**: Optional parallelization

### Constraint System

Binius64 uses an R1CS-like system with two constraint types over 64-bit words:

1. **AND constraints**: `A & B ^ C = 0`
2. **MUL constraints**: `A * B = (HI << 64) | LO`

Where A, B, C are operands (XOR combinations of shifted input values).

#### Shifted Value Indices

The key innovation is **shifted value indices** - a tuple `(value_id, shift_op, shift_amount)` where:
- `value_id`: index of a 64-bit word in the witness
- `shift_op`: one of `sll` (logical left), `srl` (logical right), `sra` (arithmetic right)
- `shift_amount`: 0-63 bits

This allows constraints to directly express shifted operands without separate shift constraints. For example:
- `v0 XOR (v1 >> 5)` represents value 0 XORed with value 1 shifted right by 5
- Shifts and XORs within constraints are "free" (no additional gates)

This design maps naturally to CPU instructions and achieves massive efficiency gains over bit-level constraint systems.

### Cost Model
- AND constraint: baseline cost (1x)
- MUL constraint: ~200x more expensive
- Committing one 64-bit word: ~0.2x

### Circuit Design Guidelines

When implementing circuits:
1. Prefer AND constraints over MUL when possible
2. XORs and shifts are free within constraints
3. Stand-alone XOR requires one AND constraint
4. Test edge cases (all zeros, all ones)
5. Variable-length inputs should test multiple sizes

See AGENTS.md for detailed circuit design patterns and the formal grammar.

## Key Differences from Original Binius

Binius64 represents a major simplification and redesign compared to the original Binius framework:

1. **Constraint System**: Uses a customizable constraint system (like SuperSpartan) instead of AIR tables
2. **Word-Level Focus**: Operates on 64-bit words natively, not individual bits or multi-field arithmetization
3. **Shifted Value Indices**: Unifies value references with shift operations, eliminating separate shift constraints
4. **Simplified Architecture**: No complex multi-field operations; focuses on binary field arithmetic
5. **CPU Optimization**: Designed specifically for modern 64-bit CPUs with SIMD support

This results in:
- 64x reduction in constraint complexity vs bit-level approaches
- Direct mapping to CPU instructions
- Simpler implementation and analysis
- Better performance on commodity hardware

## Mathematical Foundation

The Binius64 protocol is formally specified in `../writeups/binius64/main.tex`. Key mathematical concepts:

### Binary Tower Fields
- Uses tower fields $T_i \cong \mathbb{F}_{2^{2^i}}$ for efficient binary field arithmetic
- Witness encoded as multilinear polynomial over $T_0$ (bits)
- Verifier samples challenges from larger tower field (typically $T_7$)

### Polynomial Interactive Oracle Protocol (PIOP)
The protocol uses a 7-phase PIOP that reduces all constraint checks to a single witness evaluation:
1. Oracle commitment (witness polynomial)
2. Multiplication constraint reduction (GKR protocol)
3. AND constraint reduction
4. Non-linear constraint verification (batched multilinear extension)
5. Shift reduction (sumcheck protocol)
6. Public input verification
7. Single oracle query

### Active Research Areas
- **SIMD Field Operations**: Optimizing binary field arithmetic for CPU SIMD instructions
- **Zero-Knowledge Construction**: Adapting techniques from Libra protocol while preserving word-level efficiency

## Testing Strategy

### Running Single Tests
```bash
# Run tests for specific crate
cargo test -p binius-field

# Run specific test by name
cargo test test_name

# Run tests with optimizations for performance testing
cargo test --release
```

## Development Conventions

### Toolchain Requirements
- Uses Rust nightly (see rust-toolchain.toml for specific version)
- All operations are 64-bit word-based (fundamental to Binius64 design)
- Heavy performance optimization with SIMD support
- Pre-commit hooks run rustfmt and clippy automatically
- Implementation follows the formal Binius64 specification in `../writeups/binius64/main.tex`

### Naming Conventions
- Prefers descriptive names over abbreviations
- Generic type parameters: `F` (Field), `P` (PackedField), `U` (UnderlierType), `M` (MultilinearPoly)
- Use namespacing rather than prefixing (e.g., `module::function` not `module_function`)

### Error Handling
- Never use `unwrap()` in library code - use `expect()` with explanation or propagate errors
- Use `Result` types for fallible operations

### Code Style
- Extensive clippy lints are enforced
- Use `cargo fmt` for formatting
- Pre-commit hooks run rustfmt automatically

### Commenting Guidelines
- Prefer descriptive function and variable names over obvious inline comments
- Use inline comments for additional context that cannot be easily inferred from the code
- Focus comments on explaining "why" rather than "what"
- Avoid comments that simply restate what the code obviously does

Good examples:
```rust
// Fold coordinates in reverse order since first coordinate is highest-order variable
for &coord in coords.iter().rev() {

// Use extrapolation formula: x0 + (x1 - x0) * z for single multiplication
let folded = lo_val + diff * packed_coord;
```

Poor examples:
```rust
// Iterate over coordinates
for &coord in coords.iter() {

// Compute the result
let result = binius_field::util::inner_product_par(evals.as_ref(), eq_tensor.as_ref());
```

## Architecture-Specific Optimizations

The codebase includes significant architecture-specific optimizations:
- **x86_64**: GFNI, PCLMUL, AVX2/AVX-512 SIMD instructions
- **aarch64**: NEON SIMD instructions  
- **Portable**: Fallback implementations for all architectures

When adding new optimized code paths, follow the existing pattern in `crates/field/src/arch/` with separate modules for each architecture and feature detection.

### Word-Level Parallelism
The Binius64 design achieves efficiency through word-level parallelism:
- Constraints operate on 64-bit words, not individual bits
- Shifted value indices allow direct expression of bitwise operations
- Maps naturally to CPU instructions for practical performance
- Critical for achieving the theoretical 64x reduction in constraint complexity
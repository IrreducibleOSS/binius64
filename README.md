# Binius64

Binius64 is a Rust library implementing a simplified SNARK protocol that leverages binary field arithmetic to efficiently prove computations on 64-bit words. Unlike the original Binius framework, which uses AIR tables and multi-field arithmetization, Binius64 adopts a customizable constraint system inspired by SuperSpartan. Our key innovation is a constraint system that natively encodes bitwise operations on 64-bit words through *shifted value indices*, which combine value references with shift operations. This design achieves a 64-fold reduction in constraint complexity compared to bit-level approaches while maintaining the efficiency advantages of binary field arithmetic. The protocol targets modern 64-bit CPUs with SIMD instructions, making it practical for real-world applications requiring zero-knowledge proofs.

## Usage

At this stage, the primary interfaces are the unit tests and benchmarks. The benchmarks use the [criterion](https://docs.rs/criterion/0.3.4/criterion/) library.

To run the benchmarks, use the command `cargo bench`. To run the unit tests, use the command `cargo test --release`.

Binius64 implements optimizations for certain target architectures. To enable these, export the environment variable

```bash
export RUSTFLAGS="-C target-cpu=native"
```

Binius64 has notable optimizations on Intel processors featuring the [Galois Field New Instructions](https://networkbuilders.intel.com/solutionslibrary/galois-field-new-instructions-gfni-technology-guide) (GFNI) instruction set extension. To determine if your processor supports this feature, run

```bash
rustc --print cfg -C target-cpu=native | grep gfni
```

If the output of the command above is empty, the processor does not support these instructions.

When including binius64 as a dependency, it is recommended to add the following lines to your `Cargo.toml` file to have optimizations across crates

```toml
[profile.release]
lto = "fat"
```

### Examples

The `crates/frontend/src/circuits/` directory contains examples of pre-built circuits including SHA256, base64, and equality checking. To run tests for specific circuits:

```bash
cargo test -p binius-frontend
```

## Architecture

Binius64 consists of several specialized crates:

- **binius-field**: Binary field arithmetic with platform-specific optimizations
- **binius-frontend**: Circuit construction and compilation framework
- **binius-prover**: Zero-knowledge proof generation
- **binius-verifier**: Proof verification
- **binius-transcript**: Fiat-Shamir transcript handling
- **binius-utils**: Common utilities
- **binius-maybe-rayon**: Optional parallelization support

The constraint system supports two types of constraints over 64-bit words:
- AND constraints: `A & B ^ C = 0`
- MUL constraints: `A * B = (HI << 64) | LO`

## Authors

Binius64 is developed by [Irreducible](https://www.irreducible.com).
# Binius Prover Interface

Open-source Rust interface to the closed-source Binius ZK prover.

## Overview

This crate provides a clean, safe API for interacting with the Binius prover. It handles all FFI interactions and provides idiomatic Rust types and error handling.

## Architecture

```
Your Application
       ↓
This Interface (open-source)
       ↓
Closed-source Prover (via FFI)
```

## Features

- Safe Rust API wrapping unsafe FFI calls
- Mock implementation for testing without the closed-source binary
- Comprehensive error handling
- Thread-safe prover instances
- Zero-copy where possible

## Usage

```rust
use binius_prover_interface::{Prover, Witness};

// Create prover with default configuration
let prover = Prover::default()?;

// Create witness
let witness = Witness::new(vec![1, 0, 1, 1]);

// Generate proof
let proof = prover.prove(&witness)?;
println!("Proof size: {} bytes", proof.len());
```

## Configuration

```rust
use binius_prover_interface::ProverConfig;

let config = ProverConfig::builder()
    .num_threads(4)        // Number of threads (0 = auto)
    .tower_level(7)        // Tower field level (0-7)
    .security_bits(256)    // Security level in bits
    .build();
```

## Testing

The crate includes comprehensive tests that run with a mock prover implementation:

```bash
cargo test --package binius-prover-interface
```

## Examples

See the `examples/` directory for more detailed usage examples:

```bash
cargo run --package binius-prover-interface --example basic_proof
```

## Feature Flags

- `closed-source` - Link against the actual closed-source prover (default: mock implementation)
- `serde` - Enable serialization support for types

## Development

This crate was developed using Test-Driven Development (TDD):
1. Write failing tests first
2. Implement minimal code to pass
3. Refactor and improve

All functionality is thoroughly tested with both unit and integration tests.
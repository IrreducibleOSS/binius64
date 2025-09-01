# Binius Prover Client

A Rust crate providing a clean API for Binius ZK proof generation.

## Overview

This is a standard Rust library that provides a type-safe interface for generating Binius proofs. It uses FFI to communicate with the prover via serialized data, enabling the prover to be distributed as a closed-source binary while keeping the interface open-source.

## Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌──────────────────────┐
│   Your Rust App     │────│  Prover Client      │────│   Binius Prover      │
│                     │    │  (This Crate)       │    │  (C Library)         │
│ - ConstraintSystem  │    │ - ProverClient      │    │ - binius_prove()     │
│ - ValuesData        │    │ - Serialization     │    │ - Proof generation   │
│ - Proof             │    │ - Error handling    │    │                      │
└─────────────────────┘    └─────────────────────┘    └──────────────────────┘
```

## Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
binius-prover-client = { path = "../prover-client" }
```

## Requirements

This crate requires the Binius prover to be available as a C library:

```bash
export BINIUS_PROVER_LIB_PATH=/path/to/prover/library
```

Without this, the crate will compile but return runtime errors when attempting to generate proofs.

## Usage

```rust
use binius_prover_client::ProverClient;
use binius_core::constraint_system::{ConstraintSystem, ValuesData};

// Create a prover client instance
let prover = ProverClient::new(1); // log_inv_rate = 1

// Generate proof from constraint system and witness data
let proof = prover.prove(&constraint_system, &public_witness, &private_witness)?;
```

The crate provides three API methods:
- `prove()` - Takes Rust types, handles serialization internally
- `prove_serialized()` - Takes pre-serialized bytes, returns deserialized `Proof`
- `prove_serialized_raw()` - Takes and returns raw bytes for maximum efficiency

## FFI Interface Details

The FFI boundary uses a single C function with serialized inputs/outputs:

```c
// Returns proof size on success, negative error code on failure
int32_t binius_prove(
    const uint8_t* cs_bytes,          // Serialized ConstraintSystem
    size_t cs_len,
    const uint8_t* pub_witness_bytes, // Serialized public ValuesData  
    size_t pub_witness_len,
    const uint8_t* priv_witness_bytes,// Serialized private ValuesData
    size_t priv_witness_len,
    uint32_t log_inv_rate,            // Proof generation parameter
    uint8_t* proof_out,               // Output buffer for serialized Proof
    size_t proof_capacity             // Size of output buffer
);
```

### Error Codes

- **Positive number**: Size of the proof written to `proof_out` (success)
- **-1**: Null pointer error
- **-2**: Invalid input data  
- **-3**: Proving error
- **-4**: Serialization error
- **-5**: Output buffer too small

## Testing and Development

### Running the Test Suite

The crate includes a focused test suite with automatic FFI library management:

```bash
# Quick test - builds FFI library and runs all tests
./test_prover_client.sh
```

This script will:
1. Build the FFI library with the current implementation
2. Set up library paths automatically  
3. Run integration tests for all API variants
4. Verify FFI boundary crossing works correctly

### Manual Testing

```bash
# Build the FFI library
cargo build --release --features ffi-impl

# Set library path and run tests
export BINIUS_PROVER_LIB_PATH=$(pwd)/target/release
cargo test
```

### Test Coverage

The test suite focuses on interface correctness:
- **API methods**: All three variants (`prove`, `prove_serialized`, `prove_serialized_raw`)
- **FFI boundary**: Verifies data crosses the FFI boundary correctly
- **Serialization**: Ensures proper serialization/deserialization
- **Trait implementation**: Tests Default trait and accessor methods

## Implementation Notes

### Library Detection

The crate's build script automatically detects the external prover library:

- Checks `BINIUS_PROVER_LIB_PATH` environment variable
- Sets up linking when library is found
- Provides graceful fallback when library is unavailable

### FFI Implementation

The file `src/ffi_impl.rs` contains the Binius prover wrapped in a C-compatible FFI interface. This is used to test the FFI boundary. In a closed-source deployment, this code would be compiled as a proprietary C library.

## Advanced Usage

### Error Handling

The interface provides detailed error information:

```rust
use binius_prover_client::{ProverClient, ProverError};

match prover.prove(&cs, &pub_witness, &priv_witness) {
    Ok(proof) => println!("Proof generated: {} bytes", proof.data().len()),
    Err(ProverError::LibraryNotAvailable(msg)) => {
        eprintln!("FFI library not found: {}", msg);
        // Handle library not available case
    }
    Err(ProverError::FfiError(code)) => {
        eprintln!("FFI error code: {}", code);
        // Handle specific FFI error codes
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

### Performance Considerations

- **Pre-serialized data**: Use `prove_serialized_raw()` when you already have serialized inputs
- **Library linking**: Dynamic linking adds minimal overhead compared to proof generation time
- **Memory management**: The FFI boundary uses copying; consider this for very large constraint systems

### Integration with Existing Code

The interface is designed to integrate easily with existing Binius workflows:

```rust
// Works with existing constraint system construction
let cs = constraint_system_builder.build();
let witness = witness_builder.build();

// Drop-in replacement for direct prover usage  
let prover = ProverClient::new(log_inv_rate);
let proof = prover.prove(&cs.constraint_system, &witness.public, &witness.private)?;

// Use proof with existing verification code
verify_proof(&proof, &public_inputs)?;
```
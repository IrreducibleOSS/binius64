// Copyright 2025 Irreducible Inc.

//! CLI Framework Example - Using the binius_examples::Cli framework
//!
//! Demonstrates building a CLI tool using the standard Binius CLI framework.
//!
//! Tutorial guide: https://www.binius.xyz/building/

use anyhow::Result;
use binius_core::word::Word;
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;

/// A simple hash preimage circuit for demonstrating the CLI framework
struct HashPreimageExample {
	secret_wire: Wire,
	public_hash_wire: Wire,
}

/// Circuit parameters (compile-time configuration)
#[derive(Args, Clone)]
struct HashPreimageParams {
	/// Hash constant to use in the circuit
	#[arg(long, default_value = "3735928559")] // 0xDEADBEEF
	hash_constant: u64,
}

/// Instance data (runtime values for witness)
#[derive(Args, Clone)]
struct HashPreimageInstance {
	/// The secret value to prove knowledge of
	#[arg(long, default_value = "42")]
	secret: u64,
}

impl ExampleCircuit for HashPreimageExample {
	type Params = HashPreimageParams;
	type Instance = HashPreimageInstance;

	fn build(params: Self::Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// Build a simple hash circuit (XOR with constant)
		let hash_constant = builder.add_constant_64(params.hash_constant);

		// Private input (the secret)
		let secret_wire = builder.add_witness();

		// Compute "hash" = secret XOR constant
		let hash_result = builder.bxor(secret_wire, hash_constant);

		// Public output (the hash we claim to know preimage for)
		let public_hash_wire = builder.add_inout();
		builder.assert_eq("hash_verification", hash_result, public_hash_wire);

		Ok(Self {
			secret_wire,
			public_hash_wire,
		})
	}

	fn populate_witness(&self, instance: Self::Instance, filler: &mut WitnessFiller) -> Result<()> {
		// Fill in the secret value
		filler[self.secret_wire] = Word(instance.secret);

		// Compute expected hash (secret XOR constant)
		// In a real implementation, we'd get the constant from params
		let hash_constant = 0xDEADBEEF; // Default value
		let expected_hash = instance.secret ^ hash_constant;
		filler[self.public_hash_wire] = Word(expected_hash);

		Ok(())
	}
}

fn main() -> Result<()> {
	// Initialize tracing for performance profiling
	let _tracing_guard = tracing_profile::init_tracing()?;

	// Create and run the CLI
	Cli::<HashPreimageExample>::new("hash-preimage")
		.about("Prove knowledge of a hash preimage using a simple XOR hash")
		.run()
}

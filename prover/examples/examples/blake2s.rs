// Copyright 2025 Irreducible Inc.
use anyhow::{Result, ensure};
use binius_circuits::blake2s::Blake2s;
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::compiler::{CircuitBuilder, circuit::WitnessFiller};
use blake2::{Blake2s256, Digest};
use clap::Args;
use rand::prelude::*;

/// Blake2s circuit example demonstrating the Blake2s hash function implementation
struct Blake2sExample {
	blake2s_gadget: Blake2s,
}

/// Circuit parameters that affect structure (compile-time configuration)
#[derive(Args, Debug)]
struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long, default_value_t = 128)]
	max_bytes: usize,
}

/// Instance data for witness population (runtime values)
#[derive(Args, Debug)]
#[group(multiple = false)]
struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to half of --max-message-len).
	#[arg(long)]
	message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	message_string: Option<String>,
}

impl ExampleCircuit for Blake2sExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// Create the Blake2s gadget with witness wires
		let blake2s_gadget = Blake2s::new_witness(builder, params.max_bytes);

		Ok(Self { blake2s_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Determine the message bytes to hash
		let message_bytes = if let Some(message_string) = instance.message_string {
			// Use provided UTF-8 string
			message_string.as_bytes().to_vec()
		} else {
			// Generate random bytes
			let mut rng = StdRng::seed_from_u64(0);
			let len = instance.message_len.unwrap_or(self.blake2s_gadget.length);

			let mut message_bytes = vec![0u8; len];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		// Validate message length
		ensure!(
			message_bytes.len() == self.blake2s_gadget.length,
			"Message length ({}) does not equal ({})",
			message_bytes.len(),
			self.blake2s_gadget.length
		);

		// Compute the expected Blake2s digest using the reference implementation
		let mut hasher = Blake2s256::new();
		hasher.update(&message_bytes);
		let digest = hasher.finalize();
		let digest_array: [u8; 32] = digest.into();

		// Populate the witness values
		self.blake2s_gadget.populate_message(w, &message_bytes);
		self.blake2s_gadget.populate_digest(w, &digest_array);

		Ok(())
	}
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	// Create and run the CLI
	Cli::<Blake2sExample>::new("blake2s")
		.about("Blake2s hash function circuit example")
		.long_about(
			"Blake2s cryptographic hash function circuit implementation.\n\
            \n\
            This example demonstrates the Blake2s hash function which produces \
            32-byte digests. Blake2s is optimized for 32-bit platforms and is \
            faster than Blake2b on such architectures.\n\
            \n\
            The circuit supports variable-length messages up to the specified \
            maximum length. It implements the full Blake2s algorithm as \
            specified in RFC 7693, including 10 rounds of the compression \
            function.\n\
            \n\
            Examples:\n\
            \n\
            Hash a string:\n\
            cargo run --release --example blake2s -- --message-string \"Hello, World!\"\n\
            \n\
            Generate and hash random data (64 bytes):\n\
            cargo run --release --example blake2s -- --message-len 64\n\
            \n\
            Test with maximum message length:\n\
            cargo run --release --example blake2s -- --max-message-len 256 --message-len 256",
		)
		.run()
}

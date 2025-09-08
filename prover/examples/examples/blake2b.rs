// Copyright 2025 Irreducible Inc.

use anyhow::{Result, ensure};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::blake2b::{Blake2bCircuit, blake2b},
	compiler::{CircuitBuilder, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;

/// Blake2b circuit example demonstrating the Blake2b hash function implementation
struct Blake2bExample {
	blake2b_circuit: Blake2bCircuit,
	max_msg_len_bytes: usize,
}

/// Circuit parameters that affect structure (compile-time configuration)
#[derive(Args, Debug)]
struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long, default_value_t = 128)]
	max_msg_len_bytes: usize,
}

/// Instance data for witness population (runtime values)
#[derive(Args, Debug)]
#[group(multiple = false)]
struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to max_msg_len_bytes).
	#[arg(long)]
	message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	message_string: Option<String>,
}

impl ExampleCircuit for Blake2bExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// Blake2b processes messages in 128-byte blocks
		ensure!(params.max_msg_len_bytes > 0, "Message length must be positive");

		let blake2b_circuit = Blake2bCircuit::new_with_length(builder, params.max_msg_len_bytes);

		Ok(Self {
			blake2b_circuit,
			max_msg_len_bytes: params.max_msg_len_bytes,
		})
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Determine the message bytes to hash and actual length
		let (message_bytes, actual_len) = if let Some(message_string) = instance.message_string {
			// Use provided UTF-8 string
			let bytes = message_string.as_bytes().to_vec();
			let actual_len = bytes.len();
			ensure!(
				actual_len <= self.max_msg_len_bytes,
				"Message string length ({}) exceeds maximum ({})",
				actual_len,
				self.max_msg_len_bytes
			);
			// Pad to max length
			let mut padded = bytes;
			padded.resize(self.max_msg_len_bytes, 0);
			(padded, actual_len)
		} else {
			// Generate random bytes
			let mut rng = StdRng::seed_from_u64(42);
			let len = instance.message_len.unwrap_or(self.max_msg_len_bytes);
			ensure!(
				len <= self.max_msg_len_bytes,
				"Message length ({}) exceeds maximum ({})",
				len,
				self.max_msg_len_bytes
			);

			let mut message_bytes = vec![0u8; self.max_msg_len_bytes];
			rng.fill_bytes(&mut message_bytes[..len]);
			(message_bytes, len)
		};

		let expected_digest_vec = blake2b(&message_bytes[..actual_len], 64);
		let mut expected_digest = [0u8; 64];
		expected_digest.copy_from_slice(&expected_digest_vec);

		// Populate the message and digest in the witness
		self.blake2b_circuit
			.populate_message(w, &message_bytes[..actual_len]);
		self.blake2b_circuit.populate_digest(w, &expected_digest);

		Ok(())
	}
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	// Create and run the CLI
	Cli::<Blake2bExample>::new("blake2b")
		.about("Blake2b hash function circuit example")
		.long_about(
			"Blake2b cryptographic hash function circuit implementation.\n\
			\n\
			This example demonstrates the Blake2b hash function which produces \
			64-byte digests. Blake2b is optimized for 64-bit platforms and is \
			faster than Blake2s on such architectures.\n\
			\n\
			The circuit supports variable-length messages up to the specified \
			maximum length. It implements the full Blake2b algorithm as \
			specified in RFC 7693, including 12 rounds of the compression \
			function.\n\
			\n\
			Examples:\n\
			\n\
			Hash a string:\n\
			cargo run --release --example blake2b -- prove --message-string \"Hello, World!\"\n\
			\n\
			Generate and hash random data (64 bytes):\n\
			cargo run --release --example blake2b -- prove --message-len 64\n\
			\n\
			Test with maximum message length:\n\
			cargo run --release --example blake2b -- prove --max-msg-len-bytes 256 --message-len 256",
		)
		.run()
}

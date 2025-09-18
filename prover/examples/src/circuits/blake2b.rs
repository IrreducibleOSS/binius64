// Copyright 2025 Irreducible Inc.

use anyhow::{Result, ensure};
use binius_circuits::blake2b::{Blake2bCircuit, blake2b};
use binius_frontend::{CircuitBuilder, WitnessFiller};
use clap::Args;
use rand::prelude::*;

use crate::ExampleCircuit;

/// Blake2b circuit example demonstrating the Blake2b hash function implementation
pub struct Blake2bExample {
	blake2b_circuit: Blake2bCircuit,
	max_msg_len_bytes: usize,
}

/// Circuit parameters that affect structure (compile-time configuration)
#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long)]
	pub max_msg_len_bytes: Option<usize>,
}

/// Instance data for witness population (runtime values)
#[derive(Args, Debug, Clone)]
#[group(multiple = false)]
pub struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to 1024).
	#[arg(long)]
	pub message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	pub message_string: Option<String>,
}

impl ExampleCircuit for Blake2bExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// If max_msg_len_bytes not specified, determine from command line args
		let max_msg_len_bytes = params.max_msg_len_bytes.unwrap_or_else(|| {
			let args: Vec<String> = std::env::args().collect();
			let mut message_len = None;
			let mut message_string = None;

			for i in 0..args.len() {
				if args[i] == "--message-len" && i + 1 < args.len() {
					message_len = args[i + 1].parse::<usize>().ok();
				} else if args[i] == "--message-string" && i + 1 < args.len() {
					message_string = Some(args[i + 1].clone());
				}
			}

			if let Some(msg_string) = message_string {
				msg_string.len()
			} else {
				message_len.unwrap_or(1024)
			}
		});

		ensure!(max_msg_len_bytes > 0, "Message length must be positive");

		let blake2b_circuit = Blake2bCircuit::new_with_length(builder, max_msg_len_bytes);

		Ok(Self {
			blake2b_circuit,
			max_msg_len_bytes,
		})
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Determine the message bytes to hash
		let message_bytes = if let Some(message_string) = instance.message_string {
			// Use provided UTF-8 string
			let bytes = message_string.as_bytes().to_vec();
			ensure!(
				bytes.len() <= self.max_msg_len_bytes,
				"Message string length ({}) exceeds maximum ({})",
				bytes.len(),
				self.max_msg_len_bytes
			);
			// Pad to max length with zeros
			let mut padded = bytes;
			padded.resize(self.max_msg_len_bytes, 0);
			padded
		} else {
			// Generate random bytes
			let mut rng = StdRng::seed_from_u64(42);
			let len = instance.message_len.unwrap_or(1024); // Default to 1KiB
			ensure!(
				len <= self.max_msg_len_bytes,
				"Message length ({}) exceeds maximum ({})",
				len,
				self.max_msg_len_bytes
			);

			let mut message_bytes = vec![0u8; self.max_msg_len_bytes];
			rng.fill_bytes(&mut message_bytes[..len]);
			// Remaining bytes are already zeros from vec![0u8; ...]
			message_bytes
		};

		// Blake2b circuit hashes the full padded message
		let expected_digest_vec = blake2b(&message_bytes, 64);
		let mut expected_digest = [0u8; 64];
		expected_digest.copy_from_slice(&expected_digest_vec);

		// Populate the message and digest in the witness
		self.blake2b_circuit.populate_message(w, &message_bytes);
		self.blake2b_circuit.populate_digest(w, &expected_digest);

		Ok(())
	}

	fn param_summary(params: &Self::Params) -> Option<String> {
		Some(format!("{}b", params.max_msg_len_bytes))
	}
}

// Copyright 2025 Irreducible Inc.

use anyhow::{Result, ensure};
use binius_circuits::blake2s::Blake2s;
use binius_frontend::{CircuitBuilder, WitnessFiller};
use blake2::{Blake2s256, Digest};
use clap::Args;
use rand::prelude::*;

use crate::ExampleCircuit;

/// Blake2s circuit example demonstrating the Blake2s hash function implementation
pub struct Blake2sExample {
	blake2s_gadget: Blake2s,
}

/// Circuit parameters that affect structure (compile-time configuration)
#[derive(Debug, Clone, Args)]
pub struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long)]
	pub max_bytes: Option<usize>,
}

/// Instance data for witness population (runtime values)
#[derive(Debug, Clone, Args)]
#[group(multiple = false)]
pub struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to 1024).
	#[arg(long)]
	pub message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	pub message_string: Option<String>,
}

impl ExampleCircuit for Blake2sExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// If max_bytes not specified, determine from command line args
		let max_bytes = params.max_bytes.unwrap_or_else(|| {
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
		ensure!(max_bytes > 0, "max_bytes must be positive");

		// Create the Blake2s gadget with witness wires
		let blake2s_gadget = Blake2s::new_witness(builder, max_bytes);

		Ok(Self { blake2s_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Determine the message bytes to hash
		let message_bytes = if let Some(message_string) = instance.message_string {
			// Use provided UTF-8 string
			let bytes = message_string.as_bytes().to_vec();
			ensure!(
				bytes.len() <= self.blake2s_gadget.length,
				"Message string length ({}) exceeds maximum ({})",
				bytes.len(),
				self.blake2s_gadget.length
			);
			// Pad to the circuit's expected length with zeros
			let mut padded = bytes;
			padded.resize(self.blake2s_gadget.length, 0);
			padded
		} else {
			// Generate random bytes
			let mut rng = StdRng::seed_from_u64(0);
			let len = instance.message_len.unwrap_or(1024); // Default to 1KiB
			ensure!(
				len <= self.blake2s_gadget.length,
				"Message length ({}) exceeds maximum ({})",
				len,
				self.blake2s_gadget.length
			);

			let mut message_bytes = vec![0u8; self.blake2s_gadget.length];
			rng.fill_bytes(&mut message_bytes[..len]);
			// Remaining bytes are already zeros
			message_bytes
		};

		// Blake2s circuit expects the full padded message
		let mut hasher = Blake2s256::new();
		hasher.update(&message_bytes);
		let digest = hasher.finalize();
		let digest_array: [u8; 32] = digest.into();

		// Populate the witness values
		self.blake2s_gadget.populate_message(w, &message_bytes);
		self.blake2s_gadget.populate_digest(w, &digest_array);

		Ok(())
	}

	fn param_summary(params: &Self::Params) -> Option<String> {
		Some(format!("{}b", params.max_bytes.unwrap_or(1024)))
	}
}

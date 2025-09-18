// Copyright 2025 Irreducible Inc.
use anyhow::{Result, ensure};
use binius_circuits::keccak::{Keccak, N_WORDS_PER_DIGEST};
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha3::{Digest, Keccak256};

use crate::ExampleCircuit;

/// Keccak-256 hash circuit example
pub struct KeccakExample {
	keccak_hash: Keccak,
	max_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Maximum message length in bytes that the circuit can handle
	#[arg(long)]
	pub max_len_bytes: Option<usize>,
}

#[derive(Args, Debug, Clone)]
#[group(multiple = false)]
pub struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to 1024)
	#[arg(long)]
	pub message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	pub message_string: Option<String>,
}

impl ExampleCircuit for KeccakExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let max_len_bytes = params.max_len_bytes.unwrap_or_else(|| {
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

		let len_bytes = builder.add_witness();
		let digest: [Wire; N_WORDS_PER_DIGEST] = std::array::from_fn(|_| builder.add_inout());

		let n_words = max_len_bytes.div_ceil(8);
		let message = (0..n_words).map(|_| builder.add_inout()).collect();

		let keccak = Keccak::new(builder, len_bytes, digest, message);

		Ok(Self {
			keccak_hash: keccak,
			max_len_bytes,
		})
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Determine the message bytes to hash
		let message_bytes = if let Some(message_string) = instance.message_string {
			message_string.as_bytes().to_vec()
		} else {
			let mut rng = StdRng::seed_from_u64(42);
			let len = instance.message_len.unwrap_or(1024); // Default to 1KiB

			let mut message_bytes = vec![0u8; len];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		ensure!(
			message_bytes.len() <= self.max_len_bytes,
			"Message length ({}) exceeds circuit capacity ({})",
			message_bytes.len(),
			self.max_len_bytes
		);

		// Compute expected digest using reference implementation
		let mut hasher = Keccak256::new();
		hasher.update(&message_bytes);
		let digest: [u8; 32] = hasher.finalize().into();

		// Populate witness
		self.keccak_hash.populate_len_bytes(w, message_bytes.len());
		self.keccak_hash.populate_message(w, &message_bytes);
		self.keccak_hash.populate_digest(w, digest);

		Ok(())
	}

	fn param_summary(params: &Self::Params) -> Option<String> {
		Some(format!("{}b", params.max_len_bytes.unwrap_or(1024)))
	}
}

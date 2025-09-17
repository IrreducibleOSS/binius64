// Copyright 2025 Irreducible Inc.
use std::array;

use anyhow::{Result, ensure};
use binius_circuits::sha256::Sha256;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;
use rand::prelude::*;
use sha2::Digest;

use crate::ExampleCircuit;

pub struct Sha256Example {
	sha256_gadget: Sha256,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long, default_value_t = 2048)]
	pub max_len_bytes: usize,

	/// Build circuit for exact message length (makes length a compile-time constant instead of
	/// runtime witness).
	#[arg(long, default_value_t = false)]
	pub exact_len: bool,
}

#[derive(Args, Debug, Clone)]
#[group(multiple = false)]
pub struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to --max-len).
	#[arg(long)]
	pub message_len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	pub message_string: Option<String>,
}

impl ExampleCircuit for Sha256Example {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let max_len = params.max_len_bytes.div_ceil(8);
		let len_bytes = if params.exact_len {
			builder.add_constant_64(params.max_len_bytes as u64)
		} else {
			builder.add_witness()
		};
		let sha256_gadget = mk_circuit(builder, max_len, len_bytes);

		Ok(Self { sha256_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let message_bytes = if let Some(message_string) = instance.message_string {
			message_string.as_bytes().to_vec()
		} else {
			let mut rng = StdRng::seed_from_u64(42);
			let len = instance
				.message_len
				.unwrap_or(self.sha256_gadget.max_len_bytes());

			let mut message_bytes = vec![0u8; len];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		ensure!(message_bytes.len() <= self.sha256_gadget.max_len_bytes(), "message too long");

		let digest = sha2::Sha256::digest(&message_bytes);

		// Populate the input message for the hash function.
		self.sha256_gadget
			.populate_len_bytes(w, message_bytes.len());
		self.sha256_gadget.populate_message(w, &message_bytes);
		self.sha256_gadget.populate_digest(w, digest.into());

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, max_len: usize, len_bytes: Wire) -> Sha256 {
	let digest: [Wire; 4] = array::from_fn(|_| b.add_inout());
	let message = (0..max_len).map(|_| b.add_inout()).collect();
	Sha256::new(b, len_bytes, digest, message)
}

// Copyright 2025 Irreducible Inc.
use std::array;

use anyhow::{Result, ensure};
use binius_circuits::sha512::Sha512;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;
use rand::prelude::*;
use sha2::Digest;

use crate::ExampleCircuit;

pub struct Sha512Example {
	sha512_gadget: Sha512,
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
	/// Length of the randomly generated message, in bytes (defaults to max_len_bytes).
	#[arg(long)]
	pub len_bytes: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	pub message_string: Option<String>,
}

impl ExampleCircuit for Sha512Example {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let max_len = params.max_len_bytes.div_ceil(8);
		let len_bytes = if params.exact_len {
			builder.add_constant_64(params.max_len_bytes as u64)
		} else {
			builder.add_witness()
		};
		let sha512_gadget = mk_circuit(builder, max_len, len_bytes);

		Ok(Self { sha512_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let message_bytes = if let Some(message_string) = instance.message_string {
			message_string.as_bytes().to_vec()
		} else {
			let mut rng = StdRng::seed_from_u64(42);

			let mut message_bytes = vec![0u8; self.sha512_gadget.max_len_bytes()];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		ensure!(message_bytes.len() <= self.sha512_gadget.max_len_bytes(), "message too long");

		let digest = sha2::Sha512::digest(&message_bytes);

		// Populate the input message for the hash function.
		self.sha512_gadget
			.populate_len_bytes(w, message_bytes.len());
		self.sha512_gadget.populate_message(w, &message_bytes);
		self.sha512_gadget.populate_digest(w, digest.into());

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, max_len: usize, len_bytes: Wire) -> Sha512 {
	let digest: [Wire; 8] = array::from_fn(|_| b.add_inout());
	let message = (0..max_len).map(|_| b.add_inout()).collect();
	Sha512::new(b, len_bytes, digest, message)
}

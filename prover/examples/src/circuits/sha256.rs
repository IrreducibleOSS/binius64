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
	#[arg(long)]
	pub max_len_bytes: Option<usize>,

	/// Build circuit for exact message length (makes length a compile-time constant instead of
	/// runtime witness).
	#[arg(long, default_value_t = false)]
	pub exact_len: bool,
}

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

impl ExampleCircuit for Sha256Example {
	type Params = Params;
	type Instance = Instance;

	fn build(mut params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// If max_len_bytes not specified, determine from command line args
		if params.max_len_bytes.is_none() {
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

			params.max_len_bytes = Some(if let Some(msg_string) = message_string {
				msg_string.len()
			} else {
				message_len.unwrap_or(1024)
			});
		}

		let max_len_bytes = params.max_len_bytes.unwrap();
		let max_len = max_len_bytes.div_ceil(8);
		let len_bytes = if params.exact_len {
			builder.add_constant_64(max_len_bytes as u64)
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
			let len = instance.message_len.unwrap_or(1024); // Default to 1KiB

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

	fn param_summary(params: &Self::Params) -> Option<String> {
		let base = format!("{}b", params.max_len_bytes);
		if params.exact_len {
			Some(format!("{}-exact", base))
		} else {
			Some(base)
		}
	}
}

fn mk_circuit(b: &mut CircuitBuilder, max_len: usize, len_bytes: Wire) -> Sha256 {
	let digest: [Wire; 4] = array::from_fn(|_| b.add_inout());
	let message = (0..max_len).map(|_| b.add_inout()).collect();
	Sha256::new(b, len_bytes, digest, message)
}

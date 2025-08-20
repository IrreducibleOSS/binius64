use std::array;

use anyhow::{Result, ensure};
use binius_core::consts::{LOG_BYTE_BITS, LOG_WORD_SIZE_BITS};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::sha256::Sha256,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;
use sha2::Digest;

struct Sha256Example {
	sha256_gadget: Sha256,
}

#[derive(Args, Debug)]
struct Params {
	/// Maximum message length, in bytes, that the circuit can handle.
	/// Only full-word lengths (multiples of 8 bytes) are supported.
	#[arg(long, default_value_t = 2048)]
	max_len_bytes: usize,

	/// Build circuit for exact message length (makes length a compile-time constant instead of
	/// runtime witness).
	#[arg(long, default_value_t = false)]
	exact_len: bool,
}

#[derive(Args, Debug)]
#[group(multiple = false)]
struct Instance {
	/// Length of the randomly generated message, in bytes (defaults to --max-len).
	#[arg(long)]
	len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	message: Option<String>,
}

impl ExampleCircuit for Sha256Example {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		assert!(params.max_len_bytes & 0x07 == 0, "max_len_bytes must be a multiple of 8");
		let max_len = params.max_len_bytes >> (LOG_WORD_SIZE_BITS - LOG_BYTE_BITS);
		let len_wire = if params.exact_len {
			builder.add_constant_64(params.max_len_bytes as u64)
		} else {
			builder.add_witness()
		};
		let sha256_gadget = mk_circuit(builder, max_len, len_wire);

		Ok(Self { sha256_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let message_bytes = if let Some(message) = instance.message {
			message.as_bytes().to_vec()
		} else {
			let mut rng = StdRng::seed_from_u64(0);

			let mut message_bytes = vec![0u8; self.sha256_gadget.max_len_bytes()];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		ensure!(message_bytes.len() <= self.sha256_gadget.max_len_bytes(), "message too long");

		let digest = sha2::Sha256::digest(&message_bytes);

		// Populate the input message for the hash function.
		self.sha256_gadget.populate_len(w, message_bytes.len());
		self.sha256_gadget.populate_message(w, &message_bytes);
		self.sha256_gadget.populate_digest(w, digest.into());

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, message_len: usize, len: Wire) -> Sha256 {
	let digest: [Wire; 4] = array::from_fn(|_| b.add_inout());
	let message = (0..message_len).map(|_| b.add_inout()).collect();
	Sha256::new(b, len, digest, message)
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<Sha256Example>::new("sha256")
		.about("SHA256 compression function example")
		.run()
}

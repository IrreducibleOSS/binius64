use std::array;

use anyhow::{Result, ensure};
use binius_core::consts::{LOG_BYTE_BITS, LOG_WORD_SIZE_BITS};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::sha512::Sha512,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;
use sha2::Digest;

struct Sha512Example {
	sha512_gadget: Sha512,
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
	/// Length of the randomly generated message, in bytes (defaults to message-len * 8).
	#[arg(long)]
	len: Option<usize>,

	/// UTF-8 string to hash (if not provided, random bytes are generated)
	#[arg(long)]
	message: Option<String>,
}

impl ExampleCircuit for Sha512Example {
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
		let sha512_gadget = mk_circuit(builder, max_len, len_wire);

		Ok(Self { sha512_gadget })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let message_bytes = if let Some(message) = instance.message {
			message.as_bytes().to_vec()
		} else {
			let mut rng = StdRng::seed_from_u64(0);

			let mut message_bytes = vec![0u8; self.sha512_gadget.max_len_bytes()];
			rng.fill_bytes(&mut message_bytes);
			message_bytes
		};

		ensure!(message_bytes.len() <= self.sha512_gadget.max_len_bytes(), "message too long");

		let digest = sha2::Sha512::digest(&message_bytes);

		// Populate the input message for the hash function.
		self.sha512_gadget.populate_len(w, message_bytes.len());
		self.sha512_gadget.populate_message(w, &message_bytes);
		self.sha512_gadget.populate_digest(w, digest.into());

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, message_len: usize, len: Wire) -> Sha512 {
	let digest: [Wire; 8] = array::from_fn(|_| b.add_inout());
	let message = (0..message_len).map(|_| b.add_inout()).collect();
	Sha512::new(b, len, digest, message)
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<Sha512Example>::new("sha512")
		.about("SHA512 compression function example")
		.run()
}

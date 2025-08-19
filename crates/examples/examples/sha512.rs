use std::array;

use anyhow::{Result, ensure};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::sha512::Sha512,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;
use sha2::Digest;

struct Sha512Example {
	params: Params,
	sha512_gadget: Sha512,
}

#[derive(Args, Debug)]
struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long, default_value_t = 2048)]
	max_len: usize,

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

impl ExampleCircuit for Sha512Example {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let len_wire = if params.exact_len {
			builder.add_constant_64(params.max_len as u64)
		} else {
			builder.add_witness()
		};
		let sha512_gadget = mk_circuit(builder, params.max_len, len_wire);

		Ok(Self {
			params,
			sha512_gadget,
		})
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let message = if let Some(message) = instance.message {
			message.as_bytes().to_vec()
		} else {
			let message_len = instance.len.unwrap_or(self.params.max_len);
			let mut rng = StdRng::seed_from_u64(0);

			let mut message = vec![0u8; message_len];
			rng.fill_bytes(&mut message);
			message
		};

		ensure!(message.len() <= self.params.max_len, "message length exceeds --max-len");

		let digest = sha2::Sha512::digest(&message);

		// Populate the input message for the hash function.
		self.sha512_gadget.populate_len(w, message.len());
		self.sha512_gadget.populate_message(w, &message);
		self.sha512_gadget.populate_digest(w, digest.into());

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, max_n: usize, len: Wire) -> Sha512 {
	let digest: [Wire; 8] = array::from_fn(|_| b.add_inout());
	let n_blocks = (max_n + 17).div_ceil(128);
	let n_words = n_blocks * 16;
	let message = (0..n_words).map(|_| b.add_inout()).collect();
	Sha512::new(b, max_n, len, digest, message)
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<Sha512Example>::new("sha512")
		.about("SHA512 compression function example")
		.run()
}

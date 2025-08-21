use anyhow::{Result, ensure};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::blake3::Blake3,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;

struct Blake3Example {
	params: Params,
	blake3_gadget: Blake3,
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

impl ExampleCircuit for Blake3Example {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let len_wire = if params.exact_len {
			builder.add_constant_64(params.max_len as u64)
		} else {
			builder.add_witness()
		};
		let blake3_gadget = mk_circuit(builder, params.max_len, len_wire);

		Ok(Self {
			params,
			blake3_gadget,
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

		// Fill witness using Blake3's built-in method
		self.blake3_gadget.fill_witness(w, &message);

		Ok(())
	}
}

fn mk_circuit(b: &mut CircuitBuilder, max_len: usize, len: Wire) -> Blake3 {
	// Create message wires - Blake3 expects 8 bytes per wire
	let n_words = max_len.div_ceil(8);
	let message = (0..n_words).map(|_| b.add_inout()).collect();

	// Create Blake3 circuit with the given parameters
	Blake3::new(b, max_len, len, message)
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<Blake3Example>::new("blake3")
		.about("Blake3 hash function example - 7-round variant optimized for circuits")
		.run()
}

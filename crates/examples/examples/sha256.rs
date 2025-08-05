use std::array;

use anyhow::{Result, ensure};
use binius_examples::{prove_verify, setup};
use binius_frontend::{circuits::sha256::Sha256, compiler, compiler::Wire};
use clap::Parser;
use rand::prelude::*;
use sha2::Digest;

#[derive(Parser, Debug)]
#[command(name = "sha256")]
#[command(about = "SHA256 compression function example", long_about = None)]
struct Args {
	/// Log of the inverse rate for the proof system
	#[arg(short = 'l', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
	log_inv_rate: u32,

	/// Maximum byte-length the circuit can handle, unless --exact-len is set
	#[arg(long, default_value_t = 2048)]
	max_len: usize,

	/// Actual byte-length of the message
	#[arg(long)]
	len: Option<usize>,

	/// UTF-8 string to hash
	#[arg(long)]
	message: Option<String>,

	/// Use exact-length circuit (length is constant instead of witness)
	#[arg(long, default_value_t = false)]
	exact_len: bool,
}

#[derive(Clone, Copy)]
enum LengthMode {
	ExactLen,
	MaxLen(usize),
}

fn prepare_message_and_length(
	args: &Args,
	rng: &mut impl RngCore,
) -> Result<(Vec<u8>, LengthMode)> {
	let length_mode = if args.exact_len {
		LengthMode::ExactLen
	} else {
		LengthMode::MaxLen(args.max_len)
	};

	let message_len = match (&args.message, args.len) {
		(Some(msg), Some(len)) => {
			ensure!(
				msg.len() == len,
				"--len ({}) must equal the byte-length of --message ({})",
				len,
				msg.len()
			);
			len
		}
		(Some(msg), None) => msg.len(),
		(None, Some(len)) => len,
		(None, None) => args.max_len,
	};

	// Validate message length doesn't exceed max_len
	if let LengthMode::MaxLen(max_len) = length_mode {
		ensure!(
			message_len <= max_len,
			"Message length ({}) exceeds maximum length ({})",
			message_len,
			max_len
		);
	}

	let message = match args.message {
		Some(ref message) => message.as_bytes().to_vec(),
		None => {
			// Generate random bytes
			let mut message = vec![0u8; message_len];
			rng.fill_bytes(&mut message);
			message
		}
	};

	println!("Message length is {message_len} B");

	Ok((message, length_mode))
}

fn mk_circuit(b: &mut compiler::CircuitBuilder, max_n: usize, len: Wire) -> Sha256 {
	let digest: [Wire; 4] = array::from_fn(|_| b.add_inout());
	let n_blocks = (max_n + 9).div_ceil(64);
	let n_words = n_blocks * 8;
	let message = (0..n_words).map(|_| b.add_inout()).collect();
	Sha256::new(b, max_n, len, digest, message)
}

fn main() -> Result<()> {
	let args = Args::parse();
	let _tracing_guard = tracing_profile::init_tracing()?;

	let mut rng = StdRng::seed_from_u64(0);

	// Prepare message and determine length mode
	let (message, length_mode) = prepare_message_and_length(&args, &mut rng)?;

	let digest = sha2::Sha256::digest(&message);

	let build_scope = tracing::info_span!("Building circuit").entered();

	let mut builder = compiler::CircuitBuilder::new();
	let (max_len, len_wire) = match length_mode {
		LengthMode::ExactLen => {
			let len = message.len();
			(len, builder.add_constant_64(len as u64))
		}
		LengthMode::MaxLen(max_len) => (max_len, builder.add_witness()),
	};
	let sha256_gadget = mk_circuit(&mut builder, max_len, len_wire);
	let circuit = builder.build();
	drop(build_scope);

	let log_inv_rate = args.log_inv_rate as usize;
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, log_inv_rate)?;

	let witness = tracing::info_span!("Generating witness").in_scope(|| {
		let mut w = circuit.new_witness_filler();

		// Populate the input message for the hash function.
		sha256_gadget.populate_len(&mut w, message.len());
		sha256_gadget.populate_message(&mut w, &message);
		sha256_gadget.populate_digest(&mut w, digest.into());

		circuit.populate_wire_witness(&mut w).unwrap();
		w.into_value_vec()
	});

	prove_verify(&verifier, &prover, witness)?;
	Ok(())
}

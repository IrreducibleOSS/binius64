use std::array;

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
}

fn mk_circuit(b: &mut compiler::CircuitBuilder, max_n: usize, len: Wire) -> Sha256 {
	let digest: [Wire; 4] = array::from_fn(|_| b.add_inout());
	let n_blocks = (max_n + 9).div_ceil(64);
	let n_words = n_blocks * 8;
	let message = (0..n_words).map(|_| b.add_inout()).collect();
	Sha256::new(b, max_n, len, digest, message)
}

fn main() {
	let args = Args::parse();
	let _tracing_guard = tracing_profile::init_tracing().unwrap();

	let mut rng = StdRng::seed_from_u64(0);

	const EXACT_LEN: usize = 2048;

	let mut message = vec![0u8; EXACT_LEN];
	rng.fill_bytes(&mut message);
	let digest = sha2::Sha256::digest(&message);

	let build_scope = tracing::info_span!("Building circuit").entered();

	let mut builder = compiler::CircuitBuilder::new();
	let len = builder.add_constant_64(EXACT_LEN as u64);
	let sha256_gadget = mk_circuit(&mut builder, EXACT_LEN, len);
	let circuit = builder.build();
	drop(build_scope);

	let log_inv_rate = args.log_inv_rate as usize;
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, log_inv_rate).unwrap();

	let witness = tracing::info_span!("Generating witness").in_scope(|| {
		let mut w = circuit.new_witness_filler();

		// Populate the input message for the hash function.
		sha256_gadget.populate_len(&mut w, EXACT_LEN);
		sha256_gadget.populate_message(&mut w, &message);
		sha256_gadget.populate_digest(&mut w, digest.into());

		circuit.populate_wire_witness(&mut w).unwrap();
		w.into_value_vec()
	});

	prove_verify(&verifier, &prover, witness).unwrap();
}

use binius_core::word::Word;
use binius_examples::{prove_verify, setup};
use binius_frontend::{
	circuits::sha256::{Compress, State},
	compiler,
	compiler::Wire,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "sha256")]
#[command(about = "SHA256 compression function example", long_about = None)]
struct Args {
	/// Log of the inverse rate for the proof system
	#[arg(short = 'l', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
	log_inv_rate: u32,
}

fn main() {
	let args = Args::parse();
	let _tracing_guard = tracing_profile::init_tracing().unwrap();

	let build_scope = tracing::info_span!("Building circuit").entered();

	// Use the test-vector for SHA256 single block message: "abc".
	let mut preimage: [u8; 64] = [0; 64];
	preimage[0..3].copy_from_slice(b"abc");
	preimage[3] = 0x80;
	preimage[63] = 0x18;

	#[rustfmt::skip]
	let expected_state: [u32; 8] = [
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	];

	let circuit = compiler::CircuitBuilder::new();
	let state = State::iv(&circuit);
	let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
	let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
	let compress = Compress::new(&circuit, state, input);

	// Mask to only low 32-bit.
	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	drop(build_scope);

	let log_inv_rate = args.log_inv_rate as usize;
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, log_inv_rate).unwrap();

	let witness = tracing::info_span!("Generating witness").in_scope(|| {
		let mut w = circuit.new_witness_filler();

		// Populate the input message for the compression function.
		compress.populate_m(&mut w, preimage);

		for (i, &output) in output.iter().enumerate() {
			w[output] = Word(expected_state[i] as u64);
		}
		circuit.populate_wire_witness(&mut w).unwrap();
		w.into_value_vec()
	});

	prove_verify(&verifier, &prover, witness).unwrap();
}

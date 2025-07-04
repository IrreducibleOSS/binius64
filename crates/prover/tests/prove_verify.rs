use binius_frontend::{
	circuits::sha256::{Compress, State},
	compiler,
	compiler::Wire,
	word::Word,
};
use binius_prover::prove;
use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
use binius_verifier::{Params, fields::B128, verify};
use blake2::{Blake2b, digest::consts::U32};

type Blake2b256 = Blake2b<U32>;

#[test]
fn test_prove_verify_sha256_preimage() {
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

	let mut circuit = compiler::CircuitBuilder::new();
	let state = State::iv(&mut circuit);
	let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
	let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
	let compress = Compress::new(&mut circuit, state, input);

	// Mask to only low 32-bit.
	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	let mut w = circuit.new_witness_filler();

	// Populate the input message for the compression function.
	compress.populate_m(&mut w, preimage);

	for (i, &output) in output.iter().enumerate() {
		w[output] = Word(expected_state[i] as u64);
	}
	circuit.populate_wire_witness(&mut w).unwrap();

	let cs = circuit.constraint_system();
	println!("Number of AND constraints: {}", cs.n_and_constraints());
	println!("Number of gates: {}", circuit.n_gates());

	let witness = w.into_value_vec();

	let params = Params {};

	let mut prover_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::default();
	prove::<B128, _>(&params, &cs, witness.clone(), &mut prover_transcript).unwrap();

	let mut verifier_transcript = prover_transcript.into_verifier();
	verify::<B128, _>(&params, &cs, witness.inout(), &mut verifier_transcript).unwrap();
}

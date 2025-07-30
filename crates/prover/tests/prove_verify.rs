// Copyright 2025 Irreducible Inc.

use binius_field::arch::OptimalPackedB128;
use binius_frontend::{
	circuits::sha256::{Compress, State},
	compiler,
	compiler::Wire,
	word::Word,
};
use binius_math::ntt::SingleThreadedNTT;
use binius_prover::{merkle_tree::prover::BinaryMerkleTreeProver, prove};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	Params,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	merkle_tree::BinaryMerkleTreeScheme,
	verify,
};

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
	let witness = w.into_value_vec();

	const LOG_INV_RATE: usize = 1;
	let merkle_scheme = BinaryMerkleTreeScheme::<_, StdDigest, _>::new(StdCompression::default());
	let params = Params::new(&cs, LOG_INV_RATE, merkle_scheme).unwrap();

	let ntt = SingleThreadedNTT::with_subspace(params.fri_params().rs_code().subspace()).unwrap();
	let merkle_prover = BinaryMerkleTreeProver::<_, StdDigest, _>::new(StdCompression::default());
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prove::<OptimalPackedB128, _, _, _, _>(
		&params,
		&cs,
		witness.clone(),
		&mut prover_transcript,
		&ntt,
		&merkle_prover,
	)
	.unwrap();

	let mut verifier_transcript = prover_transcript.into_verifier();
	verify(&params, &cs, witness.public(), &mut verifier_transcript).unwrap();

	verifier_transcript.finalize().unwrap();
}

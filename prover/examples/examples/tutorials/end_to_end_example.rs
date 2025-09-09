// Copyright 2025 Irreducible Inc.

//! End-to-End Example
//!
//! A complete example showing circuit building, witness generation,
//! constraint verification, proof generation, and proof verification.
//!
//! Guide: https://www.binius.xyz/building/

use binius_circuits::sha256::Sha256;
use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::CircuitBuilder;
use binius_prover::{
	OptimalPackedB128, Prover, hash::parallel_compression::ParallelCompressionAdaptor,
};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
};
use sha2::{Digest, Sha256 as StdSha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Phase 1: Building the actual circuit
	let builder = CircuitBuilder::new();

	// both `content` and `nonce` will be 32 bytes, or in other words 4 64-bit wires.
	let content: Vec<_> = (0..4).map(|_| builder.add_witness()).collect();
	let nonce: Vec<_> = (0..4).map(|_| builder.add_witness()).collect();
	let commitment: [_; 4] = core::array::from_fn(|_| builder.add_inout());

	let message: Vec<_> = content.clone().into_iter().chain(nonce.clone()).collect();
	let len_bytes = builder.add_witness();
	let sha256 = Sha256::new(&builder, len_bytes, commitment, message);
	let circuit = builder.build();

	// Phase 2: Population of wire values
	let mut witness = circuit.new_witness_filler();
	witness[len_bytes] = Word(64); // feed the circuit a wire containing the preimage length, in bytes.

	// Message with random 32-byte nonce
	let mut content_bytes = [0u8; 32];
	content_bytes[..32].copy_from_slice(&b"A sample, exactly 32 bytes long."[..]);
	let nonce_bytes: [u8; 32] = rand::random();
	let mut message_bytes = [0u8; 64];
	message_bytes[..32].copy_from_slice(&content_bytes);
	message_bytes[32..].copy_from_slice(&nonce_bytes);
	sha256.populate_message(&mut witness, &message_bytes);

	let digest = StdSha256::digest(message_bytes);
	let mut digest_bytes = [0u8; 32];
	digest_bytes.copy_from_slice(&digest);
	sha256.populate_digest(&mut witness, digest_bytes);

	circuit.populate_wire_witness(&mut witness)?;

	// Phase 3: Verification that constraints hold over wires
	let cs = circuit.constraint_system();
	let witness_vec = witness.into_value_vec();
	verify_constraints(cs, &witness_vec)?;

	println!("✓ the wire values you populated satisfy the circuit's constraints");

	let log_inv_rate = 1;

	let verifier =
		Verifier::<StdDigest, _>::setup(cs.clone(), log_inv_rate, StdCompression::default())?;

	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)?;

	let challenger = StdChallenger::default();
	let mut prover_transcript = ProverTranscript::new(challenger.clone());
	let public_words = witness_vec.public().to_vec();
	prover.prove(witness_vec, &mut prover_transcript)?;
	let proof = prover_transcript.finalize();

	let mut verifier_transcript = VerifierTranscript::new(challenger, proof);
	verifier.verify(&public_words, &mut verifier_transcript)?;
	verifier_transcript.finalize()?;

	println!("✓ proof successfully verified");

	Ok(())
}

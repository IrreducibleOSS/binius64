// Copyright 2025 Irreducible Inc.

//! Proving Example - Generate and verify cryptographic proofs
//!
//! Demonstrates the complete flow from circuit building to proof verification.
//!
//! Tutorial guide: https://www.binius.xyz/building/

use anyhow::Result;
use binius_core::{constraint_system::ConstraintSystem, word::Word};
use binius_frontend::CircuitBuilder;
use binius_prover::{
	OptimalPackedB128, Prover, hash::parallel_compression::ParallelCompressionAdaptor,
};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	transcript::{ProverTranscript, VerifierTranscript},
};

fn main() -> Result<()> {
	println!("Building circuit...");

	// Phase 1: Build the circuit
	let builder = CircuitBuilder::new();

	// Create a simple circuit: prove knowledge of x such that x * 3 = y
	let x = builder.add_witness(); // Private input
	let three = builder.add_constant_64(3);
	let (_hi, lo) = builder.imul(x, three); // x * 3
	let y = builder.add_inout(); // Public output
	builder.assert_eq("verify_multiplication", lo, y);

	let circuit = builder.build();

	// Phase 2: Setup prover and verifier
	println!("Setting up prover and verifier...");

	let cs = circuit.constraint_system().clone();
	let log_inv_rate = 1; // Controls proof size vs. security tradeoff

	let verifier =
		Verifier::<StdDigest, _>::setup(cs.clone(), log_inv_rate, StdCompression::default())?;

	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)?;

	// Phase 3: Generate witness
	println!("Generating witness...");

	let mut filler = circuit.new_witness_filler();

	// Set witness values: x = 7, so y should be 21
	filler[x] = Word(7);
	filler[y] = Word(21);

	// Populate internal wires
	circuit.populate_wire_witness(&mut filler)?;
	let witness = filler.into_value_vec();

	// Phase 4: Generate proof
	println!("Generating proof...");

	let challenger = StdChallenger::default();
	let mut prover_transcript = ProverTranscript::new(challenger.clone());

	prover.prove(witness.clone(), &mut prover_transcript)?;

	let proof = prover_transcript.finalize();
	println!("Proof size: {} bytes", proof.len());

	// Phase 5: Verify proof
	println!("Verifying proof...");

	let mut verifier_transcript = VerifierTranscript::new(challenger, proof);

	// Extract public values from witness
	let public_values = witness.public();

	verifier.verify(public_values, &mut verifier_transcript)?;
	verifier_transcript.finalize()?;

	println!("✓ Proof verified successfully!");
	println!("  Proved knowledge of x such that x * 3 = 21");

	// Display circuit statistics
	print_circuit_stats(&cs);

	Ok(())
}

fn print_circuit_stats(cs: &ConstraintSystem) {
	println!("\nCircuit Statistics:");
	println!("  AND constraints: {}", cs.n_and_constraints());
	println!("  MUL constraints: {}", cs.n_mul_constraints());
	println!("  Total constraints: {}", cs.n_and_constraints() + cs.n_mul_constraints());

	// Estimate proof generation cost
	let cost = cs.n_and_constraints() + cs.n_mul_constraints() * 4;
	println!("  Estimated proof cost: {}", cost);
}

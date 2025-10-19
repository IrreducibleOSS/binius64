// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128bGhash as B128, Random, arch::OptimalPackedB128};
use binius_prover::hash::parallel_compression::ParallelCompressionAdaptor;
use binius_spartan_frontend::{
	circuit_builder::{CircuitBuilder, ConstraintBuilder, WitnessGenerator},
	compiler::compile,
};
use binius_spartan_prover::Prover;
use binius_spartan_verifier::{Verifier, config::StdChallenger};
use binius_transcript::ProverTranscript;
use binius_verifier::hash::{StdCompression, StdDigest};
use rand::{SeedableRng, rngs::StdRng};

// Build a simple square circuit: assert that x * x = y
fn square_circuit<Builder: CircuitBuilder>(
	builder: &mut Builder,
	x_wire: Builder::Wire,
	y_wire: Builder::Wire,
) {
	let x_squared = builder.mul(x_wire, x_wire);
	builder.assert_eq(x_squared, y_wire);
}

#[test]
fn test_square_circuit_prover_verifier() {
	// Build the constraint system
	let mut constraint_builder = ConstraintBuilder::new();
	let x_wire = constraint_builder.alloc_inout();
	let y_wire = constraint_builder.alloc_inout();
	square_circuit(&mut constraint_builder, x_wire, y_wire);
	let (cs, layout) = compile(constraint_builder);

	// Choose test values: x = random, y = x^2
	let mut rng = StdRng::seed_from_u64(0);
	let x_val = B128::random(&mut rng);
	let y_val = x_val * x_val;

	// Generate witness
	let mut witness_gen = WitnessGenerator::new(&layout);
	let x_assigned = witness_gen.write_inout(x_wire, x_val);
	let y_assigned = witness_gen.write_inout(y_wire, y_val);
	square_circuit(&mut witness_gen, x_assigned, y_assigned);
	let witness = witness_gen.build().expect("failed to build witness");

	// Validate witness satisfies constraints
	cs.validate(&witness);

	// Extract public inputs (constants + inout, padded to 2^log_public)
	let public = &witness[..1 << cs.log_public()];

	// Setup prover and verifier
	let log_inv_rate = 1;
	let compression = StdCompression::default();
	let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, compression.clone())
		.expect("verifier setup failed");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(compression),
	)
	.expect("prover setup failed");

	// Generate proof
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(&witness, &mut prover_transcript)
		.expect("prove failed");

	// Verify proof
	let mut verifier_transcript = prover_transcript.into_verifier();
	verifier
		.verify(public, &mut verifier_transcript)
		.expect("verify failed");
	verifier_transcript.finalize().expect("finalize failed");
}

#[test]
fn test_multiply_circuit_prover_verifier() {
	// Build a multiplication circuit: assert that a * b = c
	let mut constraint_builder = ConstraintBuilder::new();
	let a_wire = constraint_builder.alloc_inout();
	let b_wire = constraint_builder.alloc_inout();
	let c_wire = constraint_builder.alloc_inout();
	let product = constraint_builder.mul(a_wire, b_wire);
	constraint_builder.assert_eq(product, c_wire);
	let (cs, layout) = compile(constraint_builder);

	// Choose test values
	let mut rng = StdRng::seed_from_u64(1);
	let a_val = B128::random(&mut rng);
	let b_val = B128::random(&mut rng);
	let c_val = a_val * b_val;

	// Generate witness
	let mut witness_gen = WitnessGenerator::new(&layout);
	let a_assigned = witness_gen.write_inout(a_wire, a_val);
	let b_assigned = witness_gen.write_inout(b_wire, b_val);
	let c_assigned = witness_gen.write_inout(c_wire, c_val);
	let product = witness_gen.mul(a_assigned, b_assigned);
	witness_gen.assert_eq(product, c_assigned);
	let witness = witness_gen.build().expect("failed to build witness");

	// Validate witness satisfies constraints
	cs.validate(&witness);

	// Extract public inputs (constants + inout, padded to 2^log_public)
	let public = &witness[..1 << cs.log_public()];

	// Setup prover and verifier
	let log_inv_rate = 1;
	let compression = StdCompression::default();
	let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, compression.clone())
		.expect("verifier setup failed");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(compression),
	)
	.expect("prover setup failed");

	// Generate proof
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(&witness, &mut prover_transcript)
		.expect("prove failed");

	// Verify proof
	let mut verifier_transcript = prover_transcript.into_verifier();
	verifier
		.verify(public, &mut verifier_transcript)
		.expect("verify failed");
	verifier_transcript.finalize().expect("finalize failed");
}

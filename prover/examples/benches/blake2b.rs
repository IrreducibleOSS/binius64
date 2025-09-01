// Copyright 2025 Irreducible Inc.

use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::blake2b::{Blake2bExample, Instance, Params},
	setup,
};
use binius_frontend::compiler::CircuitBuilder;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Generate a feature suffix for benchmark names based on platform diagnostics
fn get_feature_suffix(_diagnostics: &PlatformDiagnostics) -> String {
	let mut suffix_parts = Vec::new();

	// Threading - check if rayon feature is enabled
	#[cfg(feature = "rayon")]
	suffix_parts.push("mt");
	#[cfg(not(feature = "rayon"))]
	suffix_parts.push("st");

	// Architecture
	#[cfg(target_arch = "x86_64")]
	{
		suffix_parts.push("x86");
		// Add key features based on compile-time features
		#[cfg(target_feature = "gfni")]
		suffix_parts.push("gfni");
		#[cfg(target_feature = "avx512f")]
		suffix_parts.push("avx512");
		#[cfg(all(not(target_feature = "avx512f"), target_feature = "avx2"))]
		suffix_parts.push("avx2");
	}

	#[cfg(target_arch = "aarch64")]
	{
		suffix_parts.push("arm64");
		// Check for NEON and AES
		#[cfg(all(target_feature = "neon", target_feature = "aes"))]
		suffix_parts.push("neon_aes");
		#[cfg(all(target_feature = "neon", not(target_feature = "aes")))]
		suffix_parts.push("neon");
	}

	suffix_parts.join("_")
}

fn bench_blake2b_hash(c: &mut Criterion) {
	// Parse message length from environment variable or use default
	let max_msg_len_bytes = env::var("BLAKE2B_MSG_BYTES")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(128);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	println!("\nBlake2b Benchmark Parameters:");
	println!("  Message length: {} bytes", max_msg_len_bytes);
	println!("  Circuit capacity: 16384 bytes (128 blocks × 128 bytes/block)");
	println!("  Note: Circuit has fixed size regardless of message length");
	println!("=======================================\n");

	let params = Params { max_msg_len_bytes };
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = Blake2bExample::build(params.clone(), &mut builder).unwrap();
	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, 1).unwrap();

	// Create a witness once for proof size measurement
	let mut filler = circuit.new_witness_filler();
	example
		.populate_witness(instance.clone(), &mut filler)
		.unwrap();
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	let feature_suffix = get_feature_suffix(&diagnostics);
	let bench_name = format!("msg_{}_{}", max_msg_len_bytes, feature_suffix);

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("blake2b_witness_generation");
		group.throughput(Throughput::Bytes(max_msg_len_bytes as u64));

		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&max_msg_len_bytes,
			|b, _| {
				b.iter(|| {
					let mut filler = circuit.new_witness_filler();
					example
						.populate_witness(instance.clone(), &mut filler)
						.unwrap();
					circuit.populate_wire_witness(&mut filler).unwrap();
					filler.into_value_vec()
				})
			},
		);
		group.finish();
	}

	// Measure proof generation time
	{
		let mut group = c.benchmark_group("blake2b_proof_generation");
		group.throughput(Throughput::Bytes(max_msg_len_bytes as u64));

		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&max_msg_len_bytes,
			|b, _| {
				b.iter(|| {
					let mut transcript = ProverTranscript::new(StdChallenger::default());
					prover.prove(witness.clone(), &mut transcript).unwrap();
					transcript
				})
			},
		);
		group.finish();
	}

	// Generate a proof for verification benchmarking and size measurement
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.unwrap();
	let proof_bytes = prover_transcript.finalize();
	let proof_size = proof_bytes.len();

	// Measure proof verification time
	{
		let mut group = c.benchmark_group("blake2b_proof_verification");
		group.throughput(Throughput::Bytes(max_msg_len_bytes as u64));

		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&max_msg_len_bytes,
			|b, _| {
				b.iter(|| {
					let mut verifier_transcript =
						VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
					verifier
						.verify(witness.public(), &mut verifier_transcript)
						.unwrap();
					verifier_transcript.finalize().unwrap()
				})
			},
		);
		group.finish();
	}

	// Print proof size
	println!("\nBlake2b proof size for {} bytes message: {} bytes", max_msg_len_bytes, proof_size);
}

criterion_group!(benches, bench_blake2b_hash);
criterion_main!(benches);

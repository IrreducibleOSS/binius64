// Copyright 2025 Irreducible Inc.
use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::keccak::{Instance, KeccakExample, Params},
	setup,
};
use binius_frontend::CircuitBuilder;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_keccak_permutations(c: &mut Criterion) {
	// Parse n_permutations from environment variable or use default
	let n_permutations = env::var("KECCAK_PERMUTATIONS")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(1365);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	println!("\nKeccak Benchmark Parameters:");
	println!("  Permutations: {}", n_permutations);
	println!("=======================================\n");

	let params = Params { n_permutations };
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = KeccakExample::build(params.clone(), &mut builder).unwrap();
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

	let feature_suffix = diagnostics.get_feature_suffix();

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("keccak_witness_generation");
		group.throughput(Throughput::Elements(n_permutations as u64));
		group.warm_up_time(std::time::Duration::from_secs(2));
		group.measurement_time(std::time::Duration::from_secs(120));
		group.sample_size(50);

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
			b.iter(|| {
				let mut filler = circuit.new_witness_filler();
				example
					.populate_witness(instance.clone(), &mut filler)
					.unwrap();
				circuit.populate_wire_witness(&mut filler).unwrap();
				filler.into_value_vec()
			})
		});

		group.finish();
	}

	// Measure proof generation time
	{
		let mut group = c.benchmark_group("keccak_proof_generation");
		group.throughput(Throughput::Elements(n_permutations as u64));
		group.warm_up_time(std::time::Duration::from_secs(2));
		group.measurement_time(std::time::Duration::from_secs(120));
		group.sample_size(50);

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
			b.iter(|| {
				let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
				prover
					.prove(witness.clone(), &mut prover_transcript)
					.unwrap();
				prover_transcript
			})
		});

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
		let mut group = c.benchmark_group("keccak_proof_verification");
		group.throughput(Throughput::Elements(n_permutations as u64));
		group.warm_up_time(std::time::Duration::from_secs(2));
		group.measurement_time(std::time::Duration::from_secs(120));
		group.sample_size(50);

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
			b.iter(|| {
				let mut verifier_transcript =
					VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
				verifier
					.verify(witness.public(), &mut verifier_transcript)
					.unwrap();
				verifier_transcript.finalize().unwrap()
			})
		});

		group.finish();
	}

	// Report proof size
	println!("\nKeccak proof size for {} permutations: {} bytes", n_permutations, proof_size);
}

criterion_group!(keccak, bench_keccak_permutations);
criterion_main!(keccak);

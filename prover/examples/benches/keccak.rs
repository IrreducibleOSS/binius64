// Copyright 2025 Irreducible Inc.
use binius_examples::{
	ExampleCircuit,
	bench_utils::{self, BenchTimingConfig, HashBenchConfig},
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
	// Check for help
	bench_utils::print_env_help();

	// Parse configuration from environment variables
	let config = HashBenchConfig::from_env();

	// Keccak-256 rate is 136 bytes (1088 bits)
	// For n bytes, we need n/136 permutations (rounded up)
	const KECCAK_256_RATE: usize = 136;
	let n_permutations = config.max_bytes.div_ceil(KECCAK_256_RATE);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	let params = vec![
		("Max bytes".to_string(), format!("{} bytes", config.max_bytes)),
		(
			"Permutations".to_string(),
			format!(
				"{} (for {} bytes at {} bytes/permutation)",
				n_permutations, config.max_bytes, KECCAK_256_RATE
			),
		),
		("Log inverse rate".to_string(), config.log_inv_rate.to_string()),
	];
	bench_utils::print_benchmark_header("Keccak", &params);

	let params = Params { n_permutations };
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = KeccakExample::build(params.clone(), &mut builder).unwrap();
	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, config.log_inv_rate).unwrap();

	// Create a witness once for proof size measurement
	let mut filler = circuit.new_witness_filler();
	example
		.populate_witness(instance.clone(), &mut filler)
		.unwrap();
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	let feature_suffix = diagnostics.get_feature_suffix();

	// Get timing configuration
	let timing = BenchTimingConfig::from_env_with_defaults(BenchTimingConfig::hash_default());

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("keccak_witness_generation");
		group.throughput(Throughput::Bytes(config.max_bytes as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

		let bench_name = format!("bytes_{}_{}", config.max_bytes, feature_suffix);
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
		group.throughput(Throughput::Bytes(config.max_bytes as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

		let bench_name = format!("bytes_{}_{}", config.max_bytes, feature_suffix);
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
		group.throughput(Throughput::Bytes(config.max_bytes as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

		let bench_name = format!("bytes_{}_{}", config.max_bytes, feature_suffix);
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
	bench_utils::print_proof_size("Keccak", &format!("{} bytes", config.max_bytes), proof_size);
}

criterion_group!(keccak, bench_keccak_permutations);
criterion_main!(keccak);

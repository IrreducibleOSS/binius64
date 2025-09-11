// Copyright 2025 Irreducible Inc.
//! SHA-512 hash benchmark

use binius_examples::{
	ExampleCircuit,
	bench_utils::{self, BenchTimingConfig, HashBenchConfig},
	circuits::sha512::{Instance, Params, Sha512Example},
	setup,
};
use binius_frontend::CircuitBuilder;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Benchmark SHA-512 hash circuit
fn bench_sha512_hash(c: &mut Criterion) {
	// Check for help
	bench_utils::print_env_help();

	// Parse configuration from environment variables
	let config = HashBenchConfig::from_env();

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	let blocks = config.max_bytes.div_ceil(128);
	let params_list = vec![
		(
			"Circuit capacity".to_string(),
			format!("{} bytes ({} blocks × 128 bytes/block)", config.max_bytes, blocks),
		),
		(
			"Message length".to_string(),
			format!("{} bytes (using full capacity)", config.max_bytes),
		),
		("Log inverse rate".to_string(), config.log_inv_rate.to_string()),
		("Note".to_string(), "Circuit size is dynamic based on max_bytes parameter".to_string()),
	];
	bench_utils::print_benchmark_header("SHA-512", &params_list);

	let params = Params {
		max_len_bytes: config.max_bytes,
		exact_len: false,
	};
	let instance = Instance {
		len_bytes: Some(config.max_bytes),
		message_string: None,
	};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = Sha512Example::build(params.clone(), &mut builder).unwrap();
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

	// Benchmark 1: Witness generation
	{
		let mut group = c.benchmark_group("sha512_witness_generation");
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

	// Benchmark 2: Proof generation
	{
		let mut group = c.benchmark_group("sha512_proof_generation");
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
					.unwrap()
			})
		});

		group.finish();
	}

	// Generate one proof for verification benchmark and size reporting
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.unwrap();
	let proof_bytes = prover_transcript.finalize();

	// Benchmark 3: Proof verification
	{
		let mut group = c.benchmark_group("sha512_proof_verification");
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
					.expect("Proof verification failed")
			})
		});

		group.finish();
	}

	// Print proof size
	bench_utils::print_proof_size(
		"SHA-512",
		&format!("{} bytes message", config.max_bytes),
		proof_bytes.len(),
	);
}

criterion_group!(benches, bench_sha512_hash);
criterion_main!(benches);

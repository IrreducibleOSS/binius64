// Copyright 2025 Irreducible Inc.
use std::env;

use binius_examples::{
	ExampleCircuit,
	bench_utils::{self, BenchTimingConfig, SignBenchConfig},
	circuits::hashsign::{HashBasedSigExample, Instance, Params},
	setup,
};
use binius_frontend::CircuitBuilder;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_hashsign(c: &mut Criterion) {
	// Check for help
	bench_utils::print_env_help();

	// Parse configuration from environment variables
	let config = SignBenchConfig::from_env(4); // default: 4 signatures

	// Parse XMSS/WOTS parameters from environment variables
	let tree_height = env::var("XMSS_TREE_HEIGHT")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(13);

	let spec = env::var("WOTS_SPEC")
		.ok()
		.and_then(|s| s.parse::<u8>().ok())
		.unwrap_or(2);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	let params_list = vec![
		("Signatures".to_string(), config.n_signatures.to_string()),
		(
			"XMSS tree height".to_string(),
			format!("{} (2^{} = {} slots)", tree_height, tree_height, 1 << tree_height),
		),
		("WOTS spec".to_string(), spec.to_string()),
		("Message size".to_string(), "32 bytes (fixed)".to_string()),
		("Log inverse rate".to_string(), config.log_inv_rate.to_string()),
	];
	bench_utils::print_benchmark_header("Hashsign", &params_list);

	let params = Params {
		num_validators: config.n_signatures,
		tree_height,
		spec,
	};
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = HashBasedSigExample::build(params.clone(), &mut builder).unwrap();
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
	let bench_name = format!("sig_{}_tree_{}_{}", config.n_signatures, tree_height, feature_suffix);

	// Get timing configuration
	let timing = BenchTimingConfig::from_env_with_defaults(BenchTimingConfig::sign_default());

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("hashsign_witness_generation");
		group.throughput(Throughput::Elements(config.n_signatures as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

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
		let mut group = c.benchmark_group("hashsign_proof_generation");
		group.throughput(Throughput::Elements(config.n_signatures as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

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
		let mut group = c.benchmark_group("hashsign_proof_verification");
		group.throughput(Throughput::Elements(config.n_signatures as u64));
		group.warm_up_time(timing.warm_up_time);
		group.measurement_time(timing.measurement_time);
		group.sample_size(timing.sample_size);

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
	bench_utils::print_proof_size(
		"Hashsign",
		&format!("{} signatures (tree height {})", config.n_signatures, tree_height),
		proof_size,
	);
}

criterion_group!(hashsign, bench_hashsign);
criterion_main!(hashsign);

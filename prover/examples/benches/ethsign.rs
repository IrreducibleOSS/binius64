// Copyright 2025 Irreducible Inc.
use std::env;

use binius_examples::{
	ExampleCircuit,
	bench_utils::{self, BenchTimingConfig, SignBenchConfig},
	circuits::ethsign::{EthSignExample, Instance, Params},
	setup,
};
use binius_frontend::CircuitBuilder;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_ethsign_signatures(c: &mut Criterion) {
	// Check for help
	bench_utils::print_env_help();

	// Parse configuration from environment variables
	let config = SignBenchConfig::from_env(1); // default: 1 signature

	// Parse message size from environment variable
	let max_msg_len_bytes = env::var("MESSAGE_MAX_BYTES")
		.ok()
		.and_then(|s| s.parse::<u16>().ok())
		.unwrap_or(67);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	let params_list = vec![
		("Signatures".to_string(), config.n_signatures.to_string()),
		("Max message length".to_string(), format!("{} bytes", max_msg_len_bytes)),
		("Log inverse rate".to_string(), config.log_inv_rate.to_string()),
	];
	bench_utils::print_benchmark_header("EthSign", &params_list);

	let params = Params {
		n_signatures: config.n_signatures,
		max_msg_len_bytes,
	};
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = EthSignExample::build(params.clone(), &mut builder).unwrap();
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
	let bench_name =
		format!("sig_{}_msg_{}_{}", config.n_signatures, max_msg_len_bytes, feature_suffix);

	// Get timing configuration
	let timing = BenchTimingConfig::from_env_with_defaults(BenchTimingConfig::sign_default());

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("ethsign_witness_generation");
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
		let mut group = c.benchmark_group("ethsign_proof_generation");
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
		let mut group = c.benchmark_group("ethsign_proof_verification");
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
		"EthSign",
		&format!("{} signatures, {} max bytes", config.n_signatures, max_msg_len_bytes),
		proof_size,
	);
}

criterion_group!(ethsign, bench_ethsign_signatures);
criterion_main!(ethsign);

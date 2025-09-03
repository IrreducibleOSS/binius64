use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::hashsign::{HashBasedSigExample, Instance, Params},
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

fn bench_hashsign(c: &mut Criterion) {
	// Parse parameters from environment variables or use defaults
	let num_validators = env::var("HASHSIGN_VALIDATORS")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(3);

	let tree_height = env::var("HASHSIGN_TREE_HEIGHT")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(3);

	let spec = env::var("HASHSIGN_SPEC")
		.ok()
		.and_then(|s| s.parse::<u8>().ok())
		.unwrap_or(2);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	println!("\nHashsign Benchmark Parameters:");
	println!("  Validators: {}", num_validators);
	println!("  Tree height: {} (2^{} = {} slots)", tree_height, tree_height, 1 << tree_height);
	println!("  Winternitz spec: {}", spec);
	println!("  Message size: 32 bytes (fixed)");
	println!("=========================================\n");

	let params = Params {
		num_validators,
		tree_height,
		spec,
	};
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = HashBasedSigExample::build(params.clone(), &mut builder).unwrap();
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
	let bench_name =
		format!("validators_{}_tree_{}_{}", num_validators, tree_height, feature_suffix);

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("hashsign_witness_generation");
		group.throughput(Throughput::Elements(num_validators as u64));

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
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
		group.throughput(Throughput::Elements(num_validators as u64));

		// Add warm-up time and measurement configuration for better stability
		group.warm_up_time(std::time::Duration::from_secs(5));

		// Scale measurement time based on number of validators
		// More validators need more time for stable measurements
		let measurement_time = match num_validators {
			1..=3 => std::time::Duration::from_secs(30),
			4..=10 => std::time::Duration::from_secs(60),
			_ => std::time::Duration::from_secs(120),
		};
		group.measurement_time(measurement_time);
		group.sample_size(50);

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
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
		group.throughput(Throughput::Elements(num_validators as u64));

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
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
	println!(
		"\nHashsign proof size for {} validators (tree height {}): {} bytes",
		num_validators, tree_height, proof_size
	);
}

criterion_group!(hashsign, bench_hashsign);
criterion_main!(hashsign);

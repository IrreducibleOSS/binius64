use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::keccak::{Instance, KeccakExample, Params},
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

	let feature_suffix = get_feature_suffix(&diagnostics);

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("keccak_witness_generation");
		group.throughput(Throughput::Elements(n_permutations as u64));

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&n_permutations,
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
		let mut group = c.benchmark_group("keccak_proof_generation");
		group.throughput(Throughput::Elements(n_permutations as u64));

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&n_permutations,
			|b, _| {
				b.iter(|| {
					let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
					prover
						.prove(witness.clone(), &mut prover_transcript)
						.unwrap();
					prover_transcript
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
		let mut group = c.benchmark_group("keccak_proof_verification");
		group.throughput(Throughput::Elements(n_permutations as u64));

		let bench_name = format!("n_{}_{}", n_permutations, feature_suffix);
		group.bench_with_input(
			BenchmarkId::from_parameter(&bench_name),
			&n_permutations,
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

	// Report proof size
	println!("\nKeccak proof size for {} permutations: {} bytes", n_permutations, proof_size);
}

criterion_group!(keccak, bench_keccak_permutations);
criterion_main!(keccak);

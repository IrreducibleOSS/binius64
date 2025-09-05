//! Blake2s hash benchmark

use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::blake2s::{Blake2sExample, Instance, Params},
	setup_sha256,
};
use binius_frontend::compiler::CircuitBuilder;
use binius_prover::hash::parallel_compression::ParallelCompressionAdaptor;
use binius_utils::platform_diagnostics::PlatformDiagnostics;
use binius_verifier::{
	config::StdChallenger,
	hash::StdCompression,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const DEFAULT_MAX_BYTES: usize = 2048 * 64; // 2048 blocks × 64 bytes/block = 131,072 bytes

fn get_feature_suffix(_diagnostics: &PlatformDiagnostics) -> String {
	let mut suffix_parts = vec![];

	// Add architecture
	#[cfg(target_arch = "x86_64")]
	{
		suffix_parts.push("x86_64");
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

/// Benchmark Blake2s hash circuit
fn bench_blake2s_hash(c: &mut Criterion) {
	// Get maximum message size from environment or use default
	let max_bytes = env::var("BLAKE2S_MAX_BYTES")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(DEFAULT_MAX_BYTES);

	// Gather and print comprehensive platform diagnostics
	let diagnostics = PlatformDiagnostics::gather();
	diagnostics.print();

	// Print benchmark-specific parameters
	let blocks = max_bytes.div_ceil(64);
	println!("\nBlake2s Benchmark Parameters:");
	println!("  Circuit capacity: {} bytes ({} blocks × 64 bytes/block)", max_bytes, blocks);
	println!("  Message length: {} bytes (using full capacity)", max_bytes);
	println!("  Note: Circuit size is dynamic based on max_bytes parameter");
	println!("=======================================\n");

	let params = Params { max_bytes };
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = Blake2sExample::build(params.clone(), &mut builder).unwrap();
	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let parallel_compression = ParallelCompressionAdaptor::new(StdCompression::default());
	let (verifier, prover) = setup_sha256(cs, 1, parallel_compression).unwrap();

	// Create a witness once for proof size measurement
	let mut filler = circuit.new_witness_filler();
	example
		.populate_witness(instance.clone(), &mut filler)
		.unwrap();
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	let feature_suffix = get_feature_suffix(&diagnostics);

	// Benchmark 1: Witness generation
	{
		let mut group = c.benchmark_group("blake2s_witness_generation");
		group.throughput(Throughput::Bytes(max_bytes as u64));

		let bench_name = format!("bytes_{}_{}", max_bytes, feature_suffix);
		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &max_bytes, |b, _| {
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
		let mut group = c.benchmark_group("blake2s_proof_generation");
		group.throughput(Throughput::Bytes(max_bytes as u64));
		group.measurement_time(std::time::Duration::from_secs(120)); // 120 seconds measurement time
		group.sample_size(100); // Keep 100 samples

		let bench_name = format!("bytes_{}_{}", max_bytes, feature_suffix);
		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &max_bytes, |b, _| {
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
		let mut group = c.benchmark_group("blake2s_proof_verification");
		group.throughput(Throughput::Bytes(max_bytes as u64));

		let bench_name = format!("bytes_{}_{}", max_bytes, feature_suffix);
		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &max_bytes, |b, _| {
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
	println!("\n\nBlake2s proof size for {} bytes message: {} bytes", max_bytes, proof_bytes.len());
}

criterion_group!(benches, bench_blake2s_hash);
criterion_main!(benches);

use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::ethsign::{EthSignExample, Instance, Params},
	setup,
};
use binius_frontend::compiler::CircuitBuilder;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Verify that optimal platform features are enabled at compile time
fn verify_platform_features() {
	#[cfg(target_arch = "x86_64")]
	{
		if !cfg!(target_feature = "gfni") {
			eprintln!(
				"⚠️  WARNING: GFNI not enabled. Use RUSTFLAGS=\"-C target-cpu=native\" for optimal performance on modern Intel CPUs (C7i)"
			);
		}
		if !cfg!(target_feature = "pclmulqdq") {
			eprintln!(
				"⚠️  WARNING: PCLMULQDQ not enabled. Carryless multiplication will be slower"
			);
		}
		if !cfg!(target_feature = "avx2") {
			eprintln!("⚠️  WARNING: AVX2 not enabled. SIMD operations will be slower");
		}
	}

	#[cfg(target_arch = "aarch64")]
	{
		if !cfg!(target_feature = "neon") {
			eprintln!(
				"⚠️  WARNING: NEON not enabled. Use RUSTFLAGS=\"-C target-cpu=native\" for optimal performance on ARM64 (C8g)"
			);
		}
		if !cfg!(target_feature = "aes") {
			eprintln!("⚠️  WARNING: AES acceleration not enabled");
		}
		if !cfg!(target_feature = "sha2") {
			eprintln!("⚠️  WARNING: SHA2 acceleration not enabled");
		}
	}
}

/// Print benchmark configuration including platform features
fn print_benchmark_config(n_signatures: usize, max_msg_len_bytes: u16) {
	println!("\n=== EthSign Benchmark Configuration ===");
	println!("Platform: {}", std::env::consts::ARCH);
	println!("Signatures: {}", n_signatures);
	println!("Max message length: {} bytes", max_msg_len_bytes);

	// Threading configuration
	let threading = if cfg!(feature = "rayon") {
		"multi-threaded (rayon)"
	} else {
		"single-threaded"
	};
	println!("Threading: {}", threading);

	// Platform-specific features
	#[cfg(target_arch = "x86_64")]
	{
		println!("\nx86_64 Features (compile-time):");
		println!(
			"  GFNI:       {}",
			if cfg!(target_feature = "gfni") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  PCLMULQDQ:  {}",
			if cfg!(target_feature = "pclmulqdq") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  AVX2:       {}",
			if cfg!(target_feature = "avx2") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  AVX-512:    {}",
			if cfg!(target_feature = "avx512f") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  AES:        {}",
			if cfg!(target_feature = "aes") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  VAES:       {}",
			if cfg!(target_feature = "vaes") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  VPCLMULQDQ: {}",
			if cfg!(target_feature = "vpclmulqdq") {
				"✓"
			} else {
				"✗"
			}
		);
	}

	#[cfg(target_arch = "aarch64")]
	{
		println!("\nARM64 Features (compile-time):");
		println!(
			"  NEON:       {}",
			if cfg!(target_feature = "neon") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  AES:        {}",
			if cfg!(target_feature = "aes") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  SHA2:       {}",
			if cfg!(target_feature = "sha2") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  SHA3:       {}",
			if cfg!(target_feature = "sha3") {
				"✓"
			} else {
				"✗"
			}
		);
		println!(
			"  PMULL:      {}",
			if cfg!(target_feature = "aes") {
				"✓ (via AES)"
			} else {
				"✗"
			}
		);
	}

	println!("=========================================\n");
}

/// Generate a feature suffix for benchmark names
fn get_feature_suffix() -> String {
	let mut features = Vec::new();

	// Threading
	if cfg!(feature = "rayon") {
		features.push("mt"); // multi-threaded
	} else {
		features.push("st"); // single-threaded
	}

	// Architecture and key features
	#[cfg(target_arch = "x86_64")]
	{
		features.push("x86");
		if cfg!(target_feature = "gfni") {
			features.push("gfni");
		}
		if cfg!(target_feature = "avx512f") {
			features.push("avx512");
		} else if cfg!(target_feature = "avx2") {
			features.push("avx2");
		}
	}

	#[cfg(target_arch = "aarch64")]
	{
		features.push("arm64");
		if cfg!(target_feature = "neon") && cfg!(target_feature = "aes") {
			features.push("neon_aes");
		} else if cfg!(target_feature = "neon") {
			features.push("neon");
		}
	}

	features.join("_")
}

fn bench_ethsign_signatures(c: &mut Criterion) {
	// Parse parameters from environment variables or use defaults
	let n_signatures = env::var("ETHSIGN_SIGNATURES")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(1);

	let max_msg_len_bytes = env::var("ETHSIGN_MSG_BYTES")
		.ok()
		.and_then(|s| s.parse::<u16>().ok())
		.unwrap_or(67);

	// Verify platform features and print configuration
	verify_platform_features();
	print_benchmark_config(n_signatures, max_msg_len_bytes);

	let params = Params {
		n_signatures,
		max_msg_len_bytes,
	};
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = EthSignExample::build(params.clone(), &mut builder).unwrap();
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

	let feature_suffix = get_feature_suffix();
	let bench_name = format!("sig_{}_msg_{}_{}", n_signatures, max_msg_len_bytes, feature_suffix);

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("ethsign_witness_generation");
		group.throughput(Throughput::Elements(n_signatures as u64));

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
		let mut group = c.benchmark_group("ethsign_proof_generation");
		group.throughput(Throughput::Elements(n_signatures as u64));

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
		let mut group = c.benchmark_group("ethsign_proof_verification");
		group.throughput(Throughput::Elements(n_signatures as u64));

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
		"\nEthSign proof size for {} signatures, {} max bytes: {} bytes",
		n_signatures, max_msg_len_bytes, proof_size
	);
}

criterion_group!(ethsign, bench_ethsign_signatures);
criterion_main!(ethsign);

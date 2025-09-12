// Copyright 2025 Irreducible Inc.

mod utils;

use std::alloc::System;

use binius_examples::circuits::keccak::{Instance, KeccakExample, Params};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use peakmem_alloc::PeakAlloc;
use utils::{ExampleBenchmark, HashBenchConfig, print_benchmark_header, run_cs_benchmark};

// Global allocator that tracks peak memory usage
#[global_allocator]
static KECCAK_PEAK_ALLOC: PeakAlloc<System> = PeakAlloc::new(System);

struct KeccakBenchmark {
	config: HashBenchConfig,
	n_permutations: usize,
}

impl KeccakBenchmark {
	fn new() -> Self {
		let config = HashBenchConfig::from_env();
		// Keccak-256 rate is 136 bytes (1088 bits)
		// For n bytes, we need n/136 permutations (rounded up)
		const KECCAK_256_RATE: usize = 136;
		let n_permutations = config.max_bytes.div_ceil(KECCAK_256_RATE);

		Self {
			config,
			n_permutations,
		}
	}
}

impl ExampleBenchmark for KeccakBenchmark {
	type Params = Params;
	type Instance = Instance;
	type Example = KeccakExample;

	fn create_params(&self) -> Self::Params {
		Params {
			n_permutations: self.n_permutations,
		}
	}

	fn create_instance(&self) -> Self::Instance {
		Instance {}
	}

	fn bench_name(&self) -> String {
		format!("message_bytes_{}", self.config.max_bytes)
	}

	fn throughput(&self) -> Throughput {
		Throughput::Bytes(self.config.max_bytes as u64)
	}

	fn proof_description(&self) -> String {
		format!("{} bytes", self.config.max_bytes)
	}

	fn log_inv_rate(&self) -> usize {
		self.config.log_inv_rate
	}

	fn print_params(&self) {
		const KECCAK_256_RATE: usize = 136;
		let params = vec![
			("Max bytes".to_string(), format!("{} bytes", self.config.max_bytes)),
			(
				"Permutations".to_string(),
				format!(
					"{} (for {} bytes at {} bytes/permutation)",
					self.n_permutations, self.config.max_bytes, KECCAK_256_RATE
				),
			),
			("Log inverse rate".to_string(), self.config.log_inv_rate.to_string()),
		];
		print_benchmark_header("Keccak", &params);
	}
}

fn bench_keccak_permutations(c: &mut Criterion) {
	let benchmark = KeccakBenchmark::new();
	run_cs_benchmark(c, benchmark, "keccak", &KECCAK_PEAK_ALLOC);
}

criterion_group!(keccak, bench_keccak_permutations);
criterion_main!(keccak);

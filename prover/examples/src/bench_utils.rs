// Copyright 2025 Irreducible Inc.
//! Common utilities for benchmarks

use std::{env, time::Duration};

/// Default HASH_MAX_BYTES for hash benchmarks
pub const DEFAULT_HASH_MAX_BYTES: usize = 128;

/// Default LOG_INV_RATE for hash benchmarks
pub const DEFAULT_HASH_LOG_INV_RATE: usize = 1;

/// Default LOG_INV_RATE for signature benchmarks
pub const DEFAULT_SIGN_LOG_INV_RATE: usize = 2;

/// Common configuration for hash benchmarks
#[derive(Debug, Clone)]
pub struct HashBenchConfig {
	pub max_bytes: usize,
	pub log_inv_rate: usize,
}

impl HashBenchConfig {
	/// Create configuration from environment variables
	pub fn from_env() -> Self {
		let max_bytes = env::var("HASH_MAX_BYTES")
			.ok()
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap_or(DEFAULT_HASH_MAX_BYTES);

		let log_inv_rate = env::var("LOG_INV_RATE")
			.ok()
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap_or(DEFAULT_HASH_LOG_INV_RATE);

		Self {
			max_bytes,
			log_inv_rate,
		}
	}
}

/// Common configuration for signature benchmarks
#[derive(Debug, Clone)]
pub struct SignBenchConfig {
	pub n_signatures: usize,
	pub log_inv_rate: usize,
}

impl SignBenchConfig {
	/// Create configuration from environment variables
	pub fn from_env(default_signatures: usize) -> Self {
		let n_signatures = env::var("N_SIGNATURES")
			.ok()
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap_or(default_signatures);

		let log_inv_rate = env::var("LOG_INV_RATE")
			.ok()
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap_or(DEFAULT_SIGN_LOG_INV_RATE);

		Self {
			n_signatures,
			log_inv_rate,
		}
	}
}

/// Benchmark timing configuration
#[derive(Debug, Clone)]
pub struct BenchTimingConfig {
	pub warm_up_time: Duration,
	pub measurement_time: Duration,
	pub sample_size: usize,
}

impl BenchTimingConfig {
	/// Default timing for hash benchmarks
	pub fn hash_default() -> Self {
		Self {
			warm_up_time: Duration::from_secs(2),
			measurement_time: Duration::from_secs(120),
			sample_size: 50,
		}
	}

	/// Default timing for signature benchmarks
	pub fn sign_default() -> Self {
		Self {
			warm_up_time: Duration::from_millis(100),
			measurement_time: Duration::from_secs(10),
			sample_size: 10,
		}
	}

	/// Create timing configuration from environment variables
	pub fn from_env_with_defaults(defaults: Self) -> Self {
		let warm_up_time = env::var("BENCH_WARM_UP_SECS")
			.ok()
			.and_then(|s| s.parse::<u64>().ok())
			.map(Duration::from_secs)
			.unwrap_or(defaults.warm_up_time);

		let measurement_time = env::var("BENCH_MEASUREMENT_SECS")
			.ok()
			.and_then(|s| s.parse::<u64>().ok())
			.map(Duration::from_secs)
			.unwrap_or(defaults.measurement_time);

		let sample_size = env::var("BENCH_SAMPLE_SIZE")
			.ok()
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap_or(defaults.sample_size);

		Self {
			warm_up_time,
			measurement_time,
			sample_size,
		}
	}
}

/// Print benchmark header with consistent formatting
pub fn print_benchmark_header(name: &str, params: &[(String, String)]) {
	println!("\n{} Benchmark Parameters:", name);
	for (key, value) in params {
		println!("  {}: {}", key, value);
	}
	println!("=======================================\n");
}

/// Print proof size in consistent format
pub fn print_proof_size(bench_name: &str, description: &str, size_bytes: usize) {
	println!(
		"\n{} proof size for {}: {} bytes ({:.2} KiB)",
		bench_name,
		description,
		size_bytes,
		size_bytes as f64 / 1024.0
	);
}

/// Print environment variable help
pub fn print_env_help() {
	if env::var("BENCH_HELP").is_ok() {
		println!("Available environment variables:");
		println!("\nCommon:");
		println!("  LOG_INV_RATE           - Logarithmic inverse rate parameter");
		println!(
			"                           (default: {} for hash, {} for signature)",
			DEFAULT_HASH_LOG_INV_RATE, DEFAULT_SIGN_LOG_INV_RATE
		);
		println!("  BENCH_WARM_UP_SECS     - Warm-up time in seconds");
		println!("  BENCH_MEASUREMENT_SECS - Measurement time in seconds");
		println!("  BENCH_SAMPLE_SIZE      - Number of samples to collect");
		println!("  BENCH_HELP             - Show this help message");
		println!("\nHash benchmarks:");
		println!(
			"  HASH_MAX_BYTES         - Maximum bytes for hash benchmarks (default: {})",
			DEFAULT_HASH_MAX_BYTES
		);
		println!("\nSignature aggregation benchmarks:");
		println!(
			"  N_SIGNATURES           - Number of signatures (default: 1 for ethsign, 4 for hashsign)"
		);
		println!("  MESSAGE_MAX_BYTES      - Max message bytes for ethsign (default: 67)");
		println!("  XMSS_TREE_HEIGHT       - Tree height for hashsign (default: 13)");
		println!("  WOTS_SPEC              - Winternitz spec for hashsign (default: 2)");
		std::process::exit(0);
	}
}

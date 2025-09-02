use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
	// Core fields
	pub benchmark: String,
	pub parameters: Option<String>,
	pub timestamp: String,

	// Git fields (prefixed)
	pub git_commit: Option<String>,
	pub git_commit_time: Option<String>,
	pub git_branch: Option<String>,

	// Environment fields (prefixed)
	pub env_os: String,
	pub env_arch: String,
	pub env_cpu_count: usize,

	// Run configuration
	pub iterations: usize,
	pub log_inv_rate: u32,

	// Timing data
	pub timings: TimingData,

	// Warnings
	#[serde(skip_serializing_if = "Option::is_none")]
	pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingData {
	pub single_run: Option<RunMetrics>,
	pub aggregate: Option<AggregateMetrics>,
	pub all_runs: Vec<RunMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetrics {
	pub iteration: Option<usize>,
	pub build_ms: f64,
	pub witness_ms: f64,
	pub prove_ms: f64,
	pub verify_ms: f64,
	pub proof_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateMetrics {
	pub avg_build_ms: f64,
	pub avg_witness_ms: f64,
	pub avg_prove_ms: f64,
	pub avg_verify_ms: f64,
	pub avg_proof_size_bytes: f64,
}

#[derive(Debug, Clone)]
pub struct ProveMetrics {
	pub build_time: Duration,
	pub witness_time: Duration,
	pub prove_time: Duration,
	pub verify_time: Duration,
	pub proof_size: usize,
}

/// Get git information for the current repository.
fn get_git_info() -> (Option<String>, Option<String>, Option<String>) {
	use std::process::Command;

	let get_commit = || -> Option<String> {
		Command::new("git")
			.args(["rev-parse", "HEAD"])
			.output()
			.ok()?
			.stdout
			.pipe(String::from_utf8)
			.ok()?
			.trim()
			.to_string()
			.pipe(|s| if s.is_empty() { None } else { Some(s) })
	};

	let get_commit_time = || -> Option<String> {
		Command::new("git")
			.args(["log", "-1", "--format=%cI"])
			.output()
			.ok()?
			.stdout
			.pipe(String::from_utf8)
			.ok()?
			.trim()
			.to_string()
			.pipe(|s| if s.is_empty() { None } else { Some(s) })
	};

	let get_branch = || -> Option<String> {
		Command::new("git")
			.args(["rev-parse", "--abbrev-ref", "HEAD"])
			.output()
			.ok()?
			.stdout
			.pipe(String::from_utf8)
			.ok()?
			.trim()
			.to_string()
			.pipe(|s| if s.is_empty() { None } else { Some(s) })
	};

	(get_commit(), get_commit_time(), get_branch())
}

// Helper trait for pipeline-style operations
trait Pipe<T> {
	fn pipe<U, F>(self, f: F) -> U
	where
		F: FnOnce(T) -> U;
}

impl<T> Pipe<T> for T {
	fn pipe<U, F>(self, f: F) -> U
	where
		F: FnOnce(T) -> U,
	{
		f(self)
	}
}

/// Export metrics to JSON file with proper support for multiple runs
pub fn export_metrics(
	benchmark: &str,
	parameters: Option<String>,
	log_inv_rate: u32,
	metrics: Vec<RunMetrics>,
	output_path: PathBuf,
) -> Result<()> {
	// Get git and environment information
	let (git_commit, git_commit_time, git_branch) = get_git_info();
	let env_os = std::env::consts::OS.to_string();
	let env_arch = std::env::consts::ARCH.to_string();
	let env_cpu_count = num_cpus::get();

	// Check proof size consistency
	let mut warnings = Vec::new();
	let proof_sizes: Vec<usize> = metrics.iter().map(|m| m.proof_size_bytes).collect();
	if proof_sizes.len() > 1 {
		let first_size = proof_sizes[0];
		let all_same = proof_sizes.iter().all(|&size| size == first_size);
		if !all_same {
			let min_size = *proof_sizes.iter().min().unwrap();
			let max_size = *proof_sizes.iter().max().unwrap();
			let warning_msg = format!(
				"Proof sizes are inconsistent! Sizes vary from {} to {} bytes (delta: {} bytes)",
				min_size,
				max_size,
				max_size - min_size
			);
			warnings.push(warning_msg.clone());

			// Print console warning with color
			eprintln!("\n⚠️  WARNING: {}", warning_msg);
			eprintln!("   All sizes: {:?}", proof_sizes);
		}
	}

	// Calculate aggregates if multiple runs
	let aggregate = if metrics.len() > 1 {
		// Calculate simple averages
		let count = metrics.len() as f64;
		let avg_build_ms = metrics.iter().map(|m| m.build_ms).sum::<f64>() / count;
		let avg_witness_ms = metrics.iter().map(|m| m.witness_ms).sum::<f64>() / count;
		let avg_prove_ms = metrics.iter().map(|m| m.prove_ms).sum::<f64>() / count;
		let avg_verify_ms = metrics.iter().map(|m| m.verify_ms).sum::<f64>() / count;
		let avg_proof_size_bytes = metrics
			.iter()
			.map(|m| m.proof_size_bytes as f64)
			.sum::<f64>()
			/ count;

		Some(AggregateMetrics {
			avg_build_ms,
			avg_witness_ms,
			avg_prove_ms,
			avg_verify_ms,
			avg_proof_size_bytes,
		})
	} else {
		None
	};

	let single_run = if metrics.len() == 1 {
		Some(metrics[0].clone())
	} else {
		None
	};

	let benchmark_metrics = BenchmarkMetrics {
		// Core fields
		benchmark: benchmark.to_string(),
		parameters,
		timestamp: chrono::Utc::now().to_rfc3339(),

		// Git fields
		git_commit,
		git_commit_time,
		git_branch,

		// Environment fields
		env_os,
		env_arch,
		env_cpu_count,

		// Run configuration
		iterations: metrics.len(),
		log_inv_rate,

		// Timing data
		timings: TimingData {
			single_run,
			aggregate,
			all_runs: metrics,
		},

		// Warnings
		warnings: if warnings.is_empty() {
			None
		} else {
			Some(warnings)
		},
	};

	// Create parent directories if they don't exist
	if let Some(parent) = output_path.parent()
		&& !parent.exists()
	{
		std::fs::create_dir_all(parent)
			.with_context(|| format!("Failed to create directory: {}", parent.display()))?;
	}

	// Write JSON with pretty formatting
	let json = serde_json::to_string_pretty(&benchmark_metrics)?;
	std::fs::write(&output_path, json)
		.with_context(|| format!("Failed to write JSON to: {}", output_path.display()))?;

	println!("📊 Metrics exported to: {}", output_path.display());

	Ok(())
}

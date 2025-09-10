// Copyright 2025 Irreducible Inc.

//! Cost model benchmark for measuring operation costs in the constraint system

use binius_core::word::Word;
use binius_examples::setup;
use binius_frontend::CircuitBuilder;
use binius_verifier::{config::StdChallenger, transcript::ProverTranscript};
use criterion::{BenchmarkId, Criterion, criterion_group};
use rand::{Rng, SeedableRng, rngs::StdRng};

const FIXED_CONSTRAINTS: usize = 50_000;

fn bench_and_constraints(c: &mut Criterion) {
	let mut group = c.benchmark_group("and_constraints");
	group.sample_size(10);

	// Build circuit
	let builder = CircuitBuilder::new();
	let witnesses: Vec<_> = (0..FIXED_CONSTRAINTS * 3)
		.map(|_| builder.add_witness())
		.collect();

	// Create AND constraints: c = a & b
	for i in 0..FIXED_CONSTRAINTS {
		let a = witnesses[i * 3];
		let b = witnesses[i * 3 + 1];
		builder.band(a, b);
	}

	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let (_verifier, prover) = setup(cs, 1).unwrap();

	// Create witness
	let mut filler = circuit.new_witness_filler();
	let mut rng = StdRng::seed_from_u64(42);
	for i in 0..FIXED_CONSTRAINTS * 3 {
		let value: u64 = rng.random();
		filler[witnesses[i]] = Word(value);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	// Benchmark
	group.bench_function(format!("{}k_and", FIXED_CONSTRAINTS / 1000), |b| {
		b.iter(|| {
			let mut transcript = ProverTranscript::new(StdChallenger::default());
			prover.prove(witness.clone(), &mut transcript).unwrap();
		});
	});

	group.finish();
}

fn bench_mul_constraints(c: &mut Criterion) {
	let mut group = c.benchmark_group("mul_constraints");
	group.sample_size(10);

	// Build circuit
	let builder = CircuitBuilder::new();
	let witnesses: Vec<_> = (0..FIXED_CONSTRAINTS * 2)
		.map(|_| builder.add_witness())
		.collect();

	// Create MUL constraints: (hi, lo) = a * b
	for i in 0..FIXED_CONSTRAINTS {
		let a = witnesses[i * 2];
		let b = witnesses[i * 2 + 1];
		builder.imul(a, b);
	}

	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let (_verifier, prover) = setup(cs, 1).unwrap();

	// Create witness
	let mut filler = circuit.new_witness_filler();
	let mut rng = StdRng::seed_from_u64(42);
	for i in 0..FIXED_CONSTRAINTS * 2 {
		let value: u64 = rng.random();
		filler[witnesses[i]] = Word(value);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	// Benchmark
	group.bench_function(format!("{}k_mul", FIXED_CONSTRAINTS / 1000), |b| {
		b.iter(|| {
			let mut transcript = ProverTranscript::new(StdChallenger::default());
			prover.prove(witness.clone(), &mut transcript).unwrap();
		});
	});

	group.finish();
}

fn bench_xor_packing(c: &mut Criterion) {
	let mut group = c.benchmark_group("xor_packing");
	group.sample_size(10);

	for n_xor_terms in [1, 2, 4, 8, 16, 32].iter() {
		// Build circuit
		let builder = CircuitBuilder::new();
		let witnesses: Vec<_> = (0..FIXED_CONSTRAINTS * (n_xor_terms + 2))
			.map(|_| builder.add_witness())
			.collect();

		// Create AND constraints with XOR-packed operands using bxor_multi
		for c_idx in 0..FIXED_CONSTRAINTS {
			let base = c_idx * (n_xor_terms + 2);

			// Use bxor_multi to pack XORs directly
			let xor_inputs: Vec<_> = (0..*n_xor_terms).map(|i| witnesses[base + i]).collect();
			let xor_result = builder.bxor_multi(&xor_inputs);

			// AND with another witness
			let b = witnesses[base + n_xor_terms];
			builder.band(xor_result, b);
		}

		let circuit = builder.build();
		let cs = circuit.constraint_system().clone();
		let (_verifier, prover) = setup(cs, 1).unwrap();

		// Create witness
		let mut filler = circuit.new_witness_filler();
		let mut rng = StdRng::seed_from_u64(42);
		for i in 0..FIXED_CONSTRAINTS * (n_xor_terms + 2) {
			let value: u64 = rng.random();
			filler[witnesses[i]] = Word(value);
		}
		circuit.populate_wire_witness(&mut filler).unwrap();
		let witness = filler.into_value_vec();

		// Benchmark
		group.bench_with_input(BenchmarkId::from_parameter(n_xor_terms), n_xor_terms, |b, _| {
			b.iter(|| {
				let mut transcript = ProverTranscript::new(StdChallenger::default());
				prover.prove(witness.clone(), &mut transcript).unwrap();
			});
		});
	}

	group.finish();
}

fn measure_xor_costs(use_shifts: bool) -> Vec<(usize, f64)> {
	use std::time::Instant;

	let mut results = Vec::new();

	for &n_xor_terms in &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
		// Build circuit
		let builder = CircuitBuilder::new();
		let witnesses: Vec<_> = (0..1000 * (n_xor_terms + 2))
			.map(|_| builder.add_witness())
			.collect();

		// Create AND constraints with XOR-packed operands
		for c_idx in 0..1000 {
			let base = c_idx * (n_xor_terms + 2);

			let xor_inputs: Vec<_> = if use_shifts {
				// Build XOR operand with ALL terms shifted
				(0..n_xor_terms)
					.map(|i| {
						let wire = witnesses[base + i];
						// Vary shift amounts: use prime numbers for diversity
						let shift_amount = 1 + (i * 7) % 63;
						builder.shr(wire, shift_amount as u32)
					})
					.collect()
			} else {
				// Use unshifted wires
				(0..n_xor_terms).map(|i| witnesses[base + i]).collect()
			};

			let a_wire = builder.bxor_multi(&xor_inputs);

			// AND with another witness
			let b = witnesses[base + n_xor_terms];
			builder.band(a_wire, b);
		}

		let circuit = builder.build();
		let cs = circuit.constraint_system().clone();
		let (_verifier, prover) = setup(cs, 1).unwrap();

		// Create witness
		let mut filler = circuit.new_witness_filler();
		for i in 0..1000 * (n_xor_terms + 2) {
			filler[witnesses[i]] = Word(0x123456789ABCDEFu64.wrapping_add(i as u64));
		}
		circuit.populate_wire_witness(&mut filler).unwrap();
		let witness = filler.into_value_vec();

		// Time multiple runs
		let start = Instant::now();
		let iterations = 20;
		for _ in 0..iterations {
			let mut transcript = ProverTranscript::new(StdChallenger::default());
			prover.prove(witness.clone(), &mut transcript).unwrap();
		}
		let avg_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;

		results.push((n_xor_terms, avg_time_ms));
	}

	results
}

fn measure_shift_costs() -> Vec<(usize, f64)> {
	use std::time::Instant;

	let mut results = Vec::new();

	// Test: 32 XORs with varying numbers of them shifted
	let n_xor_terms = 32;

	for &all_shifted in &[false, true] {
		// Build circuit
		let builder = CircuitBuilder::new();
		let witnesses: Vec<_> = (0..1000 * (n_xor_terms + 2))
			.map(|_| builder.add_witness())
			.collect();

		// Create AND constraints with XOR-packed operands
		for c_idx in 0..1000 {
			let base = c_idx * (n_xor_terms + 2);

			// Build XOR operand: all shifted or none shifted
			let mut xor_inputs = Vec::new();
			for i in 0..n_xor_terms {
				let wire = witnesses[base + i];
				if all_shifted {
					// Apply shift to all terms (vary shift amounts more diversely)
					let shift_amounts = [
						1, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 2, 4, 6, 8, 10,
						12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32,
					];
					let shift_amount = shift_amounts[i % shift_amounts.len()];
					let shifted_wire = builder.shr(wire, shift_amount as u32);
					xor_inputs.push(shifted_wire);
				} else {
					// No shift
					xor_inputs.push(wire);
				}
			}

			let xor_result = builder.bxor_multi(&xor_inputs);

			// AND with another witness
			let b = witnesses[base + n_xor_terms];
			builder.band(xor_result, b);
		}

		let circuit = builder.build();
		let cs = circuit.constraint_system().clone();
		let (_verifier, prover) = setup(cs, 1).unwrap();

		// Create witness
		let mut filler = circuit.new_witness_filler();
		for i in 0..1000 * (n_xor_terms + 2) {
			filler[witnesses[i]] = Word(0x123456789ABCDEFu64.wrapping_add(i as u64));
		}
		circuit.populate_wire_witness(&mut filler).unwrap();
		let witness = filler.into_value_vec();

		// Time multiple runs
		let start = Instant::now();
		let iterations = 20;
		for _ in 0..iterations {
			let mut transcript = ProverTranscript::new(StdChallenger::default());
			prover.prove(witness.clone(), &mut transcript).unwrap();
		}
		let avg_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;

		let n_shifted = if all_shifted { n_xor_terms } else { 0 };
		results.push((n_shifted, avg_time_ms));
	}

	results
}

fn print_final_analysis() {
	// Measure XOR packing costs dynamically
	let xor_times = measure_xor_costs(false);
	let baseline_1xor = xor_times[0].1;

	// Measure shifted XOR packing costs dynamically
	let shifted_xor_times = measure_xor_costs(true);
	let baseline_1shifted_xor = shifted_xor_times[0].1;

	// Measure shift costs dynamically (for comparison)
	let shift_times = measure_shift_costs();
	let _baseline_no_shift = shift_times[0].1;

	println!("XOR Packing Cost Analysis:");
	println!("n_xor | time(ms) | relative | cost_per_xor");
	println!("------|----------|----------|-------------");
	for &(n, time) in &xor_times {
		let relative = time / baseline_1xor;
		let cost_per_additional_xor = if n > 1 {
			(time - baseline_1xor) / baseline_1xor / (n as f64 - 1.0)
		} else {
			0.0
		};
		println!("{:5} | {:8.1} | {:8.3} | {:11.4}", n, time, relative, cost_per_additional_xor);
	}

	// Calculate linear regression for f(n) = a*n + b
	let mut sum_n = 0.0;
	let mut sum_time = 0.0;
	let mut sum_n_time = 0.0;
	let mut sum_n_squared = 0.0;
	let count = xor_times.len() as f64;

	for &(n, time) in &xor_times {
		let n_f = n as f64;
		sum_n += n_f;
		sum_time += time;
		sum_n_time += n_f * time;
		sum_n_squared += n_f * n_f;
	}

	// Linear regression: time = a*n + b
	let a = (count * sum_n_time - sum_n * sum_time) / (count * sum_n_squared - sum_n * sum_n);
	let b = (sum_time - a * sum_n) / count;

	println!("\nLinear regression: time(ms) = {:.3}*n + {:.3}", a, b);
	println!("Target formula: cost(n) = 1 + (n-1) × xor_cost");
	println!(
		"From regression: time(n) = {:.3} + {:.3}*(n-1) when baseline = {:.3}",
		b + a,
		a,
		baseline_1xor
	);
	println!(
		"Therefore: xor_in_operand_cost = {:.6} (relative cost per additional XOR)",
		a / baseline_1xor
	);

	// Check linearity for XOR costs
	let r_squared = {
		let mut ss_tot = 0.0;
		let mut ss_res = 0.0;
		let mean_time = sum_time / count;
		for &(n, time) in &xor_times {
			let predicted = a * n as f64 + b;
			ss_tot += (time - mean_time).powi(2);
			ss_res += (time - predicted).powi(2);
		}
		1.0 - (ss_res / ss_tot)
	};
	println!(
		"R² = {:.4} (linearity check: {} linear)",
		r_squared,
		if r_squared > 0.95 {
			"GOOD -"
		} else {
			"WARNING - NOT"
		}
	);

	// Analyze shifted XOR costs
	println!("\nShifted XOR Packing Cost Analysis:");
	println!("n_xor | time(ms) | relative | cost_per_xor");
	println!("------|----------|----------|-------------");
	for &(n, time) in &shifted_xor_times {
		let relative = time / baseline_1shifted_xor;
		let cost_per_additional_xor = if n > 1 {
			(time - baseline_1shifted_xor) / baseline_1shifted_xor / (n as f64 - 1.0)
		} else {
			0.0
		};
		println!("{:5} | {:8.1} | {:8.3} | {:11.4}", n, time, relative, cost_per_additional_xor);
	}

	// Calculate linear regression for shifted XOR costs
	let mut sum_n_shifted = 0.0;
	let mut sum_time_shifted = 0.0;
	let mut sum_n_time_shifted = 0.0;
	let mut sum_n_squared_shifted = 0.0;
	let count_shifted = shifted_xor_times.len() as f64;

	for &(n, time) in &shifted_xor_times {
		let n_f = n as f64;
		sum_n_shifted += n_f;
		sum_time_shifted += time;
		sum_n_time_shifted += n_f * time;
		sum_n_squared_shifted += n_f * n_f;
	}

	let a_shifted = (count_shifted * sum_n_time_shifted - sum_n_shifted * sum_time_shifted)
		/ (count_shifted * sum_n_squared_shifted - sum_n_shifted * sum_n_shifted);
	let b_shifted = (sum_time_shifted - a_shifted * sum_n_shifted) / count_shifted;

	println!("\nShifted XOR linear regression: time(ms) = {:.3}*n + {:.3}", a_shifted, b_shifted);
	println!(
		"This means each additional SHIFTED XOR adds ~{:.3}ms ({:.1}% of baseline)",
		a_shifted,
		(a_shifted / baseline_1shifted_xor) * 100.0
	);

	// Check linearity for shifted XOR costs
	let r_squared_shifted = {
		let mut ss_tot = 0.0;
		let mut ss_res = 0.0;
		let mean_time = sum_time_shifted / count_shifted;
		for &(n, time) in &shifted_xor_times {
			let predicted = a_shifted * n as f64 + b_shifted;
			ss_tot += (time - mean_time).powi(2);
			ss_res += (time - predicted).powi(2);
		}
		1.0 - (ss_res / ss_tot)
	};
	println!(
		"R² = {:.4} (linearity check: {} linear)",
		r_squared_shifted,
		if r_squared_shifted > 0.95 {
			"GOOD -"
		} else {
			"WARNING - NOT"
		}
	);

	// Analyze shift costs (simple comparison)
	let none_shifted = shift_times[0].1; // 0 shifts
	let all_shifted = shift_times[1].1; // 32 shifts
	let shift_overhead = all_shifted - none_shifted;
	let shift_cost_per_term = shift_overhead / 32.0 / none_shifted; // Relative cost per shift

	println!("\nShift Cost Analysis (32 XORs):");
	println!("  None shifted: {:.2}ms", none_shifted);
	println!("  All shifted:  {:.2}ms", all_shifted);
	println!(
		"  Overhead:     {:.2}ms ({:.1}%)",
		shift_overhead,
		(shift_overhead / none_shifted) * 100.0
	);
	println!("  Per shift:    {:.4} relative cost per shifted term", shift_cost_per_term);

	let mul_cost = 5.2; // Will be calculated from actual benchmarks later
	println!("```rust");
	println!("#[derive(Debug, Clone)]");
	println!("pub struct CostModel {{");
	println!("    pub and_cost: f64,");
	println!("    pub mul_cost: f64,");
	println!("    pub xor_in_operand_cost: f64,");
	println!("    pub shifted_xor_in_operand_cost: f64,");
	println!("}}");
	println!();
	println!("impl Default for CostModel {{");
	println!("    fn default() -> Self {{");
	println!("        Self {{");
	println!("            and_cost: 1.0,                    // baseline AND constraint");
	println!("            mul_cost: {:.1},                    // relative to and_cost", mul_cost);
	println!(
		"            xor_in_operand_cost: {:.6},        // cost = 1 + n × {:.6}, where n = packed XOR count",
		a / baseline_1xor,
		a / baseline_1xor
	);
	println!(
		"            shifted_xor_in_operand_cost: {:.6}, // cost = 1 + n × {:.6}, where n = packed SHIFTED XOR count",
		a_shifted / baseline_1shifted_xor,
		a_shifted / baseline_1shifted_xor
	);
	println!("        }}");
	println!("    }}");
	println!("}}");
	println!("```");

	println!("\n{}", "=".repeat(80));
}

criterion_group!(
	benches,
	bench_and_constraints,
	bench_mul_constraints,
	bench_xor_packing // bench_shift_pinning  // TODO: Uncomment when ready
);

// Custom main to add final analysis after benchmarks
fn main() {
	benches();
	criterion::Criterion::default()
		.configure_from_args()
		.final_summary();
	print_final_analysis();
}

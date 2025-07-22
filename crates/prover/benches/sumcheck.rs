// Copyright 2025 Irreducible Inc.

use binius_field::arch::OptimalPackedB128;
use binius_math::{inner_product::inner_product_par, test_utils::random_field_buffer};
use binius_prover::protocols::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, prove_single,
};
use binius_transcript::ProverTranscript;
use binius_verifier::config::StdChallenger;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, prelude::StdRng};

type P = OptimalPackedB128;

fn bench_sumcheck_prove(c: &mut Criterion) {
	let mut group = c.benchmark_group("sumcheck/bivariate_product");

	// Test different sizes of multilinear polynomials
	for n_vars in [12, 16, 20] {
		// Each multilinear has 2^n_vars elements, and we have 2 multilinears
		// So total elements processed is 2 * 2^n_vars = 2^(n_vars+1)
		group.throughput(Throughput::Elements(2u64 << n_vars));

		group.bench_function(format!("n_vars={n_vars}"), |b| {
			// Setup phase - prepare the multilinears and compute the sum
			let mut rng = StdRng::seed_from_u64(0);
			let multilinear_a = random_field_buffer::<P>(&mut rng, n_vars);
			let multilinear_b = random_field_buffer::<P>(&mut rng, n_vars);
			let sum = inner_product_par(&multilinear_a, &multilinear_b);

			let mut transcript = ProverTranscript::new(StdChallenger::default());

			// Benchmark only the proving phase
			b.iter(|| {
				let prover = BivariateProductSumcheckProver::new(
					[multilinear_a.clone(), multilinear_b.clone()],
					sum,
				)
				.unwrap();

				prove_single(prover, &mut transcript).unwrap()
			});
		});
	}

	group.finish();
}

criterion_group!(sumcheck, bench_sumcheck_prove);
criterion_main!(sumcheck);

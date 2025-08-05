// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, PackedSubfield, arch::OptimalPackedB128};
use binius_math::test_utils::random_field_buffer;
use binius_prover::pcs::prover::fold_1b_rows;
use binius_utils::checked_arithmetics::log2_strict_usize;
use binius_verifier::config::{B1, B128};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

fn bench_fold_1b_rows(c: &mut Criterion) {
	let mut group = c.benchmark_group("pcs/fold_1b_rows");

	type P = OptimalPackedB128;

	let log_bits = log2_strict_usize(B128::N_BITS);
	for log_len in [12, 16, 20] {
		const LOG_BITS_PER_BYTE: usize = 3;
		group.throughput(Throughput::Bytes((1 << (log_len + log_bits - LOG_BITS_PER_BYTE)) as u64));
		group.bench_function(format!("log_len={log_len}"), |b| {
			let mut rng = StdRng::seed_from_u64(0);

			let mat = random_field_buffer::<PackedSubfield<P, B1>>(&mut rng, log_len + log_bits);
			let vec = random_field_buffer::<P>(&mut rng, log_len);

			b.iter(|| fold_1b_rows(&mat, &vec));
		});
	}

	group.finish();
}

criterion_group!(pcs, bench_fold_1b_rows);
criterion_main!(pcs);

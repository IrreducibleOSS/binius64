// Copyright 2025 Irreducible Inc.

use std::array;

use binius_field::{BinaryField128bGhash as Ghash, Field, Random};
use binius_math::batch_invert::batch_invert;
use criterion::{
	BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use rand::{SeedableRng, rngs::StdRng};

fn bench_batch_invert(c: &mut Criterion) {
	let mut group = c.benchmark_group("Batch Invert Throughput");
	let mut rng = StdRng::seed_from_u64(0);

	fn bench_for_size<const N: usize, const N2: usize>(
		group: &mut BenchmarkGroup<'_, WallTime>,
		rng: &mut StdRng,
	) {
		group.throughput(Throughput::Elements(N as u64));
		let mut elements: [Ghash; N] = array::from_fn(|_| <Ghash as Random>::random(&mut *rng));
		let scratchpad = &mut [Ghash::ZERO; N2];
		group.bench_function(format!("{N}"), |b| {
			b.iter(|| {
				batch_invert::<N>(&mut elements, scratchpad);
			})
		});
	}

	bench_for_size::<2, 4>(&mut group, &mut rng);
	bench_for_size::<4, 8>(&mut group, &mut rng);
	bench_for_size::<8, 16>(&mut group, &mut rng);
	bench_for_size::<16, 32>(&mut group, &mut rng);
	bench_for_size::<32, 64>(&mut group, &mut rng);
	bench_for_size::<64, 128>(&mut group, &mut rng);
	bench_for_size::<128, 256>(&mut group, &mut rng);
	bench_for_size::<256, 512>(&mut group, &mut rng);

	group.finish();
}

criterion_group!(batch_invert_bench, bench_batch_invert);
criterion_main!(batch_invert_bench);

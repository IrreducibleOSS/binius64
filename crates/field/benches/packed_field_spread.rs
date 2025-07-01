// Copyright 2024-2025 Irreducible Inc.

use std::array;

use binius_field::{
	PackedBinaryField4x16b, PackedBinaryField8x8b, PackedBinaryField8x16b, PackedBinaryField16x8b,
	PackedBinaryField16x16b, PackedBinaryField32x8b, PackedBinaryField32x16b,
	PackedBinaryField64x1b, PackedBinaryField64x8b, PackedBinaryField128x1b,
	PackedBinaryField256x1b, PackedBinaryField512x1b, PackedField,
};
use criterion::{
	BenchmarkGroup, Throughput, criterion_group, criterion_main, measurement::WallTime,
};

const BATCH_SIZE: usize = 32;

#[allow(clippy::modulo_one)]
fn benchmark_get_impl<P: PackedField>(
	group: &mut BenchmarkGroup<'_, WallTime>,
	id: &str,
	log_block_len: usize,
) {
	let mut rng = rand::rng();
	let values = array::from_fn::<_, BATCH_SIZE, _>(|_| P::random(&mut rng));

	group.throughput(Throughput::Elements(P::WIDTH as _));
	group.bench_function(format!("{id}/{log_block_len}"), |b| {
		b.iter(|| {
			array::from_fn::<_, BATCH_SIZE, _>(|j| {
				values[j].spread(log_block_len, (j % 1) << (P::LOG_WIDTH - log_block_len))
			})
		})
	});
}

fn packed_64(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("packed_64");

	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 0);
	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 1);
	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 2);
	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 3);
	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 4);
	benchmark_get_impl::<PackedBinaryField64x1b>(&mut group, "64x1b", 5);

	benchmark_get_impl::<PackedBinaryField8x8b>(&mut group, "8x8b", 0);
	benchmark_get_impl::<PackedBinaryField8x8b>(&mut group, "8x8b", 1);
	benchmark_get_impl::<PackedBinaryField8x8b>(&mut group, "8x8b", 2);
	benchmark_get_impl::<PackedBinaryField8x8b>(&mut group, "8x8b", 3);

	benchmark_get_impl::<PackedBinaryField4x16b>(&mut group, "4x16b", 0);
	benchmark_get_impl::<PackedBinaryField4x16b>(&mut group, "4x16b", 1);
	benchmark_get_impl::<PackedBinaryField4x16b>(&mut group, "4x16b", 2);
}

fn packed_128(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("packed_128");

	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 0);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 1);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 2);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 3);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 4);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 5);
	benchmark_get_impl::<PackedBinaryField128x1b>(&mut group, "128x1b", 6);

	benchmark_get_impl::<PackedBinaryField16x8b>(&mut group, "16x8b", 0);
	benchmark_get_impl::<PackedBinaryField16x8b>(&mut group, "16x8b", 1);
	benchmark_get_impl::<PackedBinaryField16x8b>(&mut group, "16x8b", 2);
	benchmark_get_impl::<PackedBinaryField16x8b>(&mut group, "16x8b", 3);
	benchmark_get_impl::<PackedBinaryField16x8b>(&mut group, "16x8b", 4);

	benchmark_get_impl::<PackedBinaryField8x16b>(&mut group, "8x16b", 0);
	benchmark_get_impl::<PackedBinaryField8x16b>(&mut group, "8x16b", 1);
	benchmark_get_impl::<PackedBinaryField8x16b>(&mut group, "8x16b", 2);
	benchmark_get_impl::<PackedBinaryField8x16b>(&mut group, "8x16b", 3);
}

fn packed_256(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("packed_256");

	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 0);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 1);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 2);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 3);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 4);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 5);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 6);
	benchmark_get_impl::<PackedBinaryField256x1b>(&mut group, "256x1b", 7);

	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 0);
	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 1);
	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 2);
	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 3);
	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 4);
	benchmark_get_impl::<PackedBinaryField32x8b>(&mut group, "32x8b", 5);

	benchmark_get_impl::<PackedBinaryField16x16b>(&mut group, "16x16b", 0);
	benchmark_get_impl::<PackedBinaryField16x16b>(&mut group, "16x16b", 1);
	benchmark_get_impl::<PackedBinaryField16x16b>(&mut group, "16x16b", 2);
	benchmark_get_impl::<PackedBinaryField16x16b>(&mut group, "16x16b", 3);
	benchmark_get_impl::<PackedBinaryField16x16b>(&mut group, "16x16b", 4);
}

fn packed_512(c: &mut criterion::Criterion) {
	let mut group = c.benchmark_group("packed_512");

	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 0);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 1);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 2);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 3);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 4);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 5);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 6);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 7);
	benchmark_get_impl::<PackedBinaryField512x1b>(&mut group, "512x1b", 8);

	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 0);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 1);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 2);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 3);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 4);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 5);
	benchmark_get_impl::<PackedBinaryField64x8b>(&mut group, "64x8b", 6);

	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 0);
	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 1);
	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 2);
	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 3);
	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 4);
	benchmark_get_impl::<PackedBinaryField32x16b>(&mut group, "32x16b", 5);
}

criterion_group!(spread, packed_64, packed_128, packed_256, packed_512);
criterion_main!(spread);

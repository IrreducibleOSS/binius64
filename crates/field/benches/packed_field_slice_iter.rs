// Copyright 2025 Irreducible Inc.

use std::iter::repeat_with;

use binius_field::{
	PackedBinaryField1x128b, PackedBinaryField2x64b, PackedBinaryField2x128b,
	PackedBinaryField4x32b, PackedBinaryField4x64b, PackedBinaryField4x128b,
	PackedBinaryField8x32b, PackedBinaryField8x64b, PackedBinaryField16x8b,
	PackedBinaryField16x32b, PackedBinaryField32x8b, PackedBinaryField64x8b,
	PackedBinaryField128x1b, PackedBinaryField256x1b, PackedBinaryField512x1b, PackedField,
	packed::iter_packed_slice_with_offset,
};
use criterion::{
	BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};

fn benchmark_iter_impl<P: PackedField>(
	group: &mut BenchmarkGroup<'_, WallTime>,
	id: &str,
	len: usize,
	skip: Option<usize>,
) {
	let mut rng = rand::rng();
	let values = repeat_with(|| P::random(&mut rng))
		.take(len)
		.collect::<Vec<P>>();

	group.throughput(Throughput::Elements(((len - skip.unwrap_or_default()) * P::WIDTH) as _));

	if let Some(skip) = skip {
		group.bench_function(id, |b| {
			b.iter(|| iter_packed_slice_with_offset(&values, skip * P::WIDTH).sum::<P::Scalar>())
		});
	} else {
		group
			.bench_function(id, |b| b.iter(|| PackedField::iter_slice(&values).sum::<P::Scalar>()));
	}
}
const BATCH_SIZE: usize = 1 << 15;

macro_rules! benchmark_from_fn {
	($field:ty, $g:ident) => {
		benchmark_iter_impl::<$field>(
			&mut $g,
			&format!("{}/iter_begin", stringify!($field)),
			BATCH_SIZE / 2,
			None,
		);
		benchmark_iter_impl::<$field>(
			&mut $g,
			&format!("{}/iter_offset", stringify!($field)),
			BATCH_SIZE,
			Some(BATCH_SIZE / 2),
		);
	};
}

fn packed_128(c: &mut Criterion) {
	let mut group = c.benchmark_group("packed_128");

	benchmark_from_fn!(PackedBinaryField128x1b, group);
	benchmark_from_fn!(PackedBinaryField16x8b, group);
	benchmark_from_fn!(PackedBinaryField4x32b, group);
	benchmark_from_fn!(PackedBinaryField2x64b, group);
	benchmark_from_fn!(PackedBinaryField1x128b, group);
}

fn packed_256(c: &mut Criterion) {
	let mut group = c.benchmark_group("packed_256");

	benchmark_from_fn!(PackedBinaryField256x1b, group);
	benchmark_from_fn!(PackedBinaryField32x8b, group);
	benchmark_from_fn!(PackedBinaryField8x32b, group);
	benchmark_from_fn!(PackedBinaryField4x64b, group);
	benchmark_from_fn!(PackedBinaryField2x128b, group);
}

fn packed_512(c: &mut Criterion) {
	let mut group = c.benchmark_group("packed_512");

	benchmark_from_fn!(PackedBinaryField512x1b, group);
	benchmark_from_fn!(PackedBinaryField64x8b, group);
	benchmark_from_fn!(PackedBinaryField16x32b, group);
	benchmark_from_fn!(PackedBinaryField8x64b, group);
	benchmark_from_fn!(PackedBinaryField4x128b, group);
}

criterion_group!(iterate, packed_128, packed_256, packed_512);
criterion_main!(iterate);

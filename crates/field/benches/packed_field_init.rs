// Copyright 2024-2025 Irreducible Inc.

use std::array;

use binius_field::{
	PackedField, Random,
	arch::{byte_sliced::*, packed_128::*, packed_256::*, packed_512::*},
};
use criterion::{
	BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};

const BATCH_SIZE: usize = 32;

fn benchmark_get_impl<P: PackedField>(group: &mut BenchmarkGroup<'_, WallTime>, id: &str) {
	let mut rng = rand::rng();
	let values = array::from_fn::<_, BATCH_SIZE, _>(|_| {
		(0..P::WIDTH)
			.map(|_| P::Scalar::random(&mut rng))
			.collect::<Vec<_>>()
	});

	group.throughput(Throughput::Elements(P::WIDTH as _));
	group.bench_function(id, |b| {
		b.iter(|| {
			array::from_fn::<_, BATCH_SIZE, _>(|j| {
				let values = &values[j];
				P::from_fn(|i| values[i])
			})
		})
	});
}

macro_rules! benchmark_from_fn {
	($field:ty, $g:ident) => {
		benchmark_get_impl::<$field>(&mut $g, &format!("{}/from_fn", stringify!($field)));
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

fn byte_sliced_128(c: &mut Criterion) {
	let mut group = c.benchmark_group("bytes_sliced_128");

	benchmark_from_fn!(ByteSlicedAES16x128b, group);
	benchmark_from_fn!(ByteSlicedAES16x64b, group);
	benchmark_from_fn!(ByteSlicedAES2x16x64b, group);
	benchmark_from_fn!(ByteSlicedAES16x32b, group);
	benchmark_from_fn!(ByteSlicedAES4x16x32b, group);
	benchmark_from_fn!(ByteSlicedAES16x16b, group);
	benchmark_from_fn!(ByteSlicedAES8x16x16b, group);
	benchmark_from_fn!(ByteSlicedAES16x8b, group);
	benchmark_from_fn!(ByteSlicedAES16x16x8b, group);
	benchmark_from_fn!(ByteSliced16x128x1b, group);
}

fn byte_sliced_256(c: &mut Criterion) {
	let mut group = c.benchmark_group("bytes_sliced_256");

	benchmark_from_fn!(ByteSlicedAES32x128b, group);
	benchmark_from_fn!(ByteSlicedAES32x64b, group);
	benchmark_from_fn!(ByteSlicedAES2x32x64b, group);
	benchmark_from_fn!(ByteSlicedAES32x32b, group);
	benchmark_from_fn!(ByteSlicedAES4x32x32b, group);
	benchmark_from_fn!(ByteSlicedAES32x16b, group);
	benchmark_from_fn!(ByteSlicedAES8x32x16b, group);
	benchmark_from_fn!(ByteSlicedAES32x8b, group);
	benchmark_from_fn!(ByteSlicedAES16x32x8b, group);
	benchmark_from_fn!(ByteSliced16x256x1b, group);
}

fn byte_sliced_512(c: &mut Criterion) {
	let mut group = c.benchmark_group("bytes_sliced_512");

	benchmark_from_fn!(ByteSlicedAES64x128b, group);
	benchmark_from_fn!(ByteSlicedAES64x64b, group);
	benchmark_from_fn!(ByteSlicedAES2x64x64b, group);
	benchmark_from_fn!(ByteSlicedAES64x32b, group);
	benchmark_from_fn!(ByteSlicedAES4x64x32b, group);
	benchmark_from_fn!(ByteSlicedAES64x16b, group);
	benchmark_from_fn!(ByteSlicedAES8x64x16b, group);
	benchmark_from_fn!(ByteSlicedAES64x8b, group);
	benchmark_from_fn!(ByteSlicedAES16x64x8b, group);
	benchmark_from_fn!(ByteSliced16x512x1b, group);
}

criterion_group!(
	initialization,
	packed_128,
	packed_256,
	packed_512,
	byte_sliced_128,
	byte_sliced_256,
	byte_sliced_512
);
criterion_main!(initialization);

// Copyright 2025 Irreducible Inc.

use std::hint::black_box;

use binius_field::{PackedField, Random, arch::byte_sliced::*};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

macro_rules! bench_transform_to_byte_sliced {
	($byte_sliced:ty, $group:ident) => {{
		let mut rng = rand::rng();
		let original = std::array::from_fn(|_| Random::random(&mut rng));

		$group.throughput(Throughput::Elements(<$byte_sliced>::WIDTH as _));
		$group.bench_function(stringify!($byte_sliced), |b| {
			b.iter(|| <$byte_sliced>::transpose_from(black_box(&original)))
		});
	}};
}

macro_rules! bench_transform_from_byte_sliced {
	($byte_sliced:ty, $group:ident) => {{
		let mut rng = rand::rng();
		let original = <$byte_sliced>::random(&mut rng);
		let mut target = std::array::from_fn(|_| PackedField::zero());

		$group.throughput(Throughput::Elements(<$byte_sliced>::WIDTH as _));
		$group.bench_function(stringify!($byte_sliced), |b| {
			b.iter(|| {
				black_box(&original).transpose_to(&mut target);
				target
			})
		});
	}};
}

fn transpose_to_byte_sliced(c: &mut Criterion) {
	let mut group = c.benchmark_group("transpose_to_byte_sliced");

	bench_transform_to_byte_sliced!(ByteSlicedAES16x128b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES16x64b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES16x32b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES16x16b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES16x8b, group);

	bench_transform_to_byte_sliced!(ByteSlicedAES32x128b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES32x64b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES32x32b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES32x16b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES32x8b, group);

	bench_transform_to_byte_sliced!(ByteSlicedAES64x128b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES64x64b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES64x32b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES64x16b, group);
	bench_transform_to_byte_sliced!(ByteSlicedAES64x8b, group);
}

fn transpose_from_byte_sliced(c: &mut Criterion) {
	let mut group = c.benchmark_group("transpose_from_byte_sliced");

	bench_transform_from_byte_sliced!(ByteSlicedAES16x128b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES16x64b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES16x32b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES16x16b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES16x8b, group);

	bench_transform_from_byte_sliced!(ByteSlicedAES32x128b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES32x64b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES32x32b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES32x16b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES32x8b, group);

	bench_transform_from_byte_sliced!(ByteSlicedAES64x128b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES64x64b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES64x32b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES64x16b, group);
	bench_transform_from_byte_sliced!(ByteSlicedAES64x8b, group);
}

criterion_group!(byte_sliced, transpose_to_byte_sliced, transpose_from_byte_sliced,);
criterion_main!(byte_sliced);

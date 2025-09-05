// Copyright 2025 Irreducible Inc.

use std::{array, mem::MaybeUninit};

use binius_field::{BinaryField128bGhash as Ghash, Field, Random};
use binius_prover::hash::{
	parallel_digest::{MultiDigest, ParallelDigest, ParallelMultidigestImpl},
	vision_4::{
		digest::VisionHasherMultiDigest as VisionHasherMultiDigest_4,
		permutation::batch_permutation as parallel_permutation_4,
	},
	vision_6::{
		digest::VisionHasherMultiDigest as VisionHasherMultiDigest_6,
		permutation::parallel_permutation as parallel_permutation_6,
	},
};
use binius_utils::rayon::prelude::*;
use binius_verifier::hash::vision_4::digest::VisionHasherDigest;
use criterion::{
	BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use digest::Digest;
use rand::{RngCore, rngs::ThreadRng};

fn bench_parallel_permutation_for_size<const N: usize, const MN: usize>(
	group: &mut BenchmarkGroup<WallTime>,
	rng: &mut ThreadRng,
	permutation: fn(&mut [Ghash; MN], &mut [Ghash]),
	scratchpad: &mut [Ghash],
) {
	const BYTES_PER_ELEMENT: u64 = 16;
	group.throughput(Throughput::Bytes(MN as u64 * BYTES_PER_ELEMENT));
	let mut parallel_states: [Ghash; MN] = array::from_fn(|_| Ghash::random(&mut *rng));
	group.bench_function(format!("N={N}"), |b| {
		b.iter(|| {
			permutation(&mut parallel_states, scratchpad);
		})
	});
}

macro_rules! bench_parallel_permutation_sizes_4 {
	($group:expr, $rng:expr, $permutation:ident, $scratchpad:expr, $m:expr, $($n:expr),*) => {
		$(
			bench_parallel_permutation_for_size::<$n, { $n * $m }>(
				$group,
				$rng,
				$permutation::<$n, { $n * $m }>,
				$scratchpad,
			);
		)*
	};
}

macro_rules! bench_parallel_permutation_sizes_6 {
	($group:expr, $rng:expr, $permutation:ident, $scratchpad:expr, $m:expr, $($n:expr),*) => {
		$(
			bench_parallel_permutation_for_size::<$n, { $n * $m }>(
				$group,
				$rng,
				$permutation::<$n, { $n * $m }, { $n * $m / 3 }>,
				$scratchpad,
			);
		)*
	};
}

fn bench_parallel_permutation_4(c: &mut Criterion) {
	const M: usize = 4;
	let mut group = c.benchmark_group("Parallel Permutation 4");
	let mut rng = rand::rng();

	let scratchpad = &mut [Ghash::ZERO; 256 * M * 2];
	bench_parallel_permutation_sizes_4!(
		&mut group,
		&mut rng,
		parallel_permutation_4,
		scratchpad,
		M,
		2,
		4,
		8,
		16,
		32,
		64,
		128,
		256
	);

	group.finish();
}

fn bench_parallel_permutation_6(c: &mut Criterion) {
	const M: usize = 6;
	let mut group = c.benchmark_group("Parallel Permutation 6");
	let mut rng = rand::rng();

	let scratchpad = &mut [Ghash::ZERO; 256 * M * 2];
	bench_parallel_permutation_sizes_6!(
		&mut group,
		&mut rng,
		parallel_permutation_6,
		scratchpad,
		M,
		2,
		4,
		8,
		16,
		32,
		64,
		128,
		256
	);

	group.finish();
}

fn bench_hash_vision_4(c: &mut Criterion) {
	const M: usize = 4;
	let mut group = c.benchmark_group("Hash 4");
	let mut rng = rand::rng();

	const BYTE_COUNT: usize = 1 << 20;
	let mut data = vec![0u8; BYTE_COUNT];
	rng.fill_bytes(&mut data);

	group.throughput(Throughput::Bytes(BYTE_COUNT as u64));

	group.bench_function("SingleDigest", |bench| {
		bench.iter(|| <VisionHasherDigest as Digest>::digest(data.clone()))
	});

	// Number of parallel hashing instances
	// Larger powers of 2 perform better.
	const N: usize = 128;

	group.bench_function("MultiDigest", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];

			VisionHasherMultiDigest_4::<N, { N * M }>::digest(
				array::from_fn(|i| &data[i * BYTE_COUNT / N..(i + 1) * BYTE_COUNT / N]),
				&mut out,
			);
			out
		})
	});

	group.bench_function("ParallelMultiDigest", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];
			let hasher =
				ParallelMultidigestImpl::<VisionHasherMultiDigest_4<N, { N * M }>, N>::new();

			hasher.digest(
				(0..N).into_par_iter().map(|i| {
					let start = i * BYTE_COUNT / N;
					let end = (i + 1) * BYTE_COUNT / N;
					std::iter::once(&data[start..end])
				}),
				&mut out,
			);
			out
		})
	});

	group.finish()
}

fn bench_hash_vision_6(c: &mut Criterion) {
	const M: usize = 6;
	let mut group = c.benchmark_group("Hash 6");
	let mut rng = rand::rng();

	const BYTE_COUNT: usize = 1 << 20;
	let mut data = vec![0u8; BYTE_COUNT];
	rng.fill_bytes(&mut data);

	group.throughput(Throughput::Bytes(BYTE_COUNT as u64));

	group.bench_function("SingleDigest", |bench| {
		bench.iter(|| <VisionHasherDigest as Digest>::digest(data.clone()))
	});

	// Number of parallel hashing instances
	// Larger powers of 2 perform better.
	const N: usize = 128;

	group.bench_function("MultiDigest", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];

			VisionHasherMultiDigest_6::<N, { N * M }, { N * M / 3 }>::digest(
				array::from_fn(|i| &data[i * BYTE_COUNT / N..(i + 1) * BYTE_COUNT / N]),
				&mut out,
			);
			out
		})
	});

	group.bench_function("ParallelMultiDigest", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];
			let hasher = ParallelMultidigestImpl::<
				VisionHasherMultiDigest_6<N, { N * M }, { N * M / 3 }>,
				N,
			>::new();

			hasher.digest(
				(0..N).into_par_iter().map(|i| {
					let start = i * BYTE_COUNT / N;
					let end = (i + 1) * BYTE_COUNT / N;
					std::iter::once(&data[start..end])
				}),
				&mut out,
			);
			out
		})
	});

	group.finish()
}

criterion_group!(
	parallel_permutation_bench,
	bench_parallel_permutation_4,
	bench_parallel_permutation_6
);
criterion_group!(hash_vision_bench, bench_hash_vision_4, bench_hash_vision_6);
criterion_main!(parallel_permutation_bench, hash_vision_bench);

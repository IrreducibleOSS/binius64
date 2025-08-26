use std::{array, hint::black_box, mem::MaybeUninit};

use binius_field::{BinaryField128bGhash as Ghash, Field, Random};
use binius_prover::hash::{
	VisionHasherMultiDigest,
	batch_invert::batch_invert_scratchpad_generic,
	parallel_digest::{MultiDigest, ParallelDigest, ParallelMultidigestImpl},
	vision_parallel::flattened_parallel_permutation,
};
use binius_utils::rayon::prelude::*;
use binius_verifier::hash::vision::{constants::M, digest::VisionHasherDigest};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use digest::Digest;
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn bench_batch_invert(c: &mut Criterion) {
	let mut group = c.benchmark_group("Batch Invert Throughput");
	let mut rng = StdRng::seed_from_u64(0);

	const ITERATIONS: usize = 1000;

	// 1 state of 4 elements
	let mut state_4: [Ghash; 4] = std::array::from_fn(|_| <Ghash as Random>::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 4));
	group.bench_function("batch_invert_4_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 7];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<4>(black_box(&mut state_4), scratchpad);
				state_4[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 2 states of 4 elements each
	let mut state_8: [Ghash; 8] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 8));
	group.bench_function("batch_invert_8_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 15];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<8>(black_box(&mut state_8), scratchpad);
				state_8[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 4 states of 4 elements each
	let mut state_16: [Ghash; 16] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 16));
	group.bench_function("batch_invert_16_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 31];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<16>(black_box(&mut state_16), scratchpad);
				state_16[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 8 states of 4 elements each
	let mut state_32: [Ghash; 32] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 32));
	group.bench_function("batch_invert_32_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 63];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<32>(black_box(&mut state_32), scratchpad);
				state_32[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 16 states of 4 elements each
	let mut state_64: [Ghash; 64] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 64));
	group.bench_function("batch_invert_64_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 127];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<64>(black_box(&mut state_64), scratchpad);
				state_64[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 32 states of 4 elements each
	let mut state_128: [Ghash; 128] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 128));
	group.bench_function("batch_invert_128_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 255];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<128>(black_box(&mut state_128), scratchpad);
				state_128[0] = Ghash::random(&mut rng);
			}
		})
	});

	// 64 states of 4 elements each
	let mut state_256: [Ghash; 256] = std::array::from_fn(|_| Ghash::random(&mut rng));
	group.throughput(Throughput::Elements(ITERATIONS as u64 * 256));
	group.bench_function("batch_invert_256_scratchpad", |b| {
		b.iter(|| {
			let scratchpad = &mut [Ghash::ZERO; 511];
			for _ in 0..ITERATIONS {
				batch_invert_scratchpad_generic::<256>(black_box(&mut state_256), scratchpad);
				state_256[0] = Ghash::random(&mut rng);
			}
		})
	});

	group.finish();
}

fn bench_parallel_permutation(c: &mut Criterion) {
	let mut group = c.benchmark_group("Parallel Permutation Throughput");
	let mut rng = StdRng::seed_from_u64(0);

	const ITERATIONS: usize = 100;

	// Benchmark parallel permutation N=1
	let elements_hashed = ITERATIONS as u64 * M as u64;
	group.throughput(Throughput::Elements(elements_hashed * 16));
	let mut parallel_states_1: [Ghash; M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * M }];
	group.bench_function("parallel_permutation_N1", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<1, { M }>(&mut parallel_states_1, scratchpad);
			}
		})
	});

	// Benchmark parallel permutation N=2
	let elements_hashed = ITERATIONS as u64 * 2 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_2: [Ghash; 2 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 2 * M }];
	group.bench_function("parallel_permutation_N2", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<2, { 2 * M }>(&mut parallel_states_2, scratchpad);
			}
		})
	});

	// Benchmark parallel permutation N=4
	let elements_hashed = ITERATIONS as u64 * 4 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_4: [Ghash; 4 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 4 * M }];
	group.bench_function("parallel_permutation_N4", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<4, { 4 * M }>(&mut parallel_states_4, scratchpad);
			}
		})
	});

	// Benchmark parallel permutation N=8
	let elements_hashed = ITERATIONS as u64 * 8 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_8: [Ghash; 8 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 8 * M }];
	group.bench_function("parallel_permutation_N8", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<8, { 8 * M }>(&mut parallel_states_8, scratchpad);
			}
		})
	});

	// Benchmark parallel permutation N=16
	let elements_hashed = ITERATIONS as u64 * 16 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_16: [Ghash; 16 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 16 * M }];
	group.bench_function("parallel_permutation_N16", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<16, { 16 * M }>(
					&mut parallel_states_16,
					scratchpad,
				);
			}
		})
	});

	// Benchmark parallel permutation N=32
	let elements_hashed = ITERATIONS as u64 * 32 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_32: [Ghash; 32 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 32 * M }];
	group.bench_function("parallel_permutation_N32", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<32, { 32 * M }>(
					&mut parallel_states_32,
					scratchpad,
				);
			}
		})
	});

	// Benchmark parallel permutation N=64
	let elements_hashed = ITERATIONS as u64 * 64 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_64: [Ghash; 64 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 64 * M }];
	group.bench_function("parallel_permutation_N64", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<64, { 64 * M }>(
					&mut parallel_states_64,
					scratchpad,
				);
			}
		})
	});

	// Benchmark parallel permutation N=128
	let elements_hashed = ITERATIONS as u64 * 128 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_128: [Ghash; 128 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 128 * M }];
	group.bench_function("parallel_permutation_N128", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<128, { 128 * M }>(
					&mut parallel_states_128,
					scratchpad,
				);
			}
		})
	});

	// Benchmark parallel permutation N=256
	let elements_hashed = ITERATIONS as u64 * 256 * M as u64;
	group.throughput(Throughput::Bytes(elements_hashed * 16));
	let mut parallel_states_256: [Ghash; 256 * M] = array::from_fn(|_| Ghash::random(&mut rng));
	let scratchpad = &mut [Ghash::ZERO; { 2 * 256 * M }];
	group.bench_function("parallel_permutation_N256", |b| {
		b.iter(|| {
			for _ in 0..ITERATIONS {
				flattened_parallel_permutation::<256, { 256 * M }>(
					&mut parallel_states_256,
					scratchpad,
				);
			}
		})
	});

	group.finish();
}

fn bench_vision(c: &mut Criterion) {
	let mut group = c.benchmark_group("Vision");

	let mut rng = rand::rng();

	const BYTE_COUNT: usize = 1 << 22;
	let mut data = vec![0u8; BYTE_COUNT];
	rng.fill_bytes(&mut data);

	group.throughput(Throughput::Bytes(BYTE_COUNT as u64));

	group.bench_function("Vision-Single", |bench| {
		bench.iter(|| <VisionHasherDigest as Digest>::digest(data.clone()))
	});

	// Number of parallel hashing instances
	const N: usize = 128;

	group.bench_function("Vision-Multi", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];

			VisionHasherMultiDigest::<N, { N * M }>::digest(
				array::from_fn(|i| &data[i * BYTE_COUNT / N..(i + 1) * BYTE_COUNT / N]),
				&mut out,
			);
			out
		})
	});

	group.bench_function("Vision-Parallel", |bench| {
		bench.iter(|| {
			let mut out = [MaybeUninit::<digest::Output<VisionHasherDigest>>::uninit(); N];
			let hasher = ParallelMultidigestImpl::<VisionHasherMultiDigest<N, { N * M }>, N>::new();

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

criterion_group!(batch_invert, bench_batch_invert);
criterion_group!(parallel_permutation, bench_parallel_permutation,);
criterion_group!(hash, bench_vision);
criterion_main!(batch_invert, parallel_permutation, hash);

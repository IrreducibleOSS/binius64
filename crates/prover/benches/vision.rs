use binius_field::{BinaryField128bGhash as Ghash, WithUnderlier};
use binius_verifier::hash::vision::{
	K0, add_round_constants, add_round_constants_owned, batch_invert_4, batch_invert_4_owned,
	batch_invert_8, batch_invert_16, batch_invert_32, batch_invert_generic, linearized_transform_8,
	linearized_transform_16, linearized_transform_32, matrix_mul, matrix_mul_owned, round_4,
	round_8, round_16, round_32,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::hint::black_box;

fn bench_vision_components(c: &mut Criterion) {
	let mut group = c.benchmark_group("Vision Hash Components");

	// Field throughput
	const N_PASSES: usize = 64;
	const BATCH_SIZE: usize = 64;
	let mut rng = StdRng::seed_from_u64(0);
	let mut batch: [Ghash; BATCH_SIZE] = std::array::from_fn(|_| rng.random());
	group.throughput(Throughput::Elements((BATCH_SIZE * N_PASSES) as u64));

	group.bench_function("Field mul", |b| {
		b.iter(|| {
			for _ in 0..N_PASSES {
				for i in 0..BATCH_SIZE {
					batch[i] = batch[i] * batch[(i + BATCH_SIZE / 2) % BATCH_SIZE]
				}
			}
		})
	});

	// Batched Hash Function
	fn bench_hash_generic<const N: usize>(
		group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
		name: &str,
		state: [Ghash; N],
		round_fn: impl Fn(&mut [Ghash; N]) + Copy,
	) {
		const BATCH_SIZE: usize = 100;
		const BYTES_PER_ELEMENT: usize = 16;
		let bytes_per_state = BYTES_PER_ELEMENT * N;
		let bytes_hashed_per_batch = bytes_per_state * BATCH_SIZE;
		let mults_per_round = 2 * (3 * (N - 1));
		const ROUNDS_PER_HASH: usize = 8;
		let mults_per_hash = BATCH_SIZE * ROUNDS_PER_HASH * mults_per_round;

		// Criterion only shows one throughput metric so we need to run the benchmark twice to show 2 throughput metrics
		group.throughput(Throughput::Elements(mults_per_hash as u64));
		group.bench_with_input(BenchmarkId::new(name, "Elements multiplied"), &(), |b, _| {
			b.iter(|| {
				let mut current_state = state;
				for _ in 0..BATCH_SIZE {
					for _ in 0..ROUNDS_PER_HASH {
						round_fn(&mut current_state);
					}
					current_state[0] += Ghash::from_underlier(1);
				}
				black_box(current_state);
			});
		});

		group.throughput(Throughput::Bytes(bytes_hashed_per_batch as u64));
		group.bench_with_input(BenchmarkId::new(name, "Bytes hashed"), &(), |b, _| {
			b.iter(|| {
				let mut current_state = state;
				for _ in 0..BATCH_SIZE {
					for _ in 0..ROUNDS_PER_HASH {
						round_fn(&mut current_state);
					}
					current_state[0] += Ghash::from_underlier(1);
				}
				black_box(current_state);
			});
		});
	}

	// 4
	let state = std::array::from_fn(|_| Ghash::from_underlier(rng.random::<u128>()));
	bench_hash_generic(&mut group, "4", state, round_4);

	// 8
	let state = std::array::from_fn(|_| Ghash::from_underlier(rng.random::<u128>()));
	bench_hash_generic(&mut group, "8", state, round_8);

	// 16
	let state = std::array::from_fn(|_| Ghash::from_underlier(rng.random::<u128>()));
	bench_hash_generic(&mut group, "16", state, round_16);

	// 32
	let state = std::array::from_fn(|_| Ghash::from_underlier(rng.random::<u128>()));
	bench_hash_generic(&mut group, "32", state, round_32);

	// Batch Inversion Generic
	// let state: [Ghash; 8] = std::array::from_fn(|_| Ghash::from_underlier(rng.random::<u128>()));
	// let batch_size_generic = 100;
	// group.throughput(Throughput::Elements((batch_size_generic) as u64));
	// group.bench_with_input(
	// 	BenchmarkId::new("Batch Invert Generic", batch_size_generic),
	// 	&(),
	// 	|b, _| {
	// 		b.iter(|| {
	// 			let mut current_state = state;
	// 			for _ in 0..batch_size_generic {
	// 				batch_invert_generic(&mut current_state);
	// 				// Mutate one element to prevent over-optimizing
	// 				current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 			}
	// 			black_box(current_state);
	// 		});
	// 	},
	// );

	// // Batch Inversion 4
	// let mut state_4 = [
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// ];
	// let batch_size_4 = 100;
	// group.throughput(Throughput::Elements((batch_size_4) as u64));
	// group.bench_with_input(BenchmarkId::new("Batch Invert 4", batch_size_4), &(), |b, _| {
	// 	b.iter(|| {
	// 		let mut current_state = state_4;
	// 		for _ in 0..batch_size_4 {
	// 			batch_invert(&mut current_state);
	// 			// Mutate one element to prevent over-optimizing
	// 			current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 		}
	// 		black_box(current_state);
	// 	});
	// });

	// let batch_size = 100;
	// group.throughput(Throughput::Elements((batch_size) as u64));
	// group.bench_with_input(BenchmarkId::new("Batch Invert Owned", batch_size), &(), |b, _| {
	// 	b.iter(|| {
	// 		let mut current_state = state;
	// 		for _ in 0..batch_size {
	// 			current_state = batch_invert_owned(current_state);
	// 			// Mutate one element to prevent over-optimizing
	// 			current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 		}
	// 		black_box(current_state);
	// 	});
	// });

	// let batch_size_single = 100;
	// group.throughput(Throughput::Elements((batch_size_single) as u64));
	// group.bench_with_input(
	// 	BenchmarkId::new("Batch Invert Owned Single", batch_size_single),
	// 	&(),
	// 	|b, _| {
	// 		b.iter(|| {
	// 			let mut current_state = state;
	// 			for _ in 0..batch_size_single {
	// 				current_state = batch_invert_owned(current_state);
	// 				// Mutate one element to prevent over-optimizing
	// 				current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 			}
	// 			black_box(current_state);
	// 		});
	// 	},
	// );

	// // Linearized Transform (with B table)
	// let mut state = [
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// ];
	// let batch_size_linearized = 100;
	// group.throughput(Throughput::Elements((batch_size_linearized) as u64));
	// group.bench_with_input(
	// 	BenchmarkId::new("Linearized Transform", batch_size_linearized),
	// 	&(),
	// 	|b, _| {
	// 		b.iter(|| {
	// 			let mut current_state = state;
	// 			for _ in 0..batch_size_linearized {
	// 				linearized_transform_optimized(&mut current_state);
	// 				current_state[0] += Ghash::from_underlier(1);
	// 				current_state[1] += Ghash::from_underlier(1);
	// 				current_state[2] += Ghash::from_underlier(1);
	// 				current_state[3] += Ghash::from_underlier(1);
	// 			}
	// 			black_box(current_state);
	// 		});
	// 	},
	// );
	// let state = [
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// 	Ghash::from_underlier(rng.random::<u128>()),
	// ];
	// group.bench_with_input(
	// 	BenchmarkId::new("Linearized Transform 8", batch_size_linearized),
	// 	&(),
	// 	|b, _| {
	// 		b.iter(|| {
	// 			let mut current_state = state;
	// 			for _ in 0..batch_size_linearized {
	// 				linearized_transform_optimized_8(&mut current_state);
	// 				current_state[0] += Ghash::from_underlier(1);
	// 				current_state[1] += Ghash::from_underlier(1);
	// 				current_state[2] += Ghash::from_underlier(1);
	// 				current_state[3] += Ghash::from_underlier(1);
	// 				current_state[4] += Ghash::from_underlier(1);
	// 				current_state[5] += Ghash::from_underlier(1);
	// 				current_state[6] += Ghash::from_underlier(1);
	// 				current_state[7] += Ghash::from_underlier(1);
	// 			}
	// 			black_box(current_state);
	// 		});
	// 	},
	// );

	// // Matrix Multiplication
	// let batch_size_mutable = 100;
	// group.throughput(Throughput::Elements((batch_size_mutable) as u64));
	// group.bench_with_input(BenchmarkId::new("Matrix Mul", batch_size_mutable), &(), |b, _| {
	// 	b.iter(|| {
	// 		let mut current_state = state;
	// 		for _ in 0..batch_size_mutable {
	// 			matrix_mul(&mut current_state);
	// 			// Mutate one element to prevent over-optimizing
	// 			current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 		}
	// 		black_box(current_state);
	// 	});
	// });

	// let batch_size_matrix = 100;
	// group.throughput(Throughput::Elements((batch_size_matrix) as u64));
	// group.bench_with_input(BenchmarkId::new("Matrix Mul Owned", batch_size_matrix), &(), |b, _| {
	// 	b.iter(|| {
	// 		let mut current_state = state;
	// 		for _ in 0..batch_size_matrix {
	// 			current_state = matrix_mul_owned(current_state);
	// 			// Mutate one element to prevent over-optimizing
	// 			current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 		}
	// 		black_box(current_state);
	// 	});
	// });

	// // // Add Round Constants K0
	// let batch_size_constants_mut = 100;
	// group.throughput(Throughput::Elements((batch_size_constants_mut) as u64));
	// group.bench_with_input(
	// 	BenchmarkId::new("Add Round Constants K0", batch_size_constants_mut),
	// 	&(),
	// 	|b, _| {
	// 		b.iter(|| {
	// 			let mut current_state = state;
	// 			for _ in 0..batch_size_constants_mut {
	// 				add_round_constants(&mut current_state, &K0);
	// 				// Mutate one element to prevent over-optimizing
	// 				current_state[0] = current_state[0] + Ghash::from_underlier(1);
	// 			}
	// 			black_box(current_state);
	// 		});
	// 	},
	// );

	group.finish();
}

criterion_group!(vision_benches, bench_vision_components);
criterion_main!(vision_benches);

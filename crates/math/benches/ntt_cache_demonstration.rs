use std::iter::repeat_with;

use binius_field::{PackedField, Random};
use binius_utils::rayon::{ThreadPoolBuilder, iter::ParallelIterator, slice::ParallelSliceMut};
use criterion::{Criterion, criterion_group, criterion_main};

type F = binius_field::PackedBinaryPolyval1x128b;

fn bench(c: &mut Criterion) {
	let mut rng = rand::rng();
	let mut data: Vec<F> = repeat_with(|| F::random(&mut rng)).take(1 << 24).collect();

	// benchmark a single NTT of size 2^24

	c.bench_function("single/breadth", |b| {
		b.iter(|| breadth_first(&mut data, 24));
	});
	c.bench_function("single/depth", |b| {
		b.iter(|| depth_first(&mut data, 24));
	});

	// benchmark four NTTs of size 2^22 each, and each is run in their own thread

	let thread_pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();

	c.bench_function("multi/breadth", |b| {
		thread_pool.install(|| {
			b.iter(|| {
				data.par_chunks_mut(1 << 22)
					.for_each(|chunk| breadth_first(chunk, 22));
			})
		});
	});
	c.bench_function("multi/depth", |b| {
		thread_pool.install(|| {
			b.iter(|| {
				data.par_chunks_mut(1 << 22)
					.for_each(|chunk| depth_first(chunk, 22));
			})
		});
	});
}

fn test_equivalence(_c: &mut Criterion) {
	// no benchmarking, just checking if the two functions compute the same thing

	let mut rng = rand::rng();
	let mut data1: Vec<F> = repeat_with(|| F::random(&mut rng)).take(1 << 22).collect();
	let mut data2 = data1.clone();

	breadth_first(&mut data1, 22);
	depth_first(&mut data2, 22);

	assert_eq!(data1, data2);
	println!("Equivalence check succeeded!");
}

fn breadth_first(data: &mut [F], log_len: usize) {
	let dummy_twiddle = F::one();

	// i indexes layer
	for i in (0..log_len).rev() {
		// k indexes block
		for k in 0..1usize << (log_len - i - 1) {
			let twiddle = std::hint::black_box(dummy_twiddle);
			// l indexes element within block
			for l in 0..1 << i {
				let idx0 = k << (i + 1) | l;
				let idx1 = idx0 | 1usize << i;
				data[idx0] += data[idx1] * twiddle;
				data[idx1] += data[idx0];
			}
		}
	}
}

fn depth_first(data: &mut [F], log_len: usize) {
	// can also use something like log_len=4 as basecase and call `breadth_first` then, this boosts
	// the performance a little bit
	if log_len == 0 {
		return;
	}

	let dummy_twiddle = F::one();
	let len_half = 1 << (log_len - 1);
	for i in 0..(1 << (log_len - 1)) {
		let twiddle = std::hint::black_box(dummy_twiddle);
		let idx0 = i;
		let idx1 = idx0 | len_half;
		data[idx0] += data[idx1] * twiddle;
		data[idx1] += data[idx0];
	}

	depth_first(&mut data[..len_half], log_len - 1);
	depth_first(&mut data[len_half..], log_len - 1);
}

criterion_group! {
	name = default;
	config = Criterion::default().sample_size(10);
	targets = test_equivalence, bench
}
criterion_main!(default);

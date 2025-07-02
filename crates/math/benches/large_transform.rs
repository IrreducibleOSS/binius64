// Copyright 2024-2025 Irreducible Inc.

use std::iter::repeat_with;

use binius_field::{
	AESTowerField32b, AESTowerField128b, BinaryField32b, BinaryField128b, BinaryField128bPolyval,
	PackedExtension, TowerField,
	arch::{OptimalUnderlier, OptimalUnderlierByteSliced},
	as_packed_field::PackedType,
};
use binius_math::ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_large_transform<F: TowerField, PE: PackedExtension<F>>(c: &mut Criterion, field: &str) {
	let mut group = c.benchmark_group("NTT");
	for log_dim in [16, 20] {
		for log_stride_batch in [1, 4] {
			let data_len = 1 << (log_dim + log_stride_batch - PE::LOG_WIDTH);
			let mut rng = rand::rng();
			let mut data = repeat_with(|| PE::random(&mut rng))
				.take(data_len)
				.collect::<Vec<_>>();

			let params = format!("{field}/log_dim={log_dim}/log_s={log_stride_batch}");
			group.throughput(Throughput::Bytes((data_len * size_of::<PE>()) as u64));

			let shape = NTTShape {
				log_x: log_stride_batch,
				log_y: log_dim,
				..Default::default()
			};

			let ntt = SingleThreadedNTT::<F>::new(log_dim)
				.unwrap()
				.precompute_twiddles();
			group.bench_function(BenchmarkId::new("single-thread/precompute", &params), |b| {
				b.iter(|| ntt.forward_transform_ext(&mut data, shape, 0, 0, 0));
			});

			let ntt = SingleThreadedNTT::<F>::new(log_dim)
				.unwrap()
				.precompute_twiddles()
				.multithreaded();
			group.bench_function(BenchmarkId::new("multithread/precompute", &params), |b| {
				b.iter(|| ntt.forward_transform_ext(&mut data, shape, 0, 0, 0));
			});
		}
	}
}

// We are ignoring the transposition associated with byte slicing
fn bench_byte_sliced(c: &mut Criterion) {
	bench_large_transform::<
		AESTowerField32b,
		PackedType<OptimalUnderlierByteSliced, AESTowerField128b>,
	>(c, "bytesliced=AESTowerField128b");
}

fn bench_packed128b(c: &mut Criterion) {
	bench_large_transform::<BinaryField32b, PackedType<OptimalUnderlier, BinaryField128b>>(
		c,
		"field=BinaryField128b",
	);

	bench_large_transform::<AESTowerField32b, PackedType<OptimalUnderlier, AESTowerField128b>>(
		c,
		"field=AESTowerField128b",
	);

	bench_large_transform::<
		BinaryField128bPolyval,
		PackedType<OptimalUnderlier, BinaryField128bPolyval>,
	>(c, "field=BinaryField128bPolyval");
}

criterion_group! {
	name = large_transform;
	config = Criterion::default().sample_size(10);
	targets = bench_packed128b, bench_byte_sliced
}
criterion_main!(large_transform);

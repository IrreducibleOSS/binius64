// Copyright 2024-2025 Irreducible Inc.

use std::{iter::repeat_with, mem};

use binius_field::{
	BinaryField, PackedBinaryField4x32b, PackedBinaryField8x16b, PackedBinaryField8x32b,
	PackedBinaryField16x16b, PackedField,
	arch::byte_sliced::{ByteSlicedAES32x16b, ByteSlicedAES32x32b},
};
use binius_math::ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT};
use criterion::{
	BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
	measurement::WallTime,
};

trait BenchTransformationFunc {
	fn run_bench<F, P>(
		group: &mut BenchmarkGroup<WallTime>,
		ntt: &impl AdditiveNTT<F>,
		data: &mut [P],
		name: &str,
		param: &str,
		log_batch_size: usize,
	) where
		F: BinaryField,
		P: PackedField<Scalar = F>;
}

fn bench_helper<P, BT: BenchTransformationFunc>(
	group: &mut BenchmarkGroup<WallTime>,
	id: &str,
	log_n: usize,
	log_stride_batch: usize,
) where
	P: PackedField<Scalar: BinaryField>,
{
	let data_len = 1 << (log_n + log_stride_batch - P::LOG_WIDTH);
	let mut rng = rand::rng();
	let mut data = repeat_with(|| P::random(&mut rng))
		.take(data_len)
		.collect::<Vec<_>>();

	let params = format!("field={id}/log_n={log_n}/log_s={log_stride_batch}");
	group.throughput(Throughput::Bytes((data_len * mem::size_of::<P>()) as u64));

	let ntt = SingleThreadedNTT::<P::Scalar>::new(log_n).unwrap();
	BT::run_bench(group, &ntt, &mut data, "single-thread/on-the-fly", &params, log_stride_batch);

	let ntt = SingleThreadedNTT::<P::Scalar>::new(log_n)
		.unwrap()
		.precompute_twiddles();
	BT::run_bench(group, &ntt, &mut data, "single-thread/precompute", &params, log_stride_batch);

	let ntt = SingleThreadedNTT::<P::Scalar>::new(log_n)
		.unwrap()
		.multithreaded();
	BT::run_bench(group, &ntt, &mut data, "multithread/on-the-fly", &params, log_stride_batch);

	let ntt = SingleThreadedNTT::<P::Scalar>::new(log_n)
		.unwrap()
		.precompute_twiddles()
		.multithreaded();
	BT::run_bench(group, &ntt, &mut data, "multithread/precompute", &params, log_stride_batch);
}

fn run_benchmarks_on_packed_fields<BT: BenchTransformationFunc>(c: &mut Criterion, name: &str) {
	let mut group = c.benchmark_group(name);
	for &log_n in std::iter::once(&16) {
		for &log_stride_batch in &[0, 4] {
			// 128 bit registers
			bench_helper::<PackedBinaryField8x16b, BT>(
				&mut group,
				"8x16b",
				log_n,
				log_stride_batch,
			);
			bench_helper::<PackedBinaryField4x32b, BT>(
				&mut group,
				"4x32b",
				log_n,
				log_stride_batch,
			);

			// 256 bit registers
			bench_helper::<PackedBinaryField16x16b, BT>(
				&mut group,
				"16x16b",
				log_n,
				log_stride_batch,
			);
			bench_helper::<PackedBinaryField8x32b, BT>(
				&mut group,
				"8x32b",
				log_n,
				log_stride_batch,
			);

			// 256-bit registers with byte-slicing
			bench_helper::<ByteSlicedAES32x16b, BT>(
				&mut group,
				"byte_sliced32x16",
				log_n,
				log_stride_batch,
			);
			bench_helper::<ByteSlicedAES32x32b, BT>(
				&mut group,
				"byte_sliced32x32",
				log_n,
				log_stride_batch,
			);
		}
	}
	group.finish();
}

fn bench_forward_transform(c: &mut Criterion) {
	struct ForwardBench;

	impl BenchTransformationFunc for ForwardBench {
		fn run_bench<F, P>(
			group: &mut BenchmarkGroup<WallTime>,
			ntt: &impl AdditiveNTT<F>,
			data: &mut [P],
			name: &str,
			param: &str,
			log_stride_batch: usize,
		) where
			F: BinaryField,
			P: PackedField<Scalar = F>,
		{
			let log_n = data.len().ilog2() as usize + P::LOG_WIDTH - log_stride_batch;
			let shape = NTTShape {
				log_x: log_stride_batch,
				log_y: log_n,
				..Default::default()
			};
			group.bench_function(BenchmarkId::new(name, param), |b| {
				b.iter(|| ntt.forward_transform(data, shape, 0, 0, 0));
			});
		}
	}

	run_benchmarks_on_packed_fields::<ForwardBench>(c, "forward_transform");
}

fn bench_inverse_transform(c: &mut Criterion) {
	struct InverseBench;

	impl BenchTransformationFunc for InverseBench {
		fn run_bench<F, P>(
			group: &mut BenchmarkGroup<WallTime>,
			ntt: &impl AdditiveNTT<F>,
			data: &mut [P],
			name: &str,
			param: &str,
			log_stride_batch: usize,
		) where
			F: BinaryField,
			P: PackedField<Scalar = F>,
		{
			let log_n = data.len().ilog2() as usize + P::LOG_WIDTH - log_stride_batch;
			let shape = NTTShape {
				log_x: log_stride_batch,
				log_y: log_n,
				..Default::default()
			};
			group.bench_function(BenchmarkId::new(name, param), |b| {
				b.iter(|| ntt.inverse_transform(data, shape, 0, 0, 0));
			});
		}
	}

	run_benchmarks_on_packed_fields::<InverseBench>(c, "inverse_transform");
}

criterion_group!(ntt, bench_forward_transform, bench_inverse_transform);
criterion_main!(ntt);

// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
	PackedField,
};
use binius_math::{field_buffer::FieldSliceMut, test_utils::random_field_buffer};
use criterion::{
	BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
	measurement::WallTime,
};

fn reverse_bits(x: usize, bits: u32) -> usize {
	x.reverse_bits() >> (usize::BITS - bits)
}

fn bit_reverse_indices<P: PackedField>(mut buffer: FieldSliceMut<P>) {
	let bits = buffer.log_len() as u32;
	for i in 0..buffer.len() {
		let i_rev = reverse_bits(i, bits);
		if i < i_rev {
			let tmp = buffer.get(i);
			buffer.set(i, buffer.get(i_rev));
			buffer.set(i_rev, tmp);
		}
	}
}

fn bench_bit_reverse<F: BinaryField, P: PackedField<Scalar = F>>(
	group: &mut BenchmarkGroup<WallTime>,
	log_d: usize,
) {
	let mut rng = rand::rng();

	let parameter = format!("log_d={log_d}");
	let throughput = Throughput::Bytes(((F::N_BITS / 8) << log_d) as u64);
	group.throughput(throughput);

	group.bench_function(BenchmarkId::new("bit_reverse_indices", &parameter), |b| {
		let mut data = random_field_buffer::<P>(&mut rng, log_d);
		b.iter(|| bit_reverse_indices(data.to_mut()))
	});
}

fn bench_fields(c: &mut Criterion) {
	// 1xGhash benchmarks
	{
		type P = PackedBinaryGhash1x128b;
		type F = <P as PackedField>::Scalar;
		let mut group = c.benchmark_group("1xGhash");

		for log_d in [16, 20, 24] {
			if log_d >= 24 {
				group.sample_size(10);
			} else if log_d >= 20 {
				group.sample_size(40);
			}

			bench_bit_reverse::<F, P>(&mut group, log_d);
		}

		group.finish();
	}

	// 2xGhash benchmarks
	{
		type P = PackedBinaryGhash2x128b;
		type F = <P as PackedField>::Scalar;
		let mut group = c.benchmark_group("2xGhash");

		for log_d in [16, 20, 24] {
			if log_d >= 24 {
				group.sample_size(10);
			} else if log_d >= 20 {
				group.sample_size(40);
			}

			bench_bit_reverse::<F, P>(&mut group, log_d);
		}

		group.finish();
	}

	// 4xGhash benchmarks
	{
		type P = PackedBinaryGhash4x128b;
		type F = <P as PackedField>::Scalar;
		let mut group = c.benchmark_group("4xGhash");

		for log_d in [16, 20, 24] {
			if log_d >= 24 {
				group.sample_size(10);
			} else if log_d >= 20 {
				group.sample_size(40);
			}

			bench_bit_reverse::<F, P>(&mut group, log_d);
		}

		group.finish();
	}
}

criterion_group!(default, bench_fields);
criterion_main!(default);

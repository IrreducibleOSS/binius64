// Copyright 2025 Irreducible Inc.

use std::hint::black_box;

use binius_field::{
	BinaryField128bPolyval, PackedField,
	arch::{OptimalUnderlier128b, OptimalUnderlier256b},
	as_packed_field::PackedType,
};
use criterion::{
	BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};

fn run_google_field_bench<P: PackedField>(group: &mut BenchmarkGroup<WallTime>, id: &str) {
	let x = P::zero();
	let mut y = [P::zero(); 1000];

	group.throughput(Throughput::Elements(
		(1000 + 1000 * 1000 * (1000 + 1) + 1000) * P::WIDTH as u64,
	));
	group.bench_function(id, |b| {
		b.iter(|| {
			let mut x = black_box(x);
			for j in 0..1000 {
				y[j] = x;
				x = x * x;
			}
			for _i in 0..1000 * 1000 {
				for j in 0..1000 {
					y[j] = y[j] * x;
				}
				x = x * x;
			}
			for j in 0..1000 {
				x = y[j] * x;
			}
			x
		})
	});
}

fn bench_google_field_bench(c: &mut Criterion) {
	let mut group = c.benchmark_group("google_field_mul");

	run_google_field_bench::<BinaryField128bPolyval>(&mut group, "BinaryField128bPolyval");
	run_google_field_bench::<PackedType<OptimalUnderlier128b, BinaryField128bPolyval>>(
		&mut group,
		"1xBinaryField128bPolyval",
	);
	run_google_field_bench::<PackedType<OptimalUnderlier256b, BinaryField128bPolyval>>(
		&mut group,
		"2xBinaryField128bPolyval",
	);

	group.finish()
}

criterion_group!(google_field_bench, bench_google_field_bench);
criterion_main!(google_field_bench);

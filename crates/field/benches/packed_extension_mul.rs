// Copyright 2024-2025 Irreducible Inc.

use std::hint::black_box;

use binius_field::{
	BinaryField1b, BinaryField8b, BinaryField16b, BinaryField128b, ExtensionField, Field,
	PackedBinaryField2x128b, PackedExtension, PackedField, Random, ext_base_mul,
	packed::set_packed_slice_unchecked,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// Constants for input sizes
const EXT_WIDTH: usize = 64 * 1024; // Fixed extension width

fn benchmark_packed_extension_mul<F>(
	group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
	label: &str,
) where
	F: Field,
	PackedBinaryField2x128b: PackedExtension<F>,
{
	let mut rng = rand::rng();

	// Compute base width based on extension width and field degree
	let base_width: usize = EXT_WIDTH / <BinaryField128b as ExtensionField<F>>::DEGREE;

	// SIMD benchmark
	group.bench_function(BenchmarkId::new(label, "spread"), |b| {
		// Generate input arrays
		let base_packed: Vec<<PackedBinaryField2x128b as PackedExtension<F>>::PackedSubfield> = (0
			..base_width)
			.map(|_| {
				<<PackedBinaryField2x128b as PackedExtension<F>>::PackedSubfield>::random(&mut rng)
			})
			.collect();
		let mut ext_packed: Vec<PackedBinaryField2x128b> = (0..EXT_WIDTH)
			.map(|_| PackedBinaryField2x128b::random(&mut rng))
			.collect();

		b.iter(|| {
			ext_base_mul(&mut ext_packed, &base_packed).unwrap();
		});
		black_box(ext_packed);
	});

	// Scalar-wise benchmark
	group.bench_function(BenchmarkId::new(label, "scalar-wise"), |b| {
		// Generate input arrays
		let base_packed: Vec<<PackedBinaryField2x128b as PackedExtension<F>>::PackedSubfield> = (0
			..base_width)
			.map(|_| {
				<<PackedBinaryField2x128b as PackedExtension<F>>::PackedSubfield>::random(&mut rng)
			})
			.collect();

		let ext_packed: Vec<PackedBinaryField2x128b> = (0..EXT_WIDTH)
			.map(|_| PackedBinaryField2x128b::random(&mut rng))
			.collect();

		let mut result: Vec<PackedBinaryField2x128b> = (0..EXT_WIDTH)
			.map(|_| PackedBinaryField2x128b::default())
			.collect();

		b.iter(|| {
			for (i, (ext, base)) in PackedField::iter_slice(&ext_packed)
				.zip(PackedField::iter_slice(&base_packed))
				.enumerate()
			{
				unsafe { set_packed_slice_unchecked(&mut result, i, ext * base) };
			}
		});

		black_box(ext_packed);
	});
}

fn benchmark_mul(c: &mut Criterion) {
	let mut group = c.benchmark_group("packed_extension_mul");

	// Set throughput once, using the fixed extension width
	group
		.throughput(Throughput::Elements(EXT_WIDTH as u64 * PackedBinaryField2x128b::WIDTH as u64));

	// Benchmark for 1b
	benchmark_packed_extension_mul::<BinaryField1b>(&mut group, "mul_1b");

	// Benchmark for 8b
	benchmark_packed_extension_mul::<BinaryField8b>(&mut group, "mul_8b");

	// Benchmark for 16b
	benchmark_packed_extension_mul::<BinaryField16b>(&mut group, "mul_16b");

	group.finish();
}

criterion_group!(benches, benchmark_mul);
criterion_main!(benches);

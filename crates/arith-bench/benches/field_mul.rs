#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::uint64x2_t;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{__m128i, __m256i};
use std::{array, hint::black_box};

use binius_arith_bench::Underlier;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use rand::{
	Rng,
	distr::{Distribution, StandardUniform},
};

/// Runs the field throughput benchmark strategy in the Longfellow-ZK repo.
///
/// This increases the density of field multiplications compared to the amount of memory used per
/// iteration.
fn run_google_mul_benchmark<U, R>(
	group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
	name: &str,
	mul_fn: fn(U, U) -> U,
	rng: &mut R,
	element_bits: usize,
	underlier_bits: usize,
) where
	U: Underlier,
	R: Rng,
{
	const N: usize = 100;

	let x = U::random(rng);
	let mut y = [U::zero(); N];

	// Calculate throughput based on elements per underlier
	let elements_per_underlier = underlier_bits / element_bits;
	group.throughput(Throughput::Elements(
		((N + N * N * (N + 1) + N) * elements_per_underlier) as u64,
	));

	group.bench_function(name, |b| {
		b.iter(|| {
			let mut x = black_box(x);
			for j in 0..N {
				y[j] = x;
				x = mul_fn(x, x);
			}
			for _i in 0..N * N {
				for j in 0..N {
					y[j] = mul_fn(y[j], x);
				}
				x = mul_fn(x, x);
			}
			for j in 0..N {
				x = mul_fn(y[j], x);
			}
			x
		})
	});
}

/// Generic benchmark helper for multiplication operations.
///
/// The benchmark strategy is to iterate over an array of field elements repeatedly, multiplying
/// strided pairs of elements in place. The stride is half of the length of the array, so that when
/// the array is large enough, the instructions can be efficiently pipelined. The number of passes
/// controls the density of multiplications per iteration.
/// Generic benchmark helper for multiplication operations
fn run_mul_benchmark<T, R>(
	group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
	name: &str,
	mul_fn: fn(T, T) -> T,
	mut rng: R,
	element_bits: usize,
	underlier_bits: usize,
) where
	T: Underlier,
	R: Rng,
{
	/// The size of the field element array to process. Values too small limit pipelined
	/// parallelism.
	const BATCH_SIZE: usize = 16;
	/// The number of multiplications per element in the batch. Larger values increase the density
	/// of multiplications per iteration.
	const N_PASSES: usize = 64;

	// Generate random elements that are to be multiplied.
	let mut batch: [T; BATCH_SIZE] = array::from_fn(|_| T::random(&mut rng));

	// Calculate throughput based on elements per underlier
	let elements_per_underlier = underlier_bits / element_bits;
	group.throughput(Throughput::Elements((BATCH_SIZE * N_PASSES * elements_per_underlier) as u64));

	group.bench_function(name, |b| {
		b.iter(|| {
			for _ in 0..N_PASSES {
				for i in 0..BATCH_SIZE {
					batch[i] = mul_fn(batch[i], batch[(i + BATCH_SIZE / 2) % BATCH_SIZE]);
				}
			}
		})
	});
}

/// Benchmark GF(2^8) multiplication using GFNI instructions
#[allow(unused_variables, unused_mut)]
fn bench_rijndael(c: &mut Criterion) {
	use binius_arith_bench::rijndael::mul_gfni;

	let mut group = c.benchmark_group("rijndael");
	let mut rng = rand::rng();

	// Benchmark __m128i
	#[cfg(all(target_feature = "gfni", target_feature = "sse2"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_gfni::<__m128i>",
			mul_gfni::<__m128i>,
			&mut rng,
			8,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(target_feature = "gfni", target_feature = "avx"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_gfni::<__m256i>",
			mul_gfni::<__m256i>,
			&mut rng,
			8,
			__m256i::BITS,
		);
	}

	group.finish();
}

/// Benchmark GF(2^128) polynomial Montgomery multiplication using CLMUL instructions
#[allow(unused_imports, unused_variables, unused_mut)]
fn bench_polyval(c: &mut Criterion) {
	use binius_arith_bench::polyval::mul_clmul;

	let mut rng = rand::rng();

	let mut group = c.benchmark_group("polyval");

	// Benchmark __m128i
	#[cfg(all(target_feature = "pclmulqdq", target_feature = "sse2"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m128i>",
			mul_clmul::<__m128i>,
			&mut rng,
			128,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(
		target_feature = "vpclmulqdq",
		target_feature = "avx2",
		target_feature = "sse2"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m256i>",
			mul_clmul::<__m256i>,
			&mut rng,
			128,
			__m256i::BITS,
		);
	}

	// Benchmark uint64x2_t (AARCH64 NEON)
	#[cfg(all(
		target_arch = "aarch64",
		target_feature = "neon",
		target_feature = "aes"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::uint64x2_t",
			mul_clmul::<uint64x2_t>,
			&mut rng,
			128,
			uint64x2_t::BITS,
		);
	}

	group.finish();
}

/// Benchmark GF(2^128) GHASH multiplication using CLMUL instructions
#[allow(unused_imports, unused_variables, unused_mut)]
fn bench_ghash(c: &mut Criterion) {
	use binius_arith_bench::ghash::mul_clmul;

	let mut rng = rand::rng();

	let mut group = c.benchmark_group("ghash_mul_clmul");

	// Benchmark __m128i
	#[cfg(all(target_feature = "pclmulqdq", target_feature = "sse2"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m128i>",
			mul_clmul::<__m128i>,
			&mut rng,
			128,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(
		target_feature = "vpclmulqdq",
		target_feature = "avx2",
		target_feature = "sse2"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m256i>",
			mul_clmul::<__m256i>,
			&mut rng,
			128,
			__m256i::BITS,
		);
	}

	// Benchmark uint64x2_t (AARCH64 NEON)
	#[cfg(all(
		target_arch = "aarch64",
		target_feature = "neon",
		target_feature = "aes"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::uint64x2_t",
			mul_clmul::<uint64x2_t>,
			&mut rng,
			128,
			uint64x2_t::BITS,
		);
	}

	group.finish();

	let mut group = c.benchmark_group("ghash_google_mul_clmul");

	// Benchmark __m128i
	#[cfg(all(target_feature = "pclmulqdq", target_feature = "sse2"))]
	{
		run_google_mul_benchmark(
			&mut group,
			"mul_clmul::<__m128i>",
			mul_clmul::<__m128i>,
			&mut rng,
			128,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(
		target_feature = "vpclmulqdq",
		target_feature = "avx2",
		target_feature = "sse2"
	))]
	{
		run_google_mul_benchmark(
			&mut group,
			"mul_clmul::<__m256i>",
			mul_clmul::<__m256i>,
			&mut rng,
			128,
			__m256i::BITS,
		);
	}

	// Benchmark uint64x2_t (AARCH64 NEON)
	#[cfg(all(
		target_arch = "aarch64",
		target_feature = "neon",
		target_feature = "aes"
	))]
	{
		run_google_mul_benchmark(
			&mut group,
			"mul_clmul::uint64x2_t",
			mul_clmul::<uint64x2_t>,
			&mut rng,
			128,
			uint64x2_t::BITS,
		);
	}

	group.finish();
}

/// Benchmark GF(2^64) Monbijou multiplication using CLMUL instructions
#[allow(unused_variables, unused_mut)]
fn bench_monbijou(c: &mut Criterion) {
	use binius_arith_bench::monbijou::mul_clmul;

	let mut rng = rand::rng();

	let mut group = c.benchmark_group("monbijou_64b_mul_clmul");

	// Benchmark __m128i
	#[cfg(all(target_feature = "pclmulqdq", target_feature = "sse2"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m128i>",
			mul_clmul::<__m128i>,
			&mut rng,
			64,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(
		target_feature = "vpclmulqdq",
		target_feature = "avx2",
		target_feature = "sse2"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::<__m256i>",
			mul_clmul::<__m256i>,
			&mut rng,
			64,
			__m256i::BITS,
		);
	}

	// Benchmark uint64x2_t (AARCH64 NEON)
	#[cfg(all(
		target_arch = "aarch64",
		target_feature = "neon",
		target_feature = "aes"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_clmul::uint64x2_t",
			mul_clmul::<uint64x2_t>,
			&mut rng,
			64,
			uint64x2_t::BITS,
		);
	}

	group.finish();
}

/// Benchmark GF(2^128) Monbijou 128-bit extension field multiplication using CLMUL instructions
#[allow(unused_imports, unused_variables, unused_mut)]
fn bench_monbijou_128b(c: &mut Criterion) {
	use binius_arith_bench::monbijou::mul_128b_clmul;

	let mut rng = rand::rng();

	let mut group = c.benchmark_group("monbijou_128b");

	// Benchmark __m128i
	#[cfg(all(target_feature = "pclmulqdq", target_feature = "sse2"))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_128b_clmul::<__m128i>",
			mul_128b_clmul::<__m128i>,
			&mut rng,
			128,
			__m128i::BITS,
		);
	}

	// Benchmark __m256i
	#[cfg(all(
		target_feature = "vpclmulqdq",
		target_feature = "avx2",
		target_feature = "sse2"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_128b_clmul::<__m256i>",
			mul_128b_clmul::<__m256i>,
			&mut rng,
			128,
			__m256i::BITS,
		);
	}

	// Benchmark uint64x2_t (AARCH64 NEON)
	#[cfg(all(
		target_arch = "aarch64",
		target_feature = "neon",
		target_feature = "aes"
	))]
	{
		run_mul_benchmark(
			&mut group,
			"mul_128b_clmul::uint64x2_t",
			mul_128b_clmul::<uint64x2_t>,
			&mut rng,
			128,
			uint64x2_t::BITS,
		);
	}

	group.finish();
}

criterion_group!(
	benches,
	bench_rijndael,
	bench_polyval,
	bench_ghash,
	bench_monbijou,
	bench_monbijou_128b,
);
criterion_main!(benches);

use std::{
	iter::repeat_with,
	time::{Duration, Instant},
};

use binius_field::{BinaryField, PackedField};
use binius_math::ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT};
use binius_utils::rayon::{ThreadPool, ThreadPoolBuilder};
use criterion::{
	BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
	measurement::{Measurement, ValueFormatter},
};

/// Benches different NTT implementations with a specific `PackedField` and specific parameter
/// choice.
///
/// `log_y` is computed automatically from `log_x`, `log_z`, and the size of `data`.
fn bench_ntts<F, P>(
	group: &mut BenchmarkGroup<WallTimeMulThroughput>,
	thread_pool: &ThreadPool,
	num_threads: usize,
	data: &mut [P],
	log_x: usize,
	log_z: usize,
	skip_rounds: usize,
) where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	// log_d is the total size of input
	assert!(data.len().is_power_of_two());
	let log_d = data.len().ilog2() as usize + P::LOG_WIDTH;

	// we compute log_y automatically from log_x, log_z, and the size of the provided data
	assert!(log_x + log_z <= log_d);
	let log_y = log_d - log_x - log_z;

	let shape = NTTShape {
		log_x,
		log_y,
		log_z,
	};

	let parameter = format!(
		"threads={num_threads}/log_d={log_d}/log_x={log_x}/log_y={log_y}/log_z={log_z}/skip_rounds={skip_rounds}"
	);

	// We set the input size for the throughput to be the number of performed multiplications.
	// This way, we can compare to the raw multiplication throughput (from the field benchmarks) and
	// see the overhead of the NTT.
	let num_muls = num_muls(shape, skip_rounds);
	group.throughput(Throughput::Elements(num_muls));

	let ntt = SingleThreadedNTT::<F>::new(log_y).unwrap();
	group.bench_function(BenchmarkId::new("singlethread/on-the-fly/forward", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.forward_transform(data, shape, 0, 0, skip_rounds)))
	});
	group.bench_function(BenchmarkId::new("singlethread/on-the-fly/inverse", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.inverse_transform(data, shape, 0, 0, skip_rounds)))
	});

	let ntt = SingleThreadedNTT::<F>::new(log_y)
		.unwrap()
		.precompute_twiddles();
	group.bench_function(BenchmarkId::new("singlethread/precompute/forward", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.forward_transform(data, shape, 0, 0, skip_rounds)))
	});
	group.bench_function(BenchmarkId::new("singlethread/precompute/inverse", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.inverse_transform(data, shape, 0, 0, skip_rounds)))
	});

	let ntt = SingleThreadedNTT::<F>::new(log_y).unwrap().multithreaded();
	group.bench_function(BenchmarkId::new("multithread/on-the-fly/forward", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.forward_transform(data, shape, 0, 0, skip_rounds)))
	});
	group.bench_function(BenchmarkId::new("multithread/on-the-fly/inverse", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.inverse_transform(data, shape, 0, 0, skip_rounds)))
	});

	let ntt = SingleThreadedNTT::<F>::new(log_y)
		.unwrap()
		.precompute_twiddles()
		.multithreaded();
	group.bench_function(BenchmarkId::new("multithread/precompute/forward", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.forward_transform(data, shape, 0, 0, skip_rounds)))
	});
	group.bench_function(BenchmarkId::new("multithread/precompute/inverse", &parameter), |b| {
		thread_pool.install(|| b.iter(|| ntt.inverse_transform(data, shape, 0, 0, skip_rounds)))
	});
}

/// Calls `bench_ntts` with a fixed `PackedField` but different parameters.
fn bench_params<F, P>(c: &mut Criterion<WallTimeMulThroughput>, packed_field_name: &str)
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	let mut group = c.benchmark_group(packed_field_name);
	let mut rng = rand::rng();

	for &num_threads in &[1, 2, 4] {
		let thread_pool = ThreadPoolBuilder::new()
			.num_threads(num_threads)
			.build()
			.unwrap();
		for &log_d in &[16, 20, 24] {
			let mut data: Vec<P> = repeat_with(|| P::random(&mut rng))
				.take(1usize << (log_d - P::LOG_WIDTH))
				.collect();

			if log_d >= 24 {
				group.sample_size(10);
			} else if log_d >= 20 {
				group.sample_size(50);
			}

			bench_ntts(&mut group, &thread_pool, num_threads, &mut data, 0, 0, 0);
			bench_ntts(&mut group, &thread_pool, num_threads, &mut data, 4, 0, 0);
			bench_ntts(&mut group, &thread_pool, num_threads, &mut data, 0, 4, 0);
			bench_ntts(&mut group, &thread_pool, num_threads, &mut data, 0, 0, 4);
		}
	}
}

/// Calls `bench_params` with different fields.
fn bench_fields(c: &mut Criterion<WallTimeMulThroughput>) {
	bench_params::<_, binius_field::PackedBinaryPolyval1x128b>(c, "1xPolyv");
	bench_params::<_, binius_field::PackedBinaryPolyval2x128b>(c, "2xPolyv");
	bench_params::<_, binius_field::PackedBinaryPolyval4x128b>(c, "4xPolyv");
	bench_params::<_, binius_field::PackedBinaryGhash1x128b>(c, "1xGhash");
	bench_params::<_, binius_field::PackedBinaryGhash2x128b>(c, "2xGhash");
	bench_params::<_, binius_field::PackedBinaryGhash4x128b>(c, "4xGhash");
}

/// Gives the number of raw field multiplications that are done for an NTT with specific parameters.
fn num_muls(shape: NTTShape, skip_rounds: usize) -> u64 {
	assert!(skip_rounds <= shape.log_y);
	let num_rounds = (shape.log_y - skip_rounds) as u64;
	assert!(shape.log_y >= 1);
	let muls_per_round = 1u64 << (shape.log_y - 1);
	let muls_single_ntt = num_rounds * muls_per_round;

	let log_batch_size = shape.log_x + shape.log_z;
	muls_single_ntt << log_batch_size
}

criterion_group! {
	name = custom_formatter;
	config = Criterion::default().with_measurement(WallTimeMulThroughput);
	targets = bench_fields
}
criterion_main!(custom_formatter);

/// This implements a custom `Measurement`, which is just copy-paste from the standard `WallTime`
/// (criterion version `0.6.0`), but uses `MultiplicationFormatter` as a formatter.
struct WallTimeMulThroughput;

impl Measurement for WallTimeMulThroughput {
	type Intermediate = Instant;
	type Value = Duration;

	fn start(&self) -> Self::Intermediate {
		Instant::now()
	}

	fn end(&self, i: Self::Intermediate) -> Self::Value {
		i.elapsed()
	}

	fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
		*v1 + *v2
	}

	fn zero(&self) -> Self::Value {
		Duration::from_secs(0)
	}

	fn to_f64(&self, val: &Self::Value) -> f64 {
		val.as_nanos() as f64
	}

	fn formatter(&self) -> &dyn ValueFormatter {
		&MultiplicationFormatter
	}
}

struct MultiplicationFormatter;

impl MultiplicationFormatter {
	/// This is copy-paste from `DurationFormatter::elements_per_second` (criterion version
	/// `0.6.0`), except that the strings are adapted
	fn muls_per_second(&self, elems: f64, typical: f64, values: &mut [f64]) -> &'static str {
		let elems_per_second = elems * (1e9 / typical);

		let (denominator, unit) = if elems_per_second < 1000.0 {
			(1.0, " mul/s")
		} else if elems_per_second < 1000.0 * 1000.0 {
			(1000.0, "Kmul/s")
		} else if elems_per_second < 1000.0 * 1000.0 * 1000.0 {
			(1000.0 * 1000.0, "Mmul/s")
		} else {
			(1000.0 * 1000.0 * 1000.0, "Gmul/s")
		};

		for val in values {
			let elems_per_second = elems * (1e9 / *val);

			*val = elems_per_second / denominator;
		}

		unit
	}
}

/// This implementation is copy-paste from `DurationFormatter` (criterion version `0.6.0`), except
/// that we only accept `Throughput::Elements` and call `muls_per_second(...)`.
impl ValueFormatter for MultiplicationFormatter {
	fn scale_throughputs(
		&self,
		typical: f64,
		throughput: &Throughput,
		values: &mut [f64],
	) -> &'static str {
		match *throughput {
			Throughput::Elements(elems) => self.muls_per_second(elems as f64, typical, values),
			_ => panic!("can only format elements/second throughput (not bytes)"),
		}
	}

	fn scale_values(&self, ns: f64, values: &mut [f64]) -> &'static str {
		let (factor, unit) = if ns < 10f64.powi(0) {
			(10f64.powi(3), "ps")
		} else if ns < 10f64.powi(3) {
			(10f64.powi(0), "ns")
		} else if ns < 10f64.powi(6) {
			(10f64.powi(-3), "µs")
		} else if ns < 10f64.powi(9) {
			(10f64.powi(-6), "ms")
		} else {
			(10f64.powi(-9), "s")
		};

		for val in values {
			*val *= factor;
		}

		unit
	}

	fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
		// no scaling is needed
		"ns"
	}
}

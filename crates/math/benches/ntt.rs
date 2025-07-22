use std::iter::repeat_with;

use binius_field::{BinaryField, PackedField};
use binius_math::ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT};
use binius_utils::{
	env::boolean_env_flag_set,
	rayon::{ThreadPool, ThreadPoolBuilder},
};
use criterion::{
	BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
	measurement::WallTime,
};

/// `Standard` means it reports the standard input_size / time throughput.
/// `Multiplication` means it reports num_multiplications / time instead as throughput.
///
/// The `Multiplication` variant is useful to compare against the raw multiplication throughput
/// (from the field benchmarks), so one can see the overhead of the NTT.
#[derive(Copy, Clone)]
enum ThroughputVariant {
	Standard,
	Multiplication,
}

/// Benches different NTT implementations with a specific `PackedField` and specific parameter
/// choice.
///
/// `log_y` is computed automatically from `log_x`, `log_z`, and the size of `data`.
#[allow(clippy::too_many_arguments)]
fn bench_ntts<F, P>(
	group: &mut BenchmarkGroup<WallTime>,
	throughput_var: ThroughputVariant,
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

	let throughput = match throughput_var {
		ThroughputVariant::Standard => Throughput::Bytes(std::mem::size_of_val(data) as u64),
		ThroughputVariant::Multiplication => Throughput::Elements(num_muls(shape, skip_rounds)),
	};
	group.throughput(throughput);

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
fn bench_params<F, P>(c: &mut Criterion, packed_field_name: &str, throughput_var: ThroughputVariant)
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
				group.sample_size(40);
			}

			bench_ntts(&mut group, throughput_var, &thread_pool, num_threads, &mut data, 0, 0, 0);
			bench_ntts(&mut group, throughput_var, &thread_pool, num_threads, &mut data, 4, 0, 0);
			bench_ntts(&mut group, throughput_var, &thread_pool, num_threads, &mut data, 0, 4, 0);
			bench_ntts(&mut group, throughput_var, &thread_pool, num_threads, &mut data, 0, 0, 4);
		}
	}
}

/// Calls `bench_params` with different fields.
fn bench_fields(c: &mut Criterion) {
	let throughput_var = determine_throughput_variant();

	bench_params::<_, binius_field::PackedBinaryPolyval1x128b>(c, "1xPolyv", throughput_var);
	bench_params::<_, binius_field::PackedBinaryPolyval2x128b>(c, "2xPolyv", throughput_var);
	bench_params::<_, binius_field::PackedBinaryPolyval4x128b>(c, "4xPolyv", throughput_var);
	bench_params::<_, binius_field::PackedBinaryGhash1x128b>(c, "1xGhash", throughput_var);
	bench_params::<_, binius_field::PackedBinaryGhash2x128b>(c, "2xGhash", throughput_var);
	bench_params::<_, binius_field::PackedBinaryGhash4x128b>(c, "4xGhash", throughput_var);
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

/// Determine the throughput variant based on an environment variable.
fn determine_throughput_variant() -> ThroughputVariant {
	const VAR_NAME: &str = "NTT_MUL_THROUGHPUT";

	if boolean_env_flag_set(VAR_NAME) {
		println!("{VAR_NAME} is activated - using *multiplication* throughput");
		ThroughputVariant::Multiplication
	} else {
		println!("{VAR_NAME} is NOT activated - using *standard* throughput");
		println!(
			"NOTE: Use {VAR_NAME}=1 to see multiplication throughput instead of normal throughput"
		);
		ThroughputVariant::Standard
	}
}

criterion_group!(default, bench_fields);
criterion_main!(default);

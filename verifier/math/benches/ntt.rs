// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
	PackedField,
};
use binius_math::{
	BinarySubspace,
	ntt::{
		AdditiveNTT, DomainContext, NeighborsLastMultiThread, NeighborsLastSingleThread,
		domain_context::GenericPreExpanded,
	},
	test_utils::random_field_buffer,
};
use binius_utils::{env::boolean_env_flag_set, rayon::ThreadPoolBuilder};
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
fn bench_ntts<F: BinaryField, P: PackedField<Scalar = F>>(
	group: &mut BenchmarkGroup<WallTime>,
	throughput_var: ThroughputVariant,
	log_d: usize,
	domain_context: &(impl DomainContext<Field = P::Scalar> + Sync),
	domain_context_name: &str,
	skip_early: usize,
	skip_late: usize,
) {
	let mut rng = rand::rng();

	let parameter = format!("log_d={log_d}/skip_early={skip_early}/skip_late={skip_late}");

	let throughput = match throughput_var {
		ThroughputVariant::Standard => Throughput::Bytes(((F::N_BITS / 8) << log_d) as u64),
		ThroughputVariant::Multiplication => {
			Throughput::Elements(num_muls(log_d, skip_early, skip_late))
		}
	};
	group.throughput(throughput);

	for log_base_len in [4, 16] {
		let ntt_name = format!("singlethread/log_base_len={log_base_len}/{domain_context_name}");
		group.bench_function(BenchmarkId::new(&ntt_name, &parameter), |b| {
			let ntt = NeighborsLastSingleThread {
				domain_context,
				log_base_len,
			};

			let mut data = random_field_buffer::<P>(&mut rng, log_d);
			b.iter(|| ntt.forward_transform(data.to_mut(), skip_early, skip_late))
		});
	}

	for log_num_shares in [0, 3] {
		for log_base_len in [4, 8, 12, 16] {
			let num_threads = 1 << log_num_shares;
			let ntt_name = format!(
				"multithread/threads={num_threads}/log_base_len={log_base_len}/{domain_context_name}"
			);
			group.bench_function(BenchmarkId::new(&ntt_name, &parameter), |b| {
				let ntt = NeighborsLastMultiThread {
					domain_context,
					log_base_len,
					log_num_shares,
				};

				let mut data = random_field_buffer::<P>(&mut rng, log_d);

				let thread_pool = ThreadPoolBuilder::new()
					.num_threads(num_threads)
					.build()
					.unwrap();
				thread_pool.install(|| {
					b.iter(|| ntt.forward_transform(data.to_mut(), skip_early, skip_late))
				})
			});
		}
	}
}

/// Calls `bench_ntts` with a fixed `PackedField` but different parameters.
fn bench_params<F: BinaryField, P: PackedField<Scalar = F>>(
	c: &mut Criterion,
	packed_field_name: &str,
	throughput_var: ThroughputVariant,
) {
	let mut group = c.benchmark_group(packed_field_name);

	for log_d in [16, 20, 24] {
		let subspace = BinarySubspace::<F>::with_dim(log_d).unwrap();
		let domain_context_generic = GenericPreExpanded::generate_from_subspace(&subspace);
		let domain_context_name = "precompute";

		if log_d >= 24 {
			group.sample_size(10);
		} else if log_d >= 20 {
			group.sample_size(40);
		}

		for skip_early in [0, 4] {
			for skip_late in [0, 4] {
				bench_ntts::<F, P>(
					&mut group,
					throughput_var,
					log_d,
					&domain_context_generic,
					domain_context_name,
					skip_early,
					skip_late,
				);
			}
		}
	}
}

/// Calls `bench_params` with different fields.
fn bench_fields(c: &mut Criterion) {
	let throughput_var = determine_throughput_variant();

	bench_params::<_, PackedBinaryGhash1x128b>(c, "1xGhash", throughput_var);
	bench_params::<_, PackedBinaryGhash2x128b>(c, "2xGhash", throughput_var);
	bench_params::<_, PackedBinaryGhash4x128b>(c, "4xGhash", throughput_var);
}

/// Gives the number of raw field multiplications that are done for an NTT with specific parameters.
fn num_muls(log_d: usize, skip_early: usize, skip_late: usize) -> u64 {
	let num_rounds = log_d - skip_late - skip_early;
	let muls_per_round = 1u64 << (log_d - 1);

	num_rounds as u64 * muls_per_round
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

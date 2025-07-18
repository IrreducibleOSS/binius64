use binius_field::{BinaryField, BinaryField128b, BinaryField128bGhash, PackedBinaryField1x128b};
use binius_prover::protocols::intmul::{execute, prove};
use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
use blake2::Blake2b;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use digest::consts::U32;
use rand::Rng;

type Blake2b256 = Blake2b<U32>;
type F = BinaryField128b;
type P = BinaryField128bGhash;

fn generate_test_data(log_num: usize) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
	let num_exponents = 1 << log_num;
	let mut rng = rand::rng();

	let mut a_exponents = Vec::with_capacity(num_exponents);
	let mut b_exponents = Vec::with_capacity(num_exponents);
	let mut c_lo_exponents = Vec::with_capacity(num_exponents);
	let mut c_hi_exponents = Vec::with_capacity(num_exponents);

	for _ in 0..num_exponents {
		let a_exp = rng.random_range(1..u64::MAX);
		let b_exp = rng.random_range(1..u64::MAX);

		let a_u128 = a_exp as u128;
		let b_u128 = b_exp as u128;
		let full_result = a_u128 * b_u128;

		let c_lo = full_result as u64;
		let c_hi = (full_result >> 64) as u64;

		a_exponents.push(a_exp);
		b_exponents.push(b_exp);
		c_lo_exponents.push(c_lo);
		c_hi_exponents.push(c_hi);
	}

	(a_exponents, b_exponents, c_lo_exponents, c_hi_exponents)
}

fn bench_intmul_prove(c: &mut Criterion) {
	// rayon::ThreadPoolBuilder::new()
	// 	.num_threads(10)
	// 	.build_global()
	// 	.ok();

	let mut group = c.benchmark_group("intmul_phases");
	group.sample_size(10);
	group.throughput(Throughput::Elements(1));

	let generator = F::MULTIPLICATIVE_GENERATOR;

	let log_num = 14;
	let num_exponents = 1 << log_num;
	let (a_exponents, b_exponents, c_lo_exponents, c_hi_exponents) = generate_test_data(log_num);

	// execute
	group.bench_with_input(
		BenchmarkId::new("execute", num_exponents),
		&num_exponents,
		|bencher, _| {
			bencher.iter(|| {
				execute::execute::<P>(
					generator,
					&a_exponents,
					&b_exponents,
					&c_lo_exponents,
					&c_hi_exponents,
				)
				.unwrap()
			})
		},
	);

	// prove
	let prover_data = execute::execute::<P>(
		generator,
		&a_exponents,
		&b_exponents,
		&c_lo_exponents,
		&c_hi_exponents,
	)
	.unwrap();

	group.bench_with_input(
		BenchmarkId::new("prove", num_exponents),
		&prover_data,
		|bencher, prover_data| {
			bencher.iter_with_setup(
				|| {
					let prover_transcript =
						ProverTranscript::<HasherChallenger<Blake2b256>>::default();
					(prover_data.clone(), prover_transcript)
				},
				|(prover_data, mut prover_transcript)| {
					prove::prove::<F, P, HasherChallenger<Blake2b256>>(
						prover_data.n_vars,
						&b_exponents,
						prover_data.a_layers.into_iter(),
						prover_data.b_layers.into_iter(),
						prover_data.c_layers.into_iter(),
						generator,
						&mut prover_transcript,
					)
					.unwrap()
				},
			)
		},
	);

	// execute + prove
	group.bench_with_input(
		BenchmarkId::new("combined", num_exponents),
		&num_exponents,
		|bencher, _| {
			bencher.iter(|| {
				let prover_data = execute::execute::<P>(
					generator,
					&a_exponents,
					&b_exponents,
					&c_lo_exponents,
					&c_hi_exponents,
				)
				.unwrap();

				let mut prover_transcript =
					ProverTranscript::<HasherChallenger<Blake2b256>>::default();

				prove::prove::<F, P, HasherChallenger<Blake2b256>>(
					prover_data.n_vars,
					&b_exponents,
					prover_data.a_layers.into_iter(),
					prover_data.b_layers.into_iter(),
					prover_data.c_layers.into_iter(),
					generator,
					&mut prover_transcript,
				)
				.unwrap()
			})
		},
	);

	group.finish();
}

criterion_group!(intmul_benches, bench_intmul_prove);
criterion_main!(intmul_benches);

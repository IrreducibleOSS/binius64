use binius_field::{
	AESTowerField8b, ByteSlicedAES16x16x8b, Field, PackedAESBinaryField16x8b, PackedField, Random,
};
use binius_math::{
	BinarySubspace,
	ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT},
};
use binius_prover::sub_bytes_reduction::fast_ntt_64::{fast_ntt_64, generate_ntt_domains};
use binius_verifier::config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

fn bench_fast_ntt_64(c: &mut Criterion) {
	let mut rng = StdRng::seed_from_u64(0);

	// Generate the required domains
	let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();
	let (intt_domains, fntt_domains) = generate_ntt_domains(subspace);

	// Generate random data once
	let mut data = [AESTowerField8b::ZERO; WORD_SIZE_BITS];
	for element in data.iter_mut() {
		*element = AESTowerField8b::random(&mut rng);
	}

	let mut group = c.benchmark_group("fast_ntt_64");
	group.throughput(Throughput::Elements(WORD_SIZE_BITS as u64));

	group.bench_function("fast_ntt_64", |b| {
		b.iter(|| {
			fast_ntt_64(&mut data, &intt_domains, &fntt_domains);
			data
		})
	});

	group.finish();
}

fn bench_fast_ntt_64_packed(c: &mut Criterion) {
	let mut rng = StdRng::seed_from_u64(0);

	// Generate the required domains
	let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();
	let (intt_domains, fntt_domains) = generate_ntt_domains(subspace);

	// Generate random data once
	let mut data = [PackedAESBinaryField16x8b::zero(); WORD_SIZE_BITS];
	for element in data.iter_mut() {
		*element = PackedAESBinaryField16x8b::random(&mut rng);
	}

	let mut group = c.benchmark_group("fast_ntt_64_packed");
	group.throughput(Throughput::Elements(
		(WORD_SIZE_BITS * PackedAESBinaryField16x8b::WIDTH) as u64,
	));

	group.bench_function("fast_ntt_64_packed", |b| {
		b.iter(|| {
			fast_ntt_64(&mut data, &intt_domains, &fntt_domains);
			data
		})
	});

	group.finish();
}

fn bench_normal_ntt(c: &mut Criterion) {
	let mut rng = StdRng::seed_from_u64(0);

	// Generate random data once
	let mut data = [ByteSlicedAES16x16x8b::zero(); WORD_SIZE_BITS / 16];
	for element in data.iter_mut() {
		*element = ByteSlicedAES16x16x8b::random(&mut rng);
	}

	let mut group = c.benchmark_group("normal_ntt_packed");
	group.throughput(Throughput::Elements(
		(WORD_SIZE_BITS * PackedAESBinaryField16x8b::WIDTH) as u64,
	));
	let ntt = SingleThreadedNTT::<AESTowerField8b>::new(LOG_WORD_SIZE_BITS)
		.unwrap()
		.precompute_twiddles();

	let shape = NTTShape {
		log_x: PackedAESBinaryField16x8b::LOG_WIDTH,
		log_y: LOG_WORD_SIZE_BITS,
		log_z: 0,
	};

	group.bench_function("fast_ntt_64_packed", |b| {
		b.iter(|| {
			let _ = ntt.inverse_transform(&mut data, shape, 0, 0, 0);

			let _ = ntt.forward_transform(&mut data, shape, 0, 0, 0);

			data
		})
	});

	group.finish();
}

criterion_group!(benches, bench_fast_ntt_64, bench_fast_ntt_64_packed, bench_normal_ntt);
criterion_main!(benches);

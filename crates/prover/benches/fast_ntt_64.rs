use binius_field::{AESTowerField8b, Field, PackedAESBinaryField16x8b, PackedField, Random};
use binius_math::BinarySubspace;
use binius_prover::sub_bytes_reduction::fast_ntt_64::{fast_ntt_64, generate_ntt_domains};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

const ARRAY_SIZE: usize = 64;

fn bench_fast_ntt_64(c: &mut Criterion) {
	let mut rng = StdRng::seed_from_u64(0);

	// Generate the required domains
	let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();
	let (intt_domains, fntt_domains) = generate_ntt_domains(subspace);

	// Generate random data once
	let mut data = [AESTowerField8b::ZERO; ARRAY_SIZE];
	for element in data.iter_mut() {
		*element = AESTowerField8b::random(&mut rng);
	}

	let mut group = c.benchmark_group("fast_ntt_64");
	group.throughput(Throughput::Elements(ARRAY_SIZE as u64));

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
	let mut data = [PackedAESBinaryField16x8b::zero(); ARRAY_SIZE];
	for element in data.iter_mut() {
		*element = PackedAESBinaryField16x8b::random(&mut rng);
	}

	let mut group = c.benchmark_group("fast_ntt_64_packed");
	group.throughput(Throughput::Elements((ARRAY_SIZE * PackedAESBinaryField16x8b::WIDTH) as u64));

	group.bench_function("fast_ntt_64_packed", |b| {
		b.iter(|| {
			fast_ntt_64(&mut data, &intt_domains, &fntt_domains);
			data
		})
	});

	group.finish();
}

criterion_group!(benches, bench_fast_ntt_64, bench_fast_ntt_64_packed);
criterion_main!(benches);

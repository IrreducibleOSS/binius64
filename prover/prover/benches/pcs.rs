// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, arch::OptimalPackedB128};
use binius_math::{
	BinarySubspace,
	ntt::{AdditiveNTT, NeighborsLastMultiThread, domain_context::GenericPreExpanded},
	test_utils::{random_field_buffer, random_scalars},
};
use binius_prover::pcs::OneBitPCSProver;
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::{B1, B128, StdChallenger},
	fri::FRIParams,
	hash::{StdCompression, StdDigest},
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn bench_pcs(c: &mut Criterion) {
	let mut group = c.benchmark_group("pcs");

	type P = OptimalPackedB128;

	for log_len in [12, 16, 20] {
		const LOG_INV_RATE: usize = 1;
		const SECURITY_BITS: usize = 32;

		// Calculate throughput based on the input message size in bytes
		let message_bytes = (1 << log_len) * B128::N_BITS / 8;
		group.throughput(Throughput::Bytes(message_bytes as u64));

		let mut rng = rand::rng();
		let packed_multilin = random_field_buffer::<P>(&mut rng, log_len);

		type H = StdDigest;
		let compression = StdCompression::default();
		let subspace =
			BinarySubspace::<B128>::with_dim(log_len).expect("Failed to create subspace");
		let domain_context = GenericPreExpanded::generate_from_subspace(&subspace);
		let log_num_shares = binius_utils::rayon::current_num_threads().ilog2() as usize;
		let ntt = NeighborsLastMultiThread::new(domain_context, log_num_shares);

		let fri_params = FRIParams::<B128, H, _>::new_with_good_choices(
			compression,
			log_len,
			LOG_INV_RATE,
			SECURITY_BITS,
			&ntt.domain_context(),
		);

		let pcs_prover = OneBitPCSProver::new(&ntt, &fri_params);

		// Generate random evaluation point
		let evaluation_point =
			random_scalars(&mut rng, log_len + <B128 as ExtensionField<B1>>::LOG_DEGREE);
		group.bench_function(format!("pcs/log_len={log_len}"), |b| {
			b.iter(|| {
				// Commit the packed multilinear
				let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
				let fri_prover =
					pcs_prover.commit(packed_multilin.to_ref(), &mut prover_transcript.message());

				pcs_prover
					.prove(
						fri_prover,
						packed_multilin.clone(), /* FIXME the benchmark also measures the
						                          * cloning... */
						evaluation_point.clone(),
						&mut prover_transcript,
					)
					.unwrap()
			});
		});
	}

	group.finish();
}

criterion_group!(pcs, bench_pcs);
criterion_main!(pcs);

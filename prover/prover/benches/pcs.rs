// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, arch::OptimalPackedB128};
use binius_math::{
	BinarySubspace,
	ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded},
	test_utils::{random_field_buffer, random_scalars},
};
use binius_prover::{
	fri, fri::CommitOutput, hash::parallel_compression::ParallelCompressionAdaptor,
	merkle_tree::prover::BinaryMerkleTreeProver, pcs::OneBitPCSProver,
};
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
		const ARITY: usize = 4;

		// Calculate throughput based on the input message size in bytes
		let message_bytes = (1 << log_len) * B128::N_BITS / 8;
		group.throughput(Throughput::Bytes(message_bytes as u64));

		let mut rng = rand::rng();
		let packed_multilin = random_field_buffer::<P>(&mut rng, log_len);

		let compression = ParallelCompressionAdaptor::new(StdCompression::default());
		let merkle_prover = BinaryMerkleTreeProver::<B128, StdDigest, _>::new(compression);

		let subspace =
			BinarySubspace::<B128>::with_dim(log_len).expect("Failed to create subspace");
		let domain_context = GenericPreExpanded::generate_from_subspace(&subspace);
		let log_num_shares = binius_utils::rayon::current_num_threads().ilog2() as usize;
		let ntt = NeighborsLastMultiThread::new(domain_context, log_num_shares);

		let fri_params = FRIParams::choose_with_constant_fold_arity(
			&ntt,
			log_len,
			SECURITY_BITS,
			LOG_INV_RATE,
			ARITY,
		)
		.expect("Failed to create FRI params");

		group.bench_function(format!("commit/log_len={log_len}"), |b| {
			b.iter(|| {
				fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_multilin.to_ref())
					.unwrap()
			});
		});

		// Commit the packed multilinear
		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_multilin.to_ref())
			.expect("Failed to commit");

		group.bench_function(format!("prove/log_len={log_len}"), |b| {
			let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
			prover_transcript.message().write(&codeword_commitment);

			// Generate random evaluation point
			let evaluation_point =
				random_scalars(&mut rng, log_len + <B128 as ExtensionField<B1>>::LOG_DEGREE);

			let pcs_prover = OneBitPCSProver::new(&ntt, &merkle_prover, &fri_params);

			b.iter(|| {
				pcs_prover
					.prove(
						&codeword,
						&codeword_committed,
						packed_multilin.clone(),
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

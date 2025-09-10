// Copyright 2025 Irreducible Inc.

use std::iter::repeat_with;

use binius_field::Random;
use binius_prover::merkle_tree::MerkleTreeProver;
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::{B128, StdChallenger},
	hash::{PseudoCompressionFunction, StdCompression, StdDigest},
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use digest::{Digest, Output, core_api::BlockSizeUser};

const LOG_ELEMS: usize = 17;
const LOG_ELEMS_IN_LEAF: usize = 4;
const COMMIT_LAYER: usize = 0;

type F = B128;

fn bench_binary_merkle_tree<H, C>(c: &mut Criterion, compression: C, hash_name: &str)
where
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
{
	let mut rng = rand::rng();
	let data = repeat_with(|| F::random(&mut rng))
		.take(1 << (LOG_ELEMS + LOG_ELEMS_IN_LEAF))
		.collect::<Vec<_>>();
	let mut group = c.benchmark_group(format!("slow/merkle_tree/{hash_name}"));
	group.throughput(Throughput::Bytes(
		((1 << (LOG_ELEMS + LOG_ELEMS_IN_LEAF)) * std::mem::size_of::<F>()) as u64,
	));
	group.sample_size(10);
	group.bench_function(
		format!("{} log elems size {}xB128 leaf", LOG_ELEMS, 1 << LOG_ELEMS_IN_LEAF),
		|b| {
			// create prover transcript
			let challenger = StdChallenger::default();
			let mut prover_transcript = ProverTranscript::new(challenger);

			b.iter(|| {
				let _merkle_prover = MerkleTreeProver::<_, H, _>::write_commitment(
					compression.clone(),
					data.clone(), // NOTE: The benchmark also measures the cloning.
					LOG_ELEMS_IN_LEAF,
					COMMIT_LAYER,
					&mut prover_transcript.message(),
				);
			});
		},
	);
	group.finish()
}

fn bench_sha256_merkle_tree(c: &mut Criterion) {
	bench_binary_merkle_tree::<StdDigest, _>(c, StdCompression::default(), "SHA-256");
}

criterion_group!(binary_merkle_tree, bench_sha256_merkle_tree);
criterion_main!(binary_merkle_tree);

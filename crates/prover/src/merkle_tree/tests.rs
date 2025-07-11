// Copyright 2024-2025 Irreducible Inc.

use core::slice;
use std::iter::repeat_with;

use binius_field::{BinaryField16b, Random};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	merkle_tree::MerkleTreeScheme,
};
use rand::prelude::*;

use crate::merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver};

#[test]
fn test_binary_merkle_vcs_commit_prove_open_correctly() {
	let mut rng = StdRng::seed_from_u64(0);

	let mr_prover = BinaryMerkleTreeProver::<_, StdDigest, _>::new(StdCompression::default());

	let data = repeat_with(|| BinaryField16b::random(&mut rng))
		.take(16)
		.collect::<Vec<_>>();
	let (commitment, tree) = mr_prover.commit(&data, 1).unwrap();

	assert_eq!(commitment.root, tree.root());

	for (i, value) in data.iter().enumerate() {
		let mut proof_writer = ProverTranscript::new(StdChallenger::default());
		mr_prover
			.prove_opening(&tree, 0, i, &mut proof_writer.message())
			.unwrap();

		let mut proof_reader = proof_writer.into_verifier();
		mr_prover
			.scheme()
			.verify_opening(
				i,
				slice::from_ref(value),
				0,
				4,
				&[commitment.root],
				&mut proof_reader.message(),
			)
			.unwrap();
	}
}

#[test]
fn test_binary_merkle_vcs_commit_layer_prove_open_correctly() {
	let mut rng = StdRng::seed_from_u64(0);

	let mr_prover = BinaryMerkleTreeProver::<_, StdDigest, _>::new(StdCompression::default());

	let data = repeat_with(|| BinaryField16b::random(&mut rng))
		.take(32)
		.collect::<Vec<_>>();
	let (commitment, tree) = mr_prover.commit(&data, 1).unwrap();

	assert_eq!(commitment.root, tree.root());
	for layer_depth in 0..5 {
		let layer = mr_prover.layer(&tree, layer_depth).unwrap();
		mr_prover
			.scheme()
			.verify_layer(&commitment.root, layer_depth, layer)
			.unwrap();
		for (i, value) in data.iter().enumerate() {
			let mut proof_writer = ProverTranscript::new(StdChallenger::default());
			mr_prover
				.prove_opening(&tree, layer_depth, i, &mut proof_writer.message())
				.unwrap();

			let mut proof_reader = proof_writer.into_verifier();
			mr_prover
				.scheme()
				.verify_opening(
					i,
					slice::from_ref(value),
					layer_depth,
					5,
					layer,
					&mut proof_reader.message(),
				)
				.unwrap();
		}
	}
}

#[test]
fn test_binary_merkle_vcs_verify_vector() {
	let mut rng = StdRng::seed_from_u64(0);

	let mr_prover = BinaryMerkleTreeProver::<_, StdDigest, _>::new(StdCompression::default());

	let data = repeat_with(|| BinaryField16b::random(&mut rng))
		.take(4)
		.collect::<Vec<_>>();
	let (commitment, _) = mr_prover.commit(&data, 1).unwrap();

	mr_prover
		.scheme()
		.verify_vector(&commitment.root, &data, 1)
		.unwrap();
}

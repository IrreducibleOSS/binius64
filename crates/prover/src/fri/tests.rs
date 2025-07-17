// Copyright 2024-2025 Irreducible Inc.

use std::{iter::repeat_with, vec};

use binius_field::{
	BinaryField, BinaryField16b, BinaryField32b, BinaryField128b, ExtensionField, PackedField,
	Random, TowerField,
	arch::OptimalUnderlier128b,
	as_packed_field::{PackScalar, PackedType},
	underlier::UnderlierType,
	util::inner_product_par,
};
use binius_math::{ReedSolomonCode, multilinear::eq::eq_ind_partial_eval, ntt::SingleThreadedNTT};
use binius_transcript::{ProverTranscript, fiat_shamir::CanSample};
use binius_utils::checked_arithmetics::log2_strict_usize;
use binius_verifier::{
	config::StdChallenger,
	fri::{FRIParams, verify::FRIVerifier},
	hash::{StdCompression, StdDigest},
};
use rand::prelude::*;

use super::{CommitOutput, FRIFolder, FoldRoundOutput, commit_interleaved};
use crate::merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver};

fn test_commit_prove_verify_success<U, F, FA>(
	log_dimension: usize,
	log_inv_rate: usize,
	log_batch_size: usize,
	arities: &[usize],
) where
	U: UnderlierType + PackScalar<F> + PackScalar<FA>,
	F: TowerField + ExtensionField<FA> + PackedField<Scalar = F>,
	FA: BinaryField,
	PackedType<U, F>: PackedField,
	PackedType<U, FA>: PackedField,
{
	let mut rng = StdRng::seed_from_u64(0);

	let merkle_prover = BinaryMerkleTreeProver::<_, StdDigest, _>::new(StdCompression::default());

	let committed_rs_code = ReedSolomonCode::<FA>::new(log_dimension, log_inv_rate).unwrap();

	let n_test_queries = 3;
	let params =
		FRIParams::new(committed_rs_code, log_batch_size, arities.to_vec(), n_test_queries)
			.unwrap();

	let committed_rs_code = ReedSolomonCode::<FA>::new(log_dimension, log_inv_rate).unwrap();
	let ntt = SingleThreadedNTT::new(params.rs_code().log_len()).unwrap();

	let n_round_commitments = arities.len();

	// Generate a random message
	let msg = repeat_with(|| <PackedType<U, F>>::random(&mut rng))
		.take(committed_rs_code.dim() << log_batch_size >> <PackedType<U, F>>::LOG_WIDTH)
		.collect::<Vec<_>>();

	// Prover commits the message
	let CommitOutput {
		commitment: mut codeword_commitment,
		committed: codeword_committed,
		codeword,
	} = commit_interleaved(&committed_rs_code, &params, &ntt, &merkle_prover, &msg).unwrap();

	// Run the prover to generate the proximity proof
	let mut round_prover =
		FRIFolder::new(&params, &ntt, &merkle_prover, &codeword, &codeword_committed).unwrap();

	let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
	prover_challenger.message().write(&codeword_commitment);
	let mut round_commitments = Vec::with_capacity(params.n_oracles());
	for _i in 0..params.n_fold_rounds() {
		let challenge = prover_challenger.sample();
		let fold_round_output = round_prover.execute_fold_round(challenge).unwrap();
		match fold_round_output {
			FoldRoundOutput::NoCommitment => {}
			FoldRoundOutput::Commitment(round_commitment) => {
				prover_challenger.message().write(&round_commitment);
				round_commitments.push(round_commitment);
			}
		}
	}

	round_prover.finish_proof(&mut prover_challenger).unwrap();
	// Now run the verifier
	let mut verifier_challenger = prover_challenger.into_verifier();
	codeword_commitment = verifier_challenger.message().read().unwrap();
	let mut verifier_challenges = Vec::with_capacity(params.n_fold_rounds());

	assert_eq!(params.fold_arities().len(), n_round_commitments);
	let mut round_commitments = Vec::with_capacity(params.n_oracles());
	for &round_arity in params.fold_arities() {
		verifier_challenges.append(&mut verifier_challenger.sample_vec(round_arity));
		let commitment = verifier_challenger.message().read().unwrap();
		round_commitments.push(commitment);
	}

	verifier_challenges.append(&mut verifier_challenger.sample_vec(params.n_final_challenges()));

	assert_eq!(verifier_challenges.len(), params.n_fold_rounds());

	// check c == t(r'_0, ..., r'_{\ell-1})
	// note that the prover is claiming that the final_message is [c]
	let eval_query = eq_ind_partial_eval::<F>(&verifier_challenges);
	// recall that msg, the message the prover commits to, is (the evaluations on the Boolean
	// hypercube of) a multilinear polynomial.
	let computed_eval = inner_product_par(eval_query.as_ref(), &msg);

	let verifier = FRIVerifier::new(
		&params,
		merkle_prover.scheme(),
		&codeword_commitment,
		&round_commitments,
		&verifier_challenges,
	)
	.unwrap();

	let mut cloned_verifier_challenger = verifier_challenger.clone();

	let terminate_codeword_len =
		1 << (params.n_final_challenges() + params.rs_code().log_inv_rate());

	let mut advice = verifier_challenger.decommitment();
	let terminate_codeword: Vec<F> = advice.read_scalar_slice(terminate_codeword_len).unwrap();

	let log_batch_size =
		log2_strict_usize(terminate_codeword.len()).saturating_sub(params.rs_code().log_inv_rate());

	let (commitment, tree) = merkle_prover
		.commit(&terminate_codeword, 1 << log_batch_size)
		.unwrap();

	// Ensure that the terminate_codeword commitment is correct
	let last_round_commitment = round_commitments.last().unwrap_or(&codeword_commitment);
	assert_eq!(*last_round_commitment, commitment.root);

	// Verify that the Merkle tree has exactly inv_rate leaves.
	assert_eq!(tree.log_len, params.rs_code().log_inv_rate());

	let final_fri_value = verifier.verify(&mut cloned_verifier_challenger).unwrap();
	assert_eq!(computed_eval, final_fri_value);
}

#[test]
fn test_commit_prove_verify_success_128b_full() {
	binius_utils::rayon::adjust_thread_pool();

	// This tests the case where we have a round commitment for every round
	let log_dimension = 8;
	let log_final_dimension = 1;
	let log_inv_rate = 2;
	let arities = vec![1; log_dimension - log_final_dimension];

	test_commit_prove_verify_success::<OptimalUnderlier128b, BinaryField128b, BinaryField16b>(
		log_dimension,
		log_inv_rate,
		0,
		&arities,
	);
}

#[test]
fn test_commit_prove_verify_success_128b_higher_arity() {
	let log_dimension = 8;
	let log_inv_rate = 2;
	let arities = [3, 2, 1];

	test_commit_prove_verify_success::<OptimalUnderlier128b, BinaryField128b, BinaryField16b>(
		log_dimension,
		log_inv_rate,
		0,
		&arities,
	);
}

#[test]
fn test_commit_prove_verify_success_128b_interleaved() {
	let log_dimension = 6;
	let log_inv_rate = 2;
	let log_batch_size = 2;
	let arities = [3, 2, 1];

	test_commit_prove_verify_success::<OptimalUnderlier128b, BinaryField128b, BinaryField16b>(
		log_dimension,
		log_inv_rate,
		log_batch_size,
		&arities,
	);
}

#[test]
fn test_commit_prove_verify_success_128b_interleaved_packed() {
	let log_dimension = 6;
	let log_inv_rate = 2;
	let log_batch_size = 2;
	let arities = [3, 2, 1];

	test_commit_prove_verify_success::<OptimalUnderlier128b, BinaryField32b, BinaryField16b>(
		log_dimension,
		log_inv_rate,
		log_batch_size,
		&arities,
	);
}

#[test]
fn test_commit_prove_verify_success_without_folding() {
	let log_dimension = 4;
	let log_inv_rate = 2;
	let log_batch_size = 2;

	test_commit_prove_verify_success::<OptimalUnderlier128b, BinaryField128b, BinaryField16b>(
		log_dimension,
		log_inv_rate,
		log_batch_size,
		&[],
	);
}

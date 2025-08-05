// Copyright 2025 Irreducible Inc.

use std::array;

use binius_field::{BinaryField, PackedField};
use binius_math::{BinarySubspace, FieldBuffer, univariate::lagrange_evals};
use binius_verifier::config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS};
use tracing::instrument;

use super::{error::Error, phase_1::MultilinearTriplet};

/// Constructs the three "h" multilinear polynomials for shift operations at a
/// univariate challenge point. See the paper for definition of h polynomials.
///
/// There is one h multilinear for each shift variant (SLL, SRL, SRA). For each
/// operation there is one univariate challenge `r_zhat_prime` at which to
/// construct the three h multilinears.
///
/// # Usage in Protocol
///
/// Used in phase 1, thus returning a `MultilinearTriplet` defined in `super::phase_1`.
#[instrument(skip_all, name = "build_h_triplet")]
pub fn build_h_triplet<F: BinaryField, P: PackedField<Scalar = F>>(
	r_zhat_prime: F,
) -> Result<MultilinearTriplet<P>, Error> {
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let l_tilde = lagrange_evals(&subspace, r_zhat_prime);

	let [mut sll_data, mut srl_data, mut sra_data] =
		array::from_fn(|_| Vec::with_capacity(WORD_SIZE_BITS * WORD_SIZE_BITS));

	for s in 0..WORD_SIZE_BITS {
		for j in 0..WORD_SIZE_BITS {
			sll_data.push(if j + s < l_tilde.len() {
				l_tilde[j + s]
			} else {
				F::ZERO
			});

			let val = if j >= s { l_tilde[j - s] } else { F::ZERO };
			srl_data.push(val);
			sra_data.push(val);
		}
	}

	for s in 1..WORD_SIZE_BITS {
		let msb_idx = s * WORD_SIZE_BITS + WORD_SIZE_BITS - 1;
		let prev_val = sra_data[msb_idx - WORD_SIZE_BITS];
		sra_data[msb_idx] += prev_val;
	}

	let sll = FieldBuffer::from_values(&sll_data)?;
	let srl = FieldBuffer::from_values(&srl_data)?;
	let sra = FieldBuffer::from_values(&sra_data)?;

	Ok(MultilinearTriplet { sll, srl, sra })
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, PackedBinaryGhash2x128b, Random};
	use binius_math::{inner_product::inner_product_buffers, multilinear::eq::eq_ind_partial_eval};
	use binius_verifier::protocols::shift::evaluate_h_op;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	/// Test consistency between direct multilinear evaluation of h
	/// multilinears and the succinct `evaluate_h_op` implementation
	#[test]
	fn h_op_consistency() {
		type F = BinaryField128bGhash;
		type P = PackedBinaryGhash2x128b;

		let mut rng = StdRng::seed_from_u64(0);

		let num_random_tests = 10;

		for test_case in 0..num_random_tests {
			let r_zhat_prime = F::random(&mut rng);

			let r_j: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();
			let r_s: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();

			// Method 1: Succinct evaluation using `evaluate_h_op`
			let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
			let l_tilde = lagrange_evals(&subspace, r_zhat_prime);
			let succinct_evaluations = evaluate_h_op(&l_tilde, &r_j, &r_s);

			// Method 2: Direct evaluation via multilinear triplet
			let h_triplet = build_h_triplet(r_zhat_prime).unwrap();
			let evaluation_point: Vec<F> = [r_j.clone(), r_s.clone()].concat();
			let tensor = eq_ind_partial_eval::<P>(&evaluation_point);

			let direct_evaluations = [h_triplet.sll, h_triplet.srl, h_triplet.sra]
				.map(|buf| inner_product_buffers(&buf, &tensor));

			assert_eq!(
				succinct_evaluations, direct_evaluations,
				"H-op evaluation mismatch (test_case={test_case}): succinct != direct",
			);
		}
	}
}

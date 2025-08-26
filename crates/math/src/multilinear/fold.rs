// Copyright 2024-2025 Irreducible Inc.

use std::ops::{Deref, DerefMut};

use binius_field::{Field, PackedField};
use binius_utils::{random_access_sequence::RandomAccessSequence, rayon::prelude::*};

use crate::{Error, FieldBuffer};

/// Computes the partial evaluation of a multilinear on its highest variable, inplace.
///
/// Each scalar of the result requires one multiplication to compute. Multilinear evaluations
/// occupy a prefix of the field buffer; scalars after the truncated length are zeroed out.
pub fn fold_highest_var_inplace<P: PackedField, Data: DerefMut<Target = [P]>>(
	values: &mut FieldBuffer<P, Data>,
	scalar: P::Scalar,
) -> Result<(), Error> {
	let broadcast_scalar = P::broadcast(scalar);
	values.split_half_mut(|lo, hi| {
		(lo.as_mut(), hi.as_mut())
			.into_par_iter()
			.for_each(|(zero, one)| {
				*zero += broadcast_scalar * (*one - *zero);
			});
	})?;

	values.truncate(values.log_len() - 1);
	Ok(())
}

/// Computes the fold high of a binary multilinear with a fold tensor.
///
/// Binary multilinear is represented transparently by a boolean sequence.
/// Fold high meaning: for every hypercube vertex of the result, we specialize lower
/// indexed variables of the binary multilinear to the vertex coordinates and take an
/// inner product of the remaining multilinear and the tensor.
///
/// This method is single threaded.
///
/// # Throws
///
/// * `PowerOfTwoLengthRequired` if the bool sequence is not of power of two length.
/// * `FoldLengthMismatch` if the tensor, result and binary multilinear lengths do not add up.
pub fn binary_fold_high<P, DataOut, DataIn>(
	values: &mut FieldBuffer<P, DataOut>,
	tensor: &FieldBuffer<P, DataIn>,
	bits: impl RandomAccessSequence<bool> + Sync,
) -> Result<(), Error>
where
	P: PackedField,
	DataOut: DerefMut<Target = [P]>,
	DataIn: Deref<Target = [P]> + Sync,
{
	if !bits.len().is_power_of_two() {
		return Err(Error::PowerOfTwoLengthRequired);
	}

	let values_log_len = values.log_len();
	let width = P::WIDTH.min(values.len());

	if 1 << (values_log_len + tensor.log_len()) != bits.len() {
		return Err(Error::FoldLengthMismatch);
	}

	values
		.as_mut()
		.iter_mut()
		.enumerate()
		.for_each(|(i, packed)| {
			*packed = P::from_scalars((0..width).map(|j| {
				let scalar_index = i << P::LOG_WIDTH | j;
				let mut acc = P::Scalar::ZERO;

				for (k, tensor_packed) in tensor.as_ref().iter().enumerate() {
					for (l, tensor_scalar) in tensor_packed.iter().take(tensor.len()).enumerate() {
						let tensor_scalar_index = k << P::LOG_WIDTH | l;
						if bits.get(tensor_scalar_index << values_log_len | scalar_index) {
							acc += tensor_scalar;
						}
					}
				}

				acc
			}));
		});

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::iter::repeat_with;

	use rand::prelude::*;

	use super::*;
	use crate::{
		multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate},
		test_utils::{B128, Packed128b, random_field_buffer, random_scalars},
	};

	type P = Packed128b;
	type F = B128;

	#[test]
	fn test_fold_highest_var_inplace() {
		let mut rng = StdRng::seed_from_u64(0);

		let n_vars = 10;

		let point = random_scalars::<F>(&mut rng, n_vars);
		let mut multilinear = random_field_buffer::<P>(&mut rng, n_vars);

		let eval = evaluate(&multilinear, &point).unwrap();

		for &scalar in point.iter().rev() {
			fold_highest_var_inplace(&mut multilinear, scalar).unwrap();
		}

		assert_eq!(multilinear.get(0).unwrap(), eval);
	}

	fn test_binary_fold_high_conforms_to_regular_fold_high_helper(
		n_vars: usize,
		tensor_n_vars: usize,
	) {
		let mut rng = StdRng::seed_from_u64(0);

		let point = random_scalars::<F>(&mut rng, tensor_n_vars);

		let tensor = eq_ind_partial_eval::<P>(&point);

		let bits = repeat_with(|| rng.random())
			.take(1 << n_vars)
			.collect::<Vec<bool>>();

		let bits_scalars = bits
			.iter()
			.map(|&b| if b { F::ONE } else { F::ZERO })
			.collect::<Vec<F>>();

		let mut bits_buffer = FieldBuffer::<P>::from_values(&bits_scalars).unwrap();

		let mut binary_fold_result = FieldBuffer::<P>::zeros(n_vars - tensor_n_vars);
		binary_fold_high(&mut binary_fold_result, &tensor, bits.as_slice()).unwrap();

		for &scalar in point.iter().rev() {
			fold_highest_var_inplace(&mut bits_buffer, scalar).unwrap();
		}

		assert_eq!(bits_buffer, binary_fold_result);
	}

	#[test]
	fn test_binary_fold_high_conforms_to_regular_fold_high() {
		for (n_vars, tensor_n_vars) in [(2, 0), (2, 1), (4, 4), (10, 3)] {
			test_binary_fold_high_conforms_to_regular_fold_high_helper(n_vars, tensor_n_vars)
		}
	}
}

// Copyright 2024-2025 Irreducible Inc.

use std::ops::DerefMut;

use binius_field::PackedField;
use binius_maybe_rayon::prelude::*;

use crate::{Error, FieldBuffer};

/// Computes the partial evaluation of a multilinear on its highest variable, inplace.
///
/// Each scalar of the result requires one multiplication to compute. Multilinear evaluations
/// occupy a prefix of the field buffer; scalars after the truncated length are zeroed out.
pub fn fold_highest_var_inplace<P: PackedField, Data: DerefMut<Target = [P]>>(
	log_n_values: usize,
	values: &mut FieldBuffer<P, Data>,
	scalar: P::Scalar,
) -> Result<(), Error> {
	if log_n_values > values.log_len() {
		return Err(Error::IncorrectArgumentLength {
			arg: "values".to_string(),
			expected: 1 << log_n_values,
		});
	}

	if values.log_len() > log_n_values {
		return values
			.split_half_mut(|lo, _| fold_highest_var_inplace(log_n_values, lo, scalar))?;
	}

	let broadcast_scalar = P::broadcast(scalar);
	values.split_half_mut(|lo, hi| {
		(lo.as_mut(), hi.as_mut())
			.into_par_iter()
			.for_each(|(zero, one)| {
				*zero += broadcast_scalar * (*one - *zero);
				*one = P::zero();
			});
	})
}

#[cfg(test)]
mod tests {
	use std::iter;

	use binius_field::{Field, PackedBinaryField4x32b};
	use rand::prelude::*;

	use super::*;
	use crate::{multilinear::eq::eq_ind_partial_eval, test_utils::random_scalars};

	type P = PackedBinaryField4x32b;
	type F = <P as PackedField>::Scalar;

	#[test]
	fn test_fold_highest_var_inplace() {
		let mut rng = StdRng::seed_from_u64(0);

		let n_vars = 10;

		let point = random_scalars::<F>(&mut rng, n_vars);
		let mut multilinear =
			FieldBuffer::<P>::from_values(&random_scalars(&mut rng, 1 << n_vars)).unwrap();

		let eq_ind = eq_ind_partial_eval::<P>(&point);
		let eval = iter::zip(eq_ind.as_ref(), multilinear.as_ref())
			.fold(P::zero(), |sum, (&l, &r)| sum + l * r)
			.iter()
			.sum();

		for (prefix, &scalar) in point.iter().enumerate().rev() {
			fold_highest_var_inplace(prefix + 1, &mut multilinear, scalar).unwrap();
		}

		assert!((1..1 << n_vars).all(|i| multilinear.get(i).unwrap() == F::ZERO));
		assert_eq!(multilinear.get(0).unwrap(), eval);
	}
}

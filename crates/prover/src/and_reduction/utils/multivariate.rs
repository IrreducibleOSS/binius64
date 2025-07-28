use binius_field::{
	BinaryField1b, Field, PackedAESBinaryField16x8b, PackedBinaryField128x1b, PackedExtension,
	packed::iter_packed_slice_with_offset,
};
use binius_math::FieldBuffer;
use binius_utils::rayon::prelude::{
	IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::and_reduction::fold_lookup::FoldLookup;

// ALL FOLDING IS LOW TO HIGH
/// Represents a OblongMultilinear polynomial with binary (0/1) coefficients.
///
/// This struct stores the evaluations of a OblongMultilinear polynomial over the binary hypercube
/// in a packed format for efficient processing. The polynomial can be partially evaluated
/// (folded) on its first variable using either a naive approach or an optimized lookup table.
#[derive(Debug, Clone)]
pub struct OneBitOblongMultilinear {
	/// Logarithm base 2 of the number of rows (evaluations) in the polynomial.
	/// The total number of evaluations is 2^log_num_rows.
	pub log_num_rows: usize,
	/// Packed binary field elements storing the polynomial evaluations.
	/// Each element contains 128 binary values packed together for SIMD efficiency.
	pub packed_evals: Vec<PackedBinaryField128x1b>,
}

impl OneBitOblongMultilinear {
	/// Performs partial evaluation of the OblongMultilinear polynomial on its first variable using
	/// a lookup table.
	///
	/// This method is the optimized version of `fold_naive`, using a precomputed lookup table
	/// for efficient evaluation. It evaluates the polynomial at the challenge point that was
	/// used to construct the lookup table.
	///
	/// # Type Parameters
	/// * `F` - The field type for the evaluation result
	/// * `LOG_FIRST_VARIABLE_DEGREE_BOUND` - The logarithm base 2 of the degree bound for the first
	///   variable
	///
	/// # Arguments
	/// * `lookup` - The precomputed lookup table for the evaluation point
	///
	/// # Returns
	/// A `FieldBuffer` containing the evaluations of the partially evaluated polynomial
	/// over the remaining variables.
	#[allow(clippy::modulo_one)]
	pub fn fold<F, const LOG_FIRST_VARIABLE_DEGREE_BOUND: usize>(
		&self,
		lookup: &FoldLookup<F, LOG_FIRST_VARIABLE_DEGREE_BOUND>,
	) -> FieldBuffer<F>
	where
		F: Field + std::iter::Sum<F>,
	{
		let _span = tracing::debug_span!("fold").entered();

		let new_n_vars = self.log_num_rows - LOG_FIRST_VARIABLE_DEGREE_BOUND;

		#[allow(non_snake_case)]
		let FIRST_VARIABLE_DEGREE_BOUND = 1 << LOG_FIRST_VARIABLE_DEGREE_BOUND;

		let mut multilin = FieldBuffer::zeros(new_n_vars);

		let bytes_per_group = FIRST_VARIABLE_DEGREE_BOUND / 8;

		let packed_evals_as_bytes =
			<PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
				&self.packed_evals,
			);

		multilin.as_mut().par_iter_mut().enumerate().for_each(
			|(group_idx, hypercube_vertex_val)| {
				let this_group_byte_chunks = iter_packed_slice_with_offset(
					packed_evals_as_bytes,
					group_idx * bytes_per_group,
				)
				.take(bytes_per_group);

				*hypercube_vertex_val =
					lookup.fold_one_bit_univariate(this_group_byte_chunks.map(u8::from));
			},
		);
		multilin
	}
}

#[cfg(test)]
mod test {
	use binius_field::{
		BinaryField, Field, PackedBinaryField128x1b, Random, packed::iter_packed_slice_with_offset,
	};
	use binius_math::{BinarySubspace, FieldBuffer};
	use binius_verifier::{
		and_reduction::{
			univariate::univariate_lagrange::lexicographic_lagrange_basis_vectors,
			utils::constants::SKIPPED_VARS,
		},
		fields::B128,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::OneBitOblongMultilinear;
	use crate::and_reduction::fold_lookup::FoldLookup;

	// Performs partial evaluation of the OblongMultilinear polynomial on its first variable using
	/// a naive approach.
	///
	/// This method evaluates the polynomial at a given challenge point for the first variable,
	/// effectively reducing the number of variables by `LOG_FIRST_VARIABLE_DEGREE_BOUND`.
	/// It uses direct Lagrange interpolation without precomputation.
	///
	/// # Type Parameters
	/// * `FDomain` - The field type for the univariate domain
	/// * `F` - The field type for the evaluation result
	/// * `LOG_FIRST_VARIABLE_DEGREE_BOUND` - The logarithm base 2 of the degree bound for the first
	///   variable
	///
	/// # Arguments
	/// * `univariate_domain` - The domain over which the first variable is defined
	/// * `challenge` - The point at which to evaluate the first variable
	///
	/// # Returns
	/// A `FieldBuffer` containing the evaluations of the partially evaluated polynomial
	/// over the remaining variables.
	#[allow(clippy::modulo_one)]
	pub fn fold_naive<F, const LOG_FIRST_VARIABLE_DEGREE_BOUND: usize>(
		one_bit_oblong: &OneBitOblongMultilinear,
		univariate_domain: &BinarySubspace<F>,
		challenge: F,
	) -> FieldBuffer<F>
	where
		F: BinaryField + Field,
	{
		let new_n_vars = one_bit_oblong.log_num_rows - LOG_FIRST_VARIABLE_DEGREE_BOUND;

		#[allow(non_snake_case)]
		let FIRST_VARIABLE_DEGREE_BOUND = 1 << LOG_FIRST_VARIABLE_DEGREE_BOUND;

		let mut multilin = FieldBuffer::zeros(new_n_vars);

		let lagrange_basis_vectors =
			lexicographic_lagrange_basis_vectors::<F, F>(challenge, univariate_domain);

		multilin
			.as_mut()
			.iter_mut()
			.enumerate()
			.for_each(|(group_idx, hypercube_vertex_val)| {
				let this_group_bit_coefficients = iter_packed_slice_with_offset(
					&one_bit_oblong.packed_evals,
					group_idx * FIRST_VARIABLE_DEGREE_BOUND,
				);

				*hypercube_vertex_val = lagrange_basis_vectors
					.iter()
					.zip(this_group_bit_coefficients)
					.map(|(basis_vec, coeff)| *basis_vec * coeff)
					.sum();
			});
		multilin
	}

	#[test]
	fn test_lookup_fold() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);
		let mlv = OneBitOblongMultilinear {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		};

		let challenge = B128::random(&mut rng);

		let univariate_domain = BinarySubspace::with_dim(SKIPPED_VARS).unwrap();

		let lookup = FoldLookup::<_, SKIPPED_VARS>::new(&univariate_domain, challenge);

		let folded_naive = fold_naive::<B128, SKIPPED_VARS>(&mlv, &univariate_domain, challenge);

		let folded_smart = mlv.fold(&lookup);

		for i in 0..1 << (log_num_rows - SKIPPED_VARS) {
			assert_eq!(folded_naive.as_ref()[i], folded_smart.as_ref()[i]);
		}
	}
}

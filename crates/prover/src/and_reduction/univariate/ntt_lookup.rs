//! # NTT Lookup Table Module
//!
//! This module provides a precomputed lookup table implementation for fast Number Theoretic
//! Transform (NTT) operations on 64-bit binary field elements. The implementation is specifically
//! optimized for the Binius64 protocol's constraint system.
//!
//! ## Overview
//!
//! The NTT lookup table achieves significant performance improvements by precomputing all possible
//! NTT evaluations for 8-bit input chunks. This allows the full 64-bit NTT to be computed by:
//!
//! 1. Splitting the 64 input bits into eight 8-bit chunks
//! 2. Looking up precomputed NTT values for each chunk
//! 3. Adding the results together (exploiting the linearity of the NTT)
//!
//! ## Algorithm
//!
//! The implementation uses additive NTT over binary fields, which is a linear transformation that
//! converts between coefficient and evaluation representations of polynomials. The specific
//! approach:
//!
//! - **Input**: 64 1-bit coefficients representing a polynomial in the Lagrange basis
//! - **Output**: 64 evaluations of the polynomial at specified domain points
//! - **Optimization**: Precomputes all 256 possible evaluations for each 8-bit position
//!
//! ## Performance
//!
//! By precomputing the lookup tables, the NTT operation is reduced to:
//! - 8 table lookups (one per byte)
//! - 7 packed field additions
//!
//! This trades memory (storing 8 * 256 * 64 field elements) for significant computation savings
//! compared to computing the NTT from scratch.

use std::vec;

use binius_field::{
	BinaryField, BinaryField1b, Field, PackedBinaryField8x1b, PackedField, packed::set_packed_slice,
};
use binius_math::BinarySubspace;
use binius_verifier::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators,
	},
	utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
};

/// A precomputed lookup table for fast NTT operations on 64-bit binary field elements.
///
/// This structure stores precomputed NTT evaluations for all possible 8-bit input combinations,
/// enabling fast computation of the full 64-bit NTT through table lookups and additions.
///
/// ## Structure
///
/// The internal data structure is a 3-dimensional vector `Vec<Vec<Vec<P>>>` where:
/// - **First dimension**: Index of the 8-bit chunk within the 64-bit input (0-7)
/// - **Second dimension**: The 8-bit value (0-255) representing coefficient combinations
/// - **Third dimension**: Packed field elements containing the NTT evaluations
///
/// ## Memory Layout
///
/// For each of the 8 byte positions and 256 possible byte values, we store
/// `ROWS_PER_HYPERCUBE_VERTEX / PackedField::WIDTH` packed field elements containing
/// the precomputed NTT evaluations.
///
/// ## Type Parameters
///
/// - `P`: The packed field type used for storing precomputed values. Must implement `PackedField`
///   with a scalar type that is a binary field.
#[derive(Clone)]
pub struct NTTLookup<P>(Vec<Vec<Vec<P>>>);

impl<PNTTDomain> NTTLookup<PNTTDomain>
where
	PNTTDomain: PackedField,
	PNTTDomain::Scalar: BinaryField + Field,
{
	/// Creates a new NTT lookup table by precomputing all possible NTT evaluations
	/// for 8-bit input chunks across all byte positions in a 64-bit word.
	///
	/// ## Parameters
	///
	/// - `ntt_input_domain`: Binary subspace defining the input domain for the NTT. Must have
	///   dimension `SKIPPED_VARS` (6 bits).
	/// - `ntt_output_domain`: Array of field elements where the NTT will be evaluated. Must have
	///   length `ROWS_PER_HYPERCUBE_VERTEX` (64 elements).
	///
	/// ## Constraints
	///
	/// - `PNTTDomain::WIDTH` must equal 16 (packed field constraint)
	/// - Input domain dimension must equal `SKIPPED_VARS` (6)
	/// - Output domain length must equal `ROWS_PER_HYPERCUBE_VERTEX` (64)
	pub fn new(
		ntt_input_domain: &BinarySubspace<PNTTDomain::Scalar>,
		ntt_output_domain: &[PNTTDomain::Scalar],
	) -> Self {
		assert_eq!(PNTTDomain::WIDTH, 16);
		assert_eq!(ntt_output_domain.len(), ROWS_PER_HYPERCUBE_VERTEX);
		assert_eq!(ntt_input_domain.dim(), SKIPPED_VARS);

		let _span = tracing::debug_span!("precompute_lookup").entered();

		let mut lookup =
			vec![
				vec![vec![PNTTDomain::zero(); ntt_output_domain.len() / PNTTDomain::WIDTH]; 1 << 8];
				ROWS_PER_HYPERCUBE_VERTEX / 8
			];

		let mut eval_point_basis_point_to_numerator =
			vec![
				vec![PNTTDomain::Scalar::ZERO; ROWS_PER_HYPERCUBE_VERTEX];
				ntt_output_domain.len()
			];
		let denominator: PNTTDomain::Scalar = lexicographic_lagrange_denominator(ntt_input_domain);

		let inverse_denominator = denominator.invert_or_zero();
		for (eval_point_idx, eval_point) in ntt_output_domain.iter().enumerate() {
			eval_point_basis_point_to_numerator[eval_point_idx] =
				lexicographic_lagrange_numerators::<PNTTDomain::Scalar, PNTTDomain::Scalar>(
					*eval_point,
					ntt_input_domain,
				);
		}

		for eight_bit_chunk_idx in 0..ROWS_PER_HYPERCUBE_VERTEX / 8 {
			for log_coefficient_as_bit_string in 0..8 {
				let coefficient_as_bit_string = 1 << log_coefficient_as_bit_string;
				let nonzero_lagrange_basis_coeffs: Vec<_> =
					PackedBinaryField8x1b::from_underlier(coefficient_as_bit_string)
						.iter()
						.collect();
				let mut lagrange_basis_coeffs = [BinaryField1b::ZERO; ROWS_PER_HYPERCUBE_VERTEX];

				for (i, nonzero_lagrange_basis_coeff) in
					nonzero_lagrange_basis_coeffs.into_iter().enumerate()
				{
					lagrange_basis_coeffs[eight_bit_chunk_idx * 8 + i] =
						nonzero_lagrange_basis_coeff;
				}

				#[allow(clippy::needless_range_loop)]
				for eval_point_idx in 0..ROWS_PER_HYPERCUBE_VERTEX {
					let mut result = PNTTDomain::Scalar::ZERO;
					for basis_point_idx in 0..1 << ntt_input_domain.dim() {
						result += (eval_point_basis_point_to_numerator[eval_point_idx]
							[basis_point_idx] * lagrange_basis_coeffs[basis_point_idx])
							* inverse_denominator;
					}
					set_packed_slice(
						&mut lookup[eight_bit_chunk_idx][coefficient_as_bit_string as usize],
						eval_point_idx,
						result,
					);
				}
			}
		}

		for this_byte_lookup in lookup.iter_mut() {
			for coefficient_as_bit_string in 0..1 << 8 {
				let mut result =
					vec![PNTTDomain::zero(); ROWS_PER_HYPERCUBE_VERTEX / PNTTDomain::WIDTH];
				for bit_in_string in 0..8 {
					let this_one_hot = coefficient_as_bit_string & 1 << bit_in_string;
					for (i, result_packed_elem) in result.iter_mut().enumerate() {
						*result_packed_elem += this_byte_lookup[this_one_hot][i];
					}
				}
				this_byte_lookup[coefficient_as_bit_string] = result;
			}
		}
		NTTLookup(lookup)
	}

	/// Computes the NTT of 64 1-bit coefficients using precomputed lookup tables.
	///
	/// Takes 64 1-bit coefficients provided as eight 8-bit chunks and computes their
	/// NTT by looking up precomputed values and adding them together, exploiting
	/// the linearity of the NTT operation.
	///
	/// Mathematically, if the input coefficients are c₀, c₁, ..., c₆₃, grouped into
	/// bytes B₀, B₁, ..., B₇, then NTT(c) = NTT(B₀) + NTT(B₁) + ... + NTT(B₇)
	/// where each NTT(Bᵢ) is retrieved from the precomputed lookup table.
	///
	/// ## Parameters
	///
	/// - `coeffs_in_byte_chunks`: Iterator yielding exactly 8 bytes, where each byte represents 8
	///   consecutive 1-bit coefficients from the 64-bit input.
	///
	/// ## Returns
	///
	/// Array of `ROWS_PER_HYPERCUBE_VERTEX / 16` packed field elements containing
	/// the NTT evaluations at all points in the output domain.
	#[inline]
	pub fn ntt(
		&self,
		coeffs_in_byte_chunks: impl IntoIterator<Item = u8>,
	) -> [PNTTDomain; ROWS_PER_HYPERCUBE_VERTEX / 16] {
		let mut result = [PNTTDomain::zero(); ROWS_PER_HYPERCUBE_VERTEX / 16];

		for (eight_bit_chunk_idx, eight_bit_chunk) in coeffs_in_byte_chunks.into_iter().enumerate()
		{
			for j in 0..ROWS_PER_HYPERCUBE_VERTEX / 16 {
				result[j] += self.0[eight_bit_chunk_idx][eight_bit_chunk as usize][j];
			}
		}

		result
	}
}

#[cfg(test)]
mod test {
	use std::iter::repeat_with;

	use binius_field::{
		AESTowerField8b, Field, PackedAESBinaryField16x8b, PackedBinaryField8x1b, PackedField,
		Random,
		packed::{get_packed_slice, set_packed_slice},
	};
	use binius_math::{
		BinarySubspace,
		ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT},
	};
	use binius_verifier::{and_reduction::utils::constants::SKIPPED_VARS, config::B1};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::{NTTLookup, ROWS_PER_HYPERCUBE_VERTEX};

	/// Tests NTT accuracy on a well-known polynomial with a single coefficient set.
	///
	/// This test verifies the lookup table produces correct results by comparing
	/// against the expected mathematical result for a simple input polynomial.
	#[test]
	fn assert_accurate_ntt_on_well_known_poly() {
		let input_domain: Vec<_> = (0..SKIPPED_VARS)
			.map(|x| AESTowerField8b::new(1 << x as u8))
			.collect();

		let input_domain = BinarySubspace::new_unchecked(input_domain);

		let output_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let lookup = NTTLookup::new(&input_domain, &output_domain);

		let mut slice_to_ntt: [u8; _] = [0; ROWS_PER_HYPERCUBE_VERTEX / 8];
		slice_to_ntt[0] = 1;
		let results: [PackedAESBinaryField16x8b; _] = lookup.ntt(slice_to_ntt);

		for (i, input) in output_domain.iter().enumerate() {
			let expected_result = (1..ROWS_PER_HYPERCUBE_VERTEX)
				.map(|basis_idx| {
					let field_elem = AESTowerField8b::new(basis_idx as u8);
					(*input - field_elem) * field_elem.invert_or_zero()
				})
				.product::<AESTowerField8b>();

			assert_eq!(get_packed_slice(&results, i), expected_result);
		}
	}

	#[test]
	fn test_against_binius_ntt() {
		let mut rng = StdRng::from_seed([0; 32]);
		let mut coeffs = (0..ROWS_PER_HYPERCUBE_VERTEX)
			.map(|_| AESTowerField8b::from(B1::random(&mut rng)))
			.collect_vec();

		let mut coeffs_packed = vec![PackedBinaryField8x1b::zero(); ROWS_PER_HYPERCUBE_VERTEX / 8];

		for (i, coeff) in coeffs.iter().enumerate() {
			set_packed_slice(&mut coeffs_packed, i, B1::from(u8::from(*coeff)));
		}

		let coeffs_packed_iter_u8 = coeffs_packed.iter().map(|i| i.to_underlier());

		let input_domain: Vec<_> = (0..SKIPPED_VARS)
			.map(|x| AESTowerField8b::new(1 << x as u8))
			.collect();

		let input_domain = BinarySubspace::new_unchecked(input_domain);

		let output_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();
		println!("start precompute");
		let ntt_lookup = NTTLookup::<PackedAESBinaryField16x8b>::new(&input_domain, &output_domain);
		println!("done precompute");

		let ntt_lookup_result = ntt_lookup.ntt(coeffs_packed_iter_u8);

		let input_subspace = BinarySubspace::new_unchecked(
			(0..SKIPPED_VARS)
				.map(|i| AESTowerField8b::from(1 << i))
				.collect_vec(),
		);

		let input_ntt = SingleThreadedNTT::with_subspace(&input_subspace).unwrap();

		input_ntt
			.inverse_transform(
				&mut coeffs,
				NTTShape {
					log_x: 0,
					log_y: SKIPPED_VARS,
					log_z: 0,
				},
				0,
				0,
				0,
			)
			.unwrap();

		let output_subspace = BinarySubspace::new_unchecked(
			(0..SKIPPED_VARS + 1)
				.map(|i| AESTowerField8b::from((1 << i) as u8))
				.collect_vec(),
		);

		coeffs.extend(repeat_with(|| AESTowerField8b::ZERO).take(ROWS_PER_HYPERCUBE_VERTEX));

		let output_ntt = SingleThreadedNTT::with_subspace(&output_subspace).unwrap();

		output_ntt
			.forward_transform(
				&mut coeffs,
				NTTShape {
					log_x: 0,
					log_y: SKIPPED_VARS + 1,
					log_z: 0,
				},
				0,
				0,
				0,
			)
			.unwrap();

		for (i, coeff) in coeffs.iter().skip(ROWS_PER_HYPERCUBE_VERTEX).enumerate() {
			let lookup_result = get_packed_slice(&ntt_lookup_result, i);
			assert_eq!(lookup_result, *coeff);
		}
	}
}

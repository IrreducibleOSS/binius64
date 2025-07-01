// Copyright 2024-2025 Irreducible Inc.

use binius_maybe_rayon::prelude::{
	IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::{Error, ExtensionField, Field, PackedExtension, PackedField};

pub fn ext_base_mul<PE: PackedExtension<F>, F: Field>(
	lhs: &mut [PE],
	rhs: &[PE::PackedSubfield],
) -> Result<(), Error> {
	ext_base_op(lhs, rhs, |_, lhs, broadcasted_rhs| PE::cast_ext(lhs.cast_base() * broadcasted_rhs))
}

pub fn ext_base_mul_par<PE: PackedExtension<F>, F: Field>(
	lhs: &mut [PE],
	rhs: &[PE::PackedSubfield],
) -> Result<(), Error> {
	ext_base_op_par(lhs, rhs, |_, lhs, broadcasted_rhs| {
		PE::cast_ext(lhs.cast_base() * broadcasted_rhs)
	})
}

/// # Safety
///
/// Width of PackedSubfield is >= the width of the field implementing PackedExtension.
pub unsafe fn get_packed_subfields_at_pe_idx<PE: PackedExtension<F>, F: Field>(
	packed_subfields: &[PE::PackedSubfield],
	i: usize,
) -> PE::PackedSubfield {
	let bottom_most_scalar_idx = i * PE::WIDTH;
	let bottom_most_scalar_idx_in_subfield_arr = bottom_most_scalar_idx / PE::PackedSubfield::WIDTH;
	let bottom_most_scalar_idx_within_packed_subfield =
		bottom_most_scalar_idx % PE::PackedSubfield::WIDTH;
	let block_idx = bottom_most_scalar_idx_within_packed_subfield / PE::WIDTH;

	unsafe {
		packed_subfields
			.get_unchecked(bottom_most_scalar_idx_in_subfield_arr)
			.spread_unchecked(PE::LOG_WIDTH, block_idx)
	}
}

/// Refer to the functions above for examples of closures to pass
/// Func takes in the following parameters
///
/// Note that this function overwrites the lhs buffer, copy that data before
/// invoking this function if you need to use it elsewhere
///
/// lhs: PE::WIDTH extension field scalars
///
/// broadcasted_rhs: a broadcasted version of PE::WIDTH subfield scalars
/// with each one occurring PE::PackedSubfield::WIDTH/PE::WIDTH times in  a row
/// such that the bits of the broadcasted scalars align with the lhs scalars
pub fn ext_base_op<PE, F, Func>(
	lhs: &mut [PE],
	rhs: &[PE::PackedSubfield],
	op: Func,
) -> Result<(), Error>
where
	PE: PackedExtension<F>,
	F: Field,
	Func: Fn(usize, PE, PE::PackedSubfield) -> PE,
{
	if lhs.len() != rhs.len() * PE::Scalar::DEGREE {
		return Err(Error::MismatchedLengths);
	}

	lhs.iter_mut().enumerate().for_each(|(i, lhs_elem)| {
		// SAFETY: Width of PackedSubfield is always >= the width of the field implementing
		// PackedExtension
		let broadcasted_rhs = unsafe { get_packed_subfields_at_pe_idx::<PE, F>(rhs, i) };

		*lhs_elem = op(i, *lhs_elem, broadcasted_rhs);
	});
	Ok(())
}

/// A multithreaded version of the function directly above, use for long arrays
/// on the prover side
pub fn ext_base_op_par<PE, F, Func>(
	lhs: &mut [PE],
	rhs: &[PE::PackedSubfield],
	op: Func,
) -> Result<(), Error>
where
	PE: PackedExtension<F>,
	F: Field,
	Func: Fn(usize, PE, PE::PackedSubfield) -> PE + std::marker::Sync,
{
	if lhs.len() != rhs.len() * PE::Scalar::DEGREE {
		return Err(Error::MismatchedLengths);
	}

	lhs.par_iter_mut().enumerate().for_each(|(i, lhs_elem)| {
		// SAFETY: Width of PackedSubfield is always >= the width of the field implementing
		// PackedExtension
		let broadcasted_rhs = unsafe { get_packed_subfields_at_pe_idx::<PE, F>(rhs, i) };

		*lhs_elem = op(i, *lhs_elem, broadcasted_rhs);
	});

	Ok(())
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;

	use crate::{
		BinaryField8b, BinaryField16b, BinaryField128b, PackedBinaryField2x128b,
		PackedBinaryField16x16b, PackedBinaryField32x8b, ext_base_mul, ext_base_mul_par,
		packed::{get_packed_slice, pack_slice},
		underlier::WithUnderlier,
	};

	fn strategy_8b_scalars() -> impl Strategy<Value = [BinaryField8b; 32]> {
		any::<[<BinaryField8b as WithUnderlier>::Underlier; 32]>()
			.prop_map(|arr| arr.map(<BinaryField8b>::from_underlier))
	}

	fn strategy_16b_scalars() -> impl Strategy<Value = [BinaryField16b; 32]> {
		any::<[<BinaryField16b as WithUnderlier>::Underlier; 32]>()
			.prop_map(|arr| arr.map(<BinaryField16b>::from_underlier))
	}

	fn strategy_128b_scalars() -> impl Strategy<Value = [BinaryField128b; 32]> {
		any::<[<BinaryField128b as WithUnderlier>::Underlier; 32]>()
			.prop_map(|arr| arr.map(<BinaryField128b>::from_underlier))
	}

	proptest! {
		#[test]
		fn test_base_ext_mul_8(base_scalars in strategy_8b_scalars(), ext_scalars in strategy_128b_scalars()){
			let base_packed = pack_slice::<PackedBinaryField32x8b>(&base_scalars);
			let mut ext_packed = pack_slice::<PackedBinaryField2x128b>(&ext_scalars);

			ext_base_mul(&mut ext_packed, &base_packed).unwrap();

			for (i, (base, ext)) in base_scalars.iter().zip(ext_scalars).enumerate(){
				assert_eq!(ext * *base, get_packed_slice(&ext_packed, i));
			}
		}

		#[test]
		fn test_base_ext_mul_16(base_scalars in strategy_16b_scalars(), ext_scalars in strategy_128b_scalars()){
			let base_packed = pack_slice::<PackedBinaryField16x16b>(&base_scalars);
			let mut ext_packed = pack_slice::<PackedBinaryField2x128b>(&ext_scalars);

			ext_base_mul(&mut ext_packed, &base_packed).unwrap();

			for (i, (base, ext)) in base_scalars.iter().zip(ext_scalars).enumerate(){
				assert_eq!(ext * *base, get_packed_slice(&ext_packed, i));
			}
		}


		#[test]
		fn test_base_ext_mul_par_8(base_scalars in strategy_8b_scalars(), ext_scalars in strategy_128b_scalars()){
			let base_packed = pack_slice::<PackedBinaryField32x8b>(&base_scalars);
			let mut ext_packed = pack_slice::<PackedBinaryField2x128b>(&ext_scalars);

			ext_base_mul_par(&mut ext_packed, &base_packed).unwrap();

			for (i, (base, ext)) in base_scalars.iter().zip(ext_scalars).enumerate(){
				assert_eq!(ext * *base, get_packed_slice(&ext_packed, i));
			}
		}

		#[test]
		fn test_base_ext_mul_par_16(base_scalars in strategy_16b_scalars(), ext_scalars in strategy_128b_scalars()){
			let base_packed = pack_slice::<PackedBinaryField16x16b>(&base_scalars);
			let mut ext_packed = pack_slice::<PackedBinaryField2x128b>(&ext_scalars);

			ext_base_mul_par(&mut ext_packed, &base_packed).unwrap();

			for (i, (base, ext)) in base_scalars.iter().zip(ext_scalars).enumerate(){
				assert_eq!(ext * *base, get_packed_slice(&ext_packed, i));
			}
		}
	}
}

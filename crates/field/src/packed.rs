// Copyright 2023-2025 Irreducible Inc.

//! Traits for packed field elements which support SIMD implementations.
//!
//! Interfaces are derived from [`plonky2`](https://github.com/mir-protocol/plonky2).

use std::{
	fmt::Debug,
	iter::{self, Product, Sum},
	ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use binius_utils::{
	iter::IterExtensions,
	random_access_sequence::{RandomAccessSequence, RandomAccessSequenceMut},
};
use bytemuck::Zeroable;

use super::{
	Error, Random,
	arithmetic_traits::{Broadcast, MulAlpha, Square},
	binary_field_arithmetic::TowerFieldArithmetic,
};
use crate::{
	BinaryField, Field, PackedExtension, arithmetic_traits::InvertOrZero,
	is_packed_field_indexable, underlier::WithUnderlier, unpack_if_possible_mut,
};

/// A packed field represents a vector of underlying field elements.
///
/// Arithmetic operations on packed field elements can be accelerated with SIMD CPU instructions.
/// The vector width is a constant, `WIDTH`. This trait requires that the width must be a power of
/// two.
pub trait PackedField:
	Default
	+ Debug
	+ Clone
	+ Copy
	+ Eq
	+ Sized
	+ Add<Output = Self>
	+ Sub<Output = Self>
	+ Mul<Output = Self>
	+ AddAssign
	+ SubAssign
	+ MulAssign
	+ Add<Self::Scalar, Output = Self>
	+ Sub<Self::Scalar, Output = Self>
	+ Mul<Self::Scalar, Output = Self>
	+ AddAssign<Self::Scalar>
	+ SubAssign<Self::Scalar>
	+ MulAssign<Self::Scalar>
	// TODO: Get rid of Sum and Product. It's confusing with nested impls of Packed.
	+ Sum
	+ Product
	+ Send
	+ Sync
	+ Zeroable
	+ Random
	+ 'static
{
	type Scalar: Field;

	/// Base-2 logarithm of the number of field elements packed into one packed element.
	const LOG_WIDTH: usize;

	/// The number of field elements packed into one packed element.
	///
	/// WIDTH is guaranteed to equal 2^LOG_WIDTH.
	const WIDTH: usize = 1 << Self::LOG_WIDTH;

	/// Get the scalar at a given index without bounds checking.
	/// # Safety
	/// The caller must ensure that `i` is less than `WIDTH`.
	unsafe fn get_unchecked(&self, i: usize) -> Self::Scalar;

	/// Set the scalar at a given index without bounds checking.
	/// # Safety
	/// The caller must ensure that `i` is less than `WIDTH`.
	unsafe fn set_unchecked(&mut self, i: usize, scalar: Self::Scalar);

	/// Get the scalar at a given index.
	#[inline]
	fn get_checked(&self, i: usize) -> Result<Self::Scalar, Error> {
		(i < Self::WIDTH)
			.then_some(unsafe { self.get_unchecked(i) })
			.ok_or(Error::IndexOutOfRange {
				index: i,
				max: Self::WIDTH,
			})
	}

	/// Set the scalar at a given index.
	#[inline]
	fn set_checked(&mut self, i: usize, scalar: Self::Scalar) -> Result<(), Error> {
		(i < Self::WIDTH)
			.then(|| unsafe { self.set_unchecked(i, scalar) })
			.ok_or(Error::IndexOutOfRange {
				index: i,
				max: Self::WIDTH,
			})
	}

	/// Get the scalar at a given index.
	#[inline]
	fn get(&self, i: usize) -> Self::Scalar {
		self.get_checked(i).expect("index must be less than width")
	}

	/// Set the scalar at a given index.
	#[inline]
	fn set(&mut self, i: usize, scalar: Self::Scalar) {
		self.set_checked(i, scalar).expect("index must be less than width")
	}

	#[inline]
	fn into_iter(self) -> impl Iterator<Item=Self::Scalar> + Send + Clone {
		(0..Self::WIDTH).map_skippable(move |i|
			// Safety: `i` is always less than `WIDTH`
			unsafe { self.get_unchecked(i) })
	}

	#[inline]
	fn iter(&self) -> impl Iterator<Item=Self::Scalar> + Send + Clone + '_ {
		(0..Self::WIDTH).map_skippable(move |i|
			// Safety: `i` is always less than `WIDTH`
			unsafe { self.get_unchecked(i) })
	}

	#[inline]
	fn iter_slice(slice: &[Self]) -> impl Iterator<Item=Self::Scalar> + Send + Clone + '_ {
		slice.iter().flat_map(Self::iter)
	}

	#[inline]
	fn zero() -> Self {
		Self::broadcast(Self::Scalar::ZERO)
	}

	#[inline]
	fn one() -> Self {
		Self::broadcast(Self::Scalar::ONE)
	}

	/// Initialize zero position with `scalar`, set other elements to zero.
	#[inline(always)]
	fn set_single(scalar: Self::Scalar) -> Self {
		let mut result = Self::default();
		result.set(0, scalar);

		result
	}

	fn broadcast(scalar: Self::Scalar) -> Self;

	/// Construct a packed field element from a function that returns scalar values by index.
	fn from_fn(f: impl FnMut(usize) -> Self::Scalar) -> Self;

	/// Creates a packed field from a fallible function applied to each index.
	fn try_from_fn<E>(
            mut f: impl FnMut(usize) -> Result<Self::Scalar, E>,
        ) -> Result<Self, E> {
            let mut result = Self::default();
            for i in 0..Self::WIDTH {
                let scalar = f(i)?;
                unsafe {
                    result.set_unchecked(i, scalar);
                };
            }
            Ok(result)
        }

	/// Construct a packed field element from a sequence of scalars.
	///
	/// If the number of values in the sequence is less than the packing width, the remaining
	/// elements are set to zero. If greater than the packing width, the excess elements are
	/// ignored.
	fn from_scalars(values: impl IntoIterator<Item=Self::Scalar>) -> Self {
		let mut result = Self::default();
		for (i, val) in values.into_iter().take(Self::WIDTH).enumerate() {
			result.set(i, val);
		}
		result
	}

	/// Returns the value multiplied by itself
	fn square(self) -> Self;

	/// Returns the value to the power `exp`.
	fn pow(self, exp: u64) -> Self {
		let mut res = Self::one();
		for i in (0..64).rev() {
			res = res.square();
			if ((exp >> i) & 1) == 1 {
				res.mul_assign(self)
			}
		}
		res
	}

	/// Returns the packed inverse values or zeroes at indices where `self` is zero.
	fn invert_or_zero(self) -> Self;

	/// Interleaves blocks of this packed vector with another packed vector.
	///
	/// The operation can be seen as stacking the two vectors, dividing them into 2x2 matrices of
	/// blocks, where each block is 2^`log_block_width` elements, and transposing the matrices.
	///
	/// Consider this example, where `LOG_WIDTH` is 3 and `log_block_len` is 1:
	///     A = [a0, a1, a2, a3, a4, a5, a6, a7]
	///     B = [b0, b1, b2, b3, b4, b5, b6, b7]
	///
	/// The interleaved result is
	///     A' = [a0, a1, b0, b1, a4, a5, b4, b5]
	///     B' = [a2, a3, b2, b3, a6, a7, b6, b7]
	///
	/// ## Preconditions
	/// * `log_block_len` must be strictly less than `LOG_WIDTH`.
	fn interleave(self, other: Self, log_block_len: usize) -> (Self, Self);

	/// Unzips interleaved blocks of this packed vector with another packed vector.
	/// 
	/// Consider this example, where `LOG_WIDTH` is 3 and `log_block_len` is 1:
	///    A = [a0, a1, b0, b1, a2, a3, b2, b3]
	///    B = [a4, a5, b4, b5, a6, a7, b6, b7]
	/// 
	/// The transposed result is
	///    A' = [a0, a1, a2, a3, a4, a5, a6, a7]
	///    B' = [b0, b1, b2, b3, b4, b5, b6, b7]
	///
	/// ## Preconditions
	/// * `log_block_len` must be strictly less than `LOG_WIDTH`.
	fn unzip(self, other: Self, log_block_len: usize) -> (Self, Self);

	/// Spread takes a block of elements within a packed field and repeats them to the full packing
	/// width.
	///
	/// Spread can be seen as an extension of the functionality of [`Self::broadcast`].
	///
	/// ## Examples
	///
	/// ```
	/// use binius_field::{BinaryField16b, PackedField, PackedBinaryField8x16b};
	///
	/// let input =
	///     PackedBinaryField8x16b::from_scalars([0, 1, 2, 3, 4, 5, 6, 7].map(BinaryField16b::new));
	/// assert_eq!(
	///     input.spread(0, 5),
	///     PackedBinaryField8x16b::from_scalars([5, 5, 5, 5, 5, 5, 5, 5].map(BinaryField16b::new))
	/// );
	/// assert_eq!(
	///     input.spread(1, 2),
	///     PackedBinaryField8x16b::from_scalars([4, 4, 4, 4, 5, 5, 5, 5].map(BinaryField16b::new))
	/// );
	/// assert_eq!(
	///     input.spread(2, 1),
	///     PackedBinaryField8x16b::from_scalars([4, 4, 5, 5, 6, 6, 7, 7].map(BinaryField16b::new))
	/// );
	/// assert_eq!(input.spread(3, 0), input);
	/// ```
	///
	/// ## Preconditions
	///
	/// * `log_block_len` must be less than or equal to `LOG_WIDTH`.
	/// * `block_idx` must be less than `2^(Self::LOG_WIDTH - log_block_len)`.
	#[inline]
	fn spread(self, log_block_len: usize, block_idx: usize) -> Self {
		assert!(log_block_len <= Self::LOG_WIDTH);
		assert!(block_idx < 1 << (Self::LOG_WIDTH - log_block_len));

		// Safety: is guaranteed by the preconditions.
		unsafe {
			self.spread_unchecked(log_block_len, block_idx)
		}
	}

	/// Unsafe version of [`Self::spread`].
	///
	/// # Safety
	/// The caller must ensure that `log_block_len` is less than or equal to `LOG_WIDTH` and `block_idx` is less than `2^(Self::LOG_WIDTH - log_block_len)`.
	#[inline]
	unsafe fn spread_unchecked(self, log_block_len: usize, block_idx: usize) -> Self {
		let block_len = 1 << log_block_len;
		let repeat = 1 << (Self::LOG_WIDTH - log_block_len);

		Self::from_scalars(
			self.iter().skip(block_idx * block_len).take(block_len).flat_map(|elem| iter::repeat_n(elem, repeat))
		)
	}
}

/// Iterate over scalar values in a packed field slice.
///
/// The iterator skips the first `offset` elements. This is more efficient than skipping elements of
/// the iterator returned.
#[inline]
pub fn iter_packed_slice_with_offset<P: PackedField>(
	packed: &[P],
	offset: usize,
) -> impl Iterator<Item = P::Scalar> + '_ + Send {
	let (packed, offset): (&[P], usize) = if offset < packed.len() * P::WIDTH {
		(&packed[(offset / P::WIDTH)..], offset % P::WIDTH)
	} else {
		(&[], 0)
	};

	P::iter_slice(packed).skip(offset)
}

#[inline(always)]
pub fn get_packed_slice<P: PackedField>(packed: &[P], i: usize) -> P::Scalar {
	assert!(i >> P::LOG_WIDTH < packed.len(), "index out of bounds");

	unsafe { get_packed_slice_unchecked(packed, i) }
}

/// Returns the scalar at the given index without bounds checking.
/// # Safety
/// The caller must ensure that `i` is less than `P::WIDTH * packed.len()`.
#[inline(always)]
pub unsafe fn get_packed_slice_unchecked<P: PackedField>(packed: &[P], i: usize) -> P::Scalar {
	if is_packed_field_indexable::<P>() {
		// Safety:
		//  - We can safely cast the pointer to `P::Scalar` because `P` is `PackedFieldIndexable`
		//  - `i` is guaranteed to be less than `len_packed_slice(packed)`
		unsafe { *(packed.as_ptr() as *const P::Scalar).add(i) }
	} else {
		// Safety:
		// - `i / P::WIDTH` is within the bounds of `packed` if `i` is less than
		//   `len_packed_slice(packed)`
		// - `i % P::WIDTH` is always less than `P::WIDTH
		unsafe {
			packed
				.get_unchecked(i >> P::LOG_WIDTH)
				.get_unchecked(i % P::WIDTH)
		}
	}
}

#[inline]
pub fn get_packed_slice_checked<P: PackedField>(
	packed: &[P],
	i: usize,
) -> Result<P::Scalar, Error> {
	if i >> P::LOG_WIDTH < packed.len() {
		// Safety: `i` is guaranteed to be less than `len_packed_slice(packed)`
		Ok(unsafe { get_packed_slice_unchecked(packed, i) })
	} else {
		Err(Error::IndexOutOfRange {
			index: i,
			max: len_packed_slice(packed),
		})
	}
}

/// Sets the scalar at the given index without bounds checking.
/// # Safety
/// The caller must ensure that `i` is less than `P::WIDTH * packed.len()`.
#[inline]
pub unsafe fn set_packed_slice_unchecked<P: PackedField>(
	packed: &mut [P],
	i: usize,
	scalar: P::Scalar,
) {
	if is_packed_field_indexable::<P>() {
		// Safety:
		//  - We can safely cast the pointer to `P::Scalar` because `P` is `PackedFieldIndexable`
		//  - `i` is guaranteed to be less than `len_packed_slice(packed)`
		unsafe {
			*(packed.as_mut_ptr() as *mut P::Scalar).add(i) = scalar;
		}
	} else {
		// Safety: if `i` is less than `len_packed_slice(packed)`, then
		// - `i / P::WIDTH` is within the bounds of `packed`
		// - `i % P::WIDTH` is always less than `P::WIDTH
		unsafe {
			packed
				.get_unchecked_mut(i >> P::LOG_WIDTH)
				.set_unchecked(i % P::WIDTH, scalar)
		}
	}
}

#[inline]
pub fn set_packed_slice<P: PackedField>(packed: &mut [P], i: usize, scalar: P::Scalar) {
	assert!(i >> P::LOG_WIDTH < packed.len(), "index out of bounds");

	unsafe { set_packed_slice_unchecked(packed, i, scalar) }
}

#[inline]
pub fn set_packed_slice_checked<P: PackedField>(
	packed: &mut [P],
	i: usize,
	scalar: P::Scalar,
) -> Result<(), Error> {
	if i >> P::LOG_WIDTH < packed.len() {
		// Safety: `i` is guaranteed to be less than `len_packed_slice(packed)`
		unsafe { set_packed_slice_unchecked(packed, i, scalar) };
		Ok(())
	} else {
		Err(Error::IndexOutOfRange {
			index: i,
			max: len_packed_slice(packed),
		})
	}
}

#[inline(always)]
pub const fn len_packed_slice<P: PackedField>(packed: &[P]) -> usize {
	packed.len() << P::LOG_WIDTH
}

/// Construct a packed field element from a function that returns scalar values by index with the
/// given offset in packed elements. E.g. if `offset` is 2, and `WIDTH` is 4, `f(9)` will be used
/// to set the scalar at index 1 in the packed element.
#[inline]
pub fn packed_from_fn_with_offset<P: PackedField>(
	offset: usize,
	mut f: impl FnMut(usize) -> P::Scalar,
) -> P {
	P::from_fn(|i| f(i + offset * P::WIDTH))
}

/// Multiply packed field element by a subfield scalar.
pub fn mul_by_subfield_scalar<P: PackedExtension<FS>, FS: Field>(val: P, multiplier: FS) -> P {
	use crate::underlier::UnderlierType;

	// This is a workaround not to make the multiplication slower in certain cases.
	// TODO: implement efficient strategy to multiply packed field by a subfield scalar.
	let subfield_bits = FS::Underlier::BITS;
	let extension_bits = <<P as PackedField>::Scalar as WithUnderlier>::Underlier::BITS;

	if (subfield_bits == 1 && extension_bits > 8) || extension_bits >= 32 {
		P::from_fn(|i| unsafe { val.get_unchecked(i) } * multiplier)
	} else {
		P::cast_ext(P::cast_base(val) * P::PackedSubfield::broadcast(multiplier))
	}
}

/// Pack a slice of scalars into a vector of packed field elements.
pub fn pack_slice<P: PackedField>(scalars: &[P::Scalar]) -> Vec<P> {
	scalars
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk.iter().copied()))
		.collect()
}

/// Copy scalar elements to a vector of packed field elements.
pub fn copy_packed_from_scalars_slice<P: PackedField>(src: &[P::Scalar], dst: &mut [P]) {
	unpack_if_possible_mut(
		dst,
		|scalars| {
			scalars[0..src.len()].copy_from_slice(src);
		},
		|packed| {
			let chunks = src.chunks_exact(P::WIDTH);
			let remainder = chunks.remainder();
			for (chunk, packed) in chunks.zip(packed.iter_mut()) {
				*packed = P::from_scalars(chunk.iter().copied());
			}

			if !remainder.is_empty() {
				let offset = (src.len() >> P::LOG_WIDTH) << P::LOG_WIDTH;
				let packed = &mut packed[offset];
				for (i, scalar) in remainder.iter().enumerate() {
					// Safety: `i` is guaranteed to be less than `P::WIDTH`
					unsafe { packed.set_unchecked(i, *scalar) };
				}
			}
		},
	);
}

/// A slice of packed field elements as a collection of scalars.
#[derive(Clone)]
pub struct PackedSlice<'a, P: PackedField> {
	slice: &'a [P],
	len: usize,
}

impl<'a, P: PackedField> PackedSlice<'a, P> {
	#[inline(always)]
	pub fn new(slice: &'a [P]) -> Self {
		Self {
			slice,
			len: len_packed_slice(slice),
		}
	}

	#[inline(always)]
	pub fn new_with_len(slice: &'a [P], len: usize) -> Self {
		assert!(len <= len_packed_slice(slice));

		Self { slice, len }
	}
}

impl<P: PackedField> RandomAccessSequence<P::Scalar> for PackedSlice<'_, P> {
	#[inline(always)]
	fn len(&self) -> usize {
		self.len
	}

	#[inline(always)]
	unsafe fn get_unchecked(&self, index: usize) -> P::Scalar {
		unsafe { get_packed_slice_unchecked(self.slice, index) }
	}
}

/// A mutable slice of packed field elements as a collection of scalars.
pub struct PackedSliceMut<'a, P: PackedField> {
	slice: &'a mut [P],
	len: usize,
}

impl<'a, P: PackedField> PackedSliceMut<'a, P> {
	#[inline(always)]
	pub fn new(slice: &'a mut [P]) -> Self {
		let len = len_packed_slice(slice);
		Self { slice, len }
	}

	#[inline(always)]
	pub fn new_with_len(slice: &'a mut [P], len: usize) -> Self {
		assert!(len <= len_packed_slice(slice));

		Self { slice, len }
	}
}

impl<P: PackedField> RandomAccessSequence<P::Scalar> for PackedSliceMut<'_, P> {
	#[inline(always)]
	fn len(&self) -> usize {
		self.len
	}

	#[inline(always)]
	unsafe fn get_unchecked(&self, index: usize) -> P::Scalar {
		unsafe { get_packed_slice_unchecked(self.slice, index) }
	}
}
impl<P: PackedField> RandomAccessSequenceMut<P::Scalar> for PackedSliceMut<'_, P> {
	#[inline(always)]
	unsafe fn set_unchecked(&mut self, index: usize, value: P::Scalar) {
		unsafe { set_packed_slice_unchecked(self.slice, index, value) }
	}
}

impl<F: Field> Broadcast<F> for F {
	#[inline]
	fn broadcast(scalar: F) -> Self {
		scalar
	}
}

impl<T: TowerFieldArithmetic> MulAlpha for T {
	#[inline]
	fn mul_alpha(self) -> Self {
		<Self as TowerFieldArithmetic>::multiply_alpha(self)
	}
}

impl<F: Field> PackedField for F {
	type Scalar = F;

	const LOG_WIDTH: usize = 0;

	#[inline]
	unsafe fn get_unchecked(&self, _i: usize) -> Self::Scalar {
		*self
	}

	#[inline]
	unsafe fn set_unchecked(&mut self, _i: usize, scalar: Self::Scalar) {
		*self = scalar;
	}

	#[inline]
	fn iter(&self) -> impl Iterator<Item = Self::Scalar> + Send + Clone + '_ {
		iter::once(*self)
	}

	#[inline]
	fn into_iter(self) -> impl Iterator<Item = Self::Scalar> + Send + Clone {
		iter::once(self)
	}

	#[inline]
	fn iter_slice(slice: &[Self]) -> impl Iterator<Item = Self::Scalar> + Send + Clone + '_ {
		slice.iter().copied()
	}

	fn interleave(self, _other: Self, _log_block_len: usize) -> (Self, Self) {
		panic!("cannot interleave when WIDTH = 1");
	}

	fn unzip(self, _other: Self, _log_block_len: usize) -> (Self, Self) {
		panic!("cannot transpose when WIDTH = 1");
	}

	#[inline]
	fn broadcast(scalar: Self::Scalar) -> Self {
		scalar
	}

	#[inline]
	fn zero() -> Self {
		Self::ZERO
	}

	#[inline]
	fn one() -> Self {
		Self::ONE
	}

	#[inline]
	fn square(self) -> Self {
		<Self as Square>::square(self)
	}

	#[inline]
	fn invert_or_zero(self) -> Self {
		<Self as InvertOrZero>::invert_or_zero(self)
	}

	#[inline]
	fn from_fn(mut f: impl FnMut(usize) -> Self::Scalar) -> Self {
		f(0)
	}

	#[inline]
	unsafe fn spread_unchecked(self, _log_block_len: usize, _block_idx: usize) -> Self {
		self
	}
}

/// A helper trait to make the generic bounds shorter
pub trait PackedBinaryField: PackedField<Scalar: BinaryField> {}

impl<PT> PackedBinaryField for PT where PT: PackedField<Scalar: BinaryField> {}

#[cfg(test)]
mod tests {
	use itertools::Itertools;
	use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{
		AESTowerField8b, AESTowerField16b, AESTowerField32b, AESTowerField64b, AESTowerField128b,
		BinaryField1b, BinaryField2b, BinaryField4b, BinaryField8b, BinaryField16b, BinaryField32b,
		BinaryField64b, BinaryField128b, BinaryField128bPolyval, PackedField,
		arch::{
			byte_sliced::*, packed_1::*, packed_2::*, packed_4::*, packed_8::*, packed_16::*,
			packed_32::*, packed_64::*, packed_128::*, packed_256::*, packed_512::*,
			packed_aes_8::*, packed_aes_16::*, packed_aes_32::*, packed_aes_64::*,
			packed_aes_128::*, packed_aes_256::*, packed_aes_512::*, packed_polyval_128::*,
			packed_polyval_256::*, packed_polyval_512::*,
		},
	};

	trait PackedFieldTest {
		fn run<P: PackedField>(&self);
	}

	/// Run the test for all the packed fields defined in this crate.
	fn run_for_all_packed_fields(test: &impl PackedFieldTest) {
		// canonical tower
		test.run::<BinaryField1b>();
		test.run::<BinaryField2b>();
		test.run::<BinaryField4b>();
		test.run::<BinaryField8b>();
		test.run::<BinaryField16b>();
		test.run::<BinaryField32b>();
		test.run::<BinaryField64b>();
		test.run::<BinaryField128b>();

		// packed canonical tower
		test.run::<PackedBinaryField1x1b>();
		test.run::<PackedBinaryField2x1b>();
		test.run::<PackedBinaryField1x2b>();
		test.run::<PackedBinaryField4x1b>();
		test.run::<PackedBinaryField2x2b>();
		test.run::<PackedBinaryField1x4b>();
		test.run::<PackedBinaryField8x1b>();
		test.run::<PackedBinaryField4x2b>();
		test.run::<PackedBinaryField2x4b>();
		test.run::<PackedBinaryField1x8b>();
		test.run::<PackedBinaryField16x1b>();
		test.run::<PackedBinaryField8x2b>();
		test.run::<PackedBinaryField4x4b>();
		test.run::<PackedBinaryField2x8b>();
		test.run::<PackedBinaryField1x16b>();
		test.run::<PackedBinaryField32x1b>();
		test.run::<PackedBinaryField16x2b>();
		test.run::<PackedBinaryField8x4b>();
		test.run::<PackedBinaryField4x8b>();
		test.run::<PackedBinaryField2x16b>();
		test.run::<PackedBinaryField1x32b>();
		test.run::<PackedBinaryField64x1b>();
		test.run::<PackedBinaryField32x2b>();
		test.run::<PackedBinaryField16x4b>();
		test.run::<PackedBinaryField8x8b>();
		test.run::<PackedBinaryField4x16b>();
		test.run::<PackedBinaryField2x32b>();
		test.run::<PackedBinaryField1x64b>();
		test.run::<PackedBinaryField128x1b>();
		test.run::<PackedBinaryField64x2b>();
		test.run::<PackedBinaryField32x4b>();
		test.run::<PackedBinaryField16x8b>();
		test.run::<PackedBinaryField8x16b>();
		test.run::<PackedBinaryField4x32b>();
		test.run::<PackedBinaryField2x64b>();
		test.run::<PackedBinaryField1x128b>();
		test.run::<PackedBinaryField256x1b>();
		test.run::<PackedBinaryField128x2b>();
		test.run::<PackedBinaryField64x4b>();
		test.run::<PackedBinaryField32x8b>();
		test.run::<PackedBinaryField16x16b>();
		test.run::<PackedBinaryField8x32b>();
		test.run::<PackedBinaryField4x64b>();
		test.run::<PackedBinaryField2x128b>();
		test.run::<PackedBinaryField512x1b>();
		test.run::<PackedBinaryField256x2b>();
		test.run::<PackedBinaryField128x4b>();
		test.run::<PackedBinaryField64x8b>();
		test.run::<PackedBinaryField32x16b>();
		test.run::<PackedBinaryField16x32b>();
		test.run::<PackedBinaryField8x64b>();
		test.run::<PackedBinaryField4x128b>();

		// AES tower
		test.run::<AESTowerField8b>();
		test.run::<AESTowerField16b>();
		test.run::<AESTowerField32b>();
		test.run::<AESTowerField64b>();
		test.run::<AESTowerField128b>();

		// packed AES tower
		test.run::<PackedAESBinaryField1x8b>();
		test.run::<PackedAESBinaryField2x8b>();
		test.run::<PackedAESBinaryField1x16b>();
		test.run::<PackedAESBinaryField4x8b>();
		test.run::<PackedAESBinaryField2x16b>();
		test.run::<PackedAESBinaryField1x32b>();
		test.run::<PackedAESBinaryField8x8b>();
		test.run::<PackedAESBinaryField4x16b>();
		test.run::<PackedAESBinaryField2x32b>();
		test.run::<PackedAESBinaryField1x64b>();
		test.run::<PackedAESBinaryField16x8b>();
		test.run::<PackedAESBinaryField8x16b>();
		test.run::<PackedAESBinaryField4x32b>();
		test.run::<PackedAESBinaryField2x64b>();
		test.run::<PackedAESBinaryField1x128b>();
		test.run::<PackedAESBinaryField32x8b>();
		test.run::<PackedAESBinaryField16x16b>();
		test.run::<PackedAESBinaryField8x32b>();
		test.run::<PackedAESBinaryField4x64b>();
		test.run::<PackedAESBinaryField2x128b>();
		test.run::<PackedAESBinaryField64x8b>();
		test.run::<PackedAESBinaryField32x16b>();
		test.run::<PackedAESBinaryField16x32b>();
		test.run::<PackedAESBinaryField8x64b>();
		test.run::<PackedAESBinaryField4x128b>();

		// Byte-sliced AES tower
		test.run::<ByteSlicedAES16x128b>();
		test.run::<ByteSlicedAES16x64b>();
		test.run::<ByteSlicedAES2x16x64b>();
		test.run::<ByteSlicedAES16x32b>();
		test.run::<ByteSlicedAES4x16x32b>();
		test.run::<ByteSlicedAES16x16b>();
		test.run::<ByteSlicedAES8x16x16b>();
		test.run::<ByteSlicedAES16x8b>();
		test.run::<ByteSlicedAES16x16x8b>();

		test.run::<ByteSliced16x128x1b>();
		test.run::<ByteSliced8x128x1b>();
		test.run::<ByteSliced4x128x1b>();
		test.run::<ByteSliced2x128x1b>();
		test.run::<ByteSliced1x128x1b>();

		test.run::<ByteSlicedAES32x128b>();
		test.run::<ByteSlicedAES32x64b>();
		test.run::<ByteSlicedAES2x32x64b>();
		test.run::<ByteSlicedAES32x32b>();
		test.run::<ByteSlicedAES4x32x32b>();
		test.run::<ByteSlicedAES32x16b>();
		test.run::<ByteSlicedAES8x32x16b>();
		test.run::<ByteSlicedAES32x8b>();
		test.run::<ByteSlicedAES16x32x8b>();

		test.run::<ByteSliced16x256x1b>();
		test.run::<ByteSliced8x256x1b>();
		test.run::<ByteSliced4x256x1b>();
		test.run::<ByteSliced2x256x1b>();
		test.run::<ByteSliced1x256x1b>();

		test.run::<ByteSlicedAES64x128b>();
		test.run::<ByteSlicedAES64x64b>();
		test.run::<ByteSlicedAES2x64x64b>();
		test.run::<ByteSlicedAES64x32b>();
		test.run::<ByteSlicedAES4x64x32b>();
		test.run::<ByteSlicedAES64x16b>();
		test.run::<ByteSlicedAES8x64x16b>();
		test.run::<ByteSlicedAES64x8b>();
		test.run::<ByteSlicedAES16x64x8b>();

		test.run::<ByteSliced16x512x1b>();
		test.run::<ByteSliced8x512x1b>();
		test.run::<ByteSliced4x512x1b>();
		test.run::<ByteSliced2x512x1b>();
		test.run::<ByteSliced1x512x1b>();

		// polyval tower
		test.run::<BinaryField128bPolyval>();

		// packed polyval tower
		test.run::<PackedBinaryPolyval1x128b>();
		test.run::<PackedBinaryPolyval2x128b>();
		test.run::<PackedBinaryPolyval4x128b>();
	}

	fn check_value_iteration<P: PackedField>(mut rng: impl RngCore) {
		let packed = P::random(&mut rng);
		let mut iter = packed.iter();
		for i in 0..P::WIDTH {
			assert_eq!(packed.get(i), iter.next().unwrap());
		}
		assert!(iter.next().is_none());
	}

	fn check_ref_iteration<P: PackedField>(mut rng: impl RngCore) {
		let packed = P::random(&mut rng);
		let mut iter = packed.into_iter();
		for i in 0..P::WIDTH {
			assert_eq!(packed.get(i), iter.next().unwrap());
		}
		assert!(iter.next().is_none());
	}

	fn check_slice_iteration<P: PackedField>(mut rng: impl RngCore) {
		for len in [0, 1, 5] {
			let packed = std::iter::repeat_with(|| P::random(&mut rng))
				.take(len)
				.collect::<Vec<_>>();

			let elements_count = len * P::WIDTH;
			for offset in [
				0,
				1,
				rng.random_range(0..elements_count.max(1)),
				elements_count.saturating_sub(1),
				elements_count,
			] {
				let actual = iter_packed_slice_with_offset(&packed, offset).collect::<Vec<_>>();
				let expected = (offset..elements_count)
					.map(|i| get_packed_slice(&packed, i))
					.collect::<Vec<_>>();

				assert_eq!(actual, expected);
			}
		}
	}

	struct PackedFieldIterationTest;

	impl PackedFieldTest for PackedFieldIterationTest {
		fn run<P: PackedField>(&self) {
			let mut rng = StdRng::seed_from_u64(0);

			check_value_iteration::<P>(&mut rng);
			check_ref_iteration::<P>(&mut rng);
			check_slice_iteration::<P>(&mut rng);
		}
	}

	#[test]
	fn test_iteration() {
		run_for_all_packed_fields(&PackedFieldIterationTest);
	}

	fn check_copy_from_scalars<P: PackedField>(mut rng: impl RngCore) {
		let scalars = (0..100)
			.map(|_| <<P as PackedField>::Scalar as Random>::random(&mut rng))
			.collect::<Vec<_>>();

		let mut packed_copy = vec![P::zero(); 100];

		for len in [0, 2, 4, 8, 12, 16] {
			copy_packed_from_scalars_slice(&scalars[0..len], &mut packed_copy);

			for (i, &scalar) in scalars[0..len].iter().enumerate() {
				assert_eq!(get_packed_slice(&packed_copy, i), scalar);
			}
			for i in len..100 {
				assert_eq!(get_packed_slice(&packed_copy, i), P::Scalar::ZERO);
			}
		}
	}

	#[test]
	fn test_copy_from_scalars() {
		let mut rng = StdRng::seed_from_u64(0);

		check_copy_from_scalars::<PackedBinaryField16x8b>(&mut rng);
		check_copy_from_scalars::<PackedBinaryField32x4b>(&mut rng);
	}

	fn check_collection<F: Field>(collection: &impl RandomAccessSequence<F>, expected: &[F]) {
		assert_eq!(collection.len(), expected.len());

		for (i, v) in expected.iter().enumerate() {
			assert_eq!(&collection.get(i), v);
			assert_eq!(&unsafe { collection.get_unchecked(i) }, v);
		}
	}

	fn check_collection_get_set<F: Field>(
		collection: &mut impl RandomAccessSequenceMut<F>,
		random: &mut impl FnMut() -> F,
	) {
		for i in 0..collection.len() {
			let value = random();
			collection.set(i, value);
			assert_eq!(collection.get(i), value);
			assert_eq!(unsafe { collection.get_unchecked(i) }, value);
		}
	}

	#[test]
	fn check_packed_slice() {
		let slice: &[PackedBinaryField16x8b] = &[];
		let packed_slice = PackedSlice::new(slice);
		check_collection(&packed_slice, &[]);
		let packed_slice = PackedSlice::new_with_len(slice, 0);
		check_collection(&packed_slice, &[]);

		let mut rng = StdRng::seed_from_u64(0);
		let slice: &[PackedBinaryField16x8b] = &[
			PackedBinaryField16x8b::random(&mut rng),
			PackedBinaryField16x8b::random(&mut rng),
		];
		let packed_slice = PackedSlice::new(slice);
		check_collection(&packed_slice, &PackedField::iter_slice(slice).collect_vec());

		let packed_slice = PackedSlice::new_with_len(slice, 3);
		check_collection(&packed_slice, &PackedField::iter_slice(slice).take(3).collect_vec());
	}

	#[test]
	fn check_packed_slice_mut() {
		let mut rng = StdRng::seed_from_u64(0);
		let mut random = || BinaryField8b::random(&mut rng);

		let slice: &mut [PackedBinaryField16x8b] = &mut [];
		let packed_slice = PackedSliceMut::new(slice);
		check_collection(&packed_slice, &[]);
		let packed_slice = PackedSliceMut::new_with_len(slice, 0);
		check_collection(&packed_slice, &[]);

		let mut rng = StdRng::seed_from_u64(0);
		let slice: &mut [PackedBinaryField16x8b] = &mut [
			PackedBinaryField16x8b::random(&mut rng),
			PackedBinaryField16x8b::random(&mut rng),
		];
		let values = PackedField::iter_slice(slice).collect_vec();
		let mut packed_slice = PackedSliceMut::new(slice);
		check_collection(&packed_slice, &values);
		check_collection_get_set(&mut packed_slice, &mut random);

		let values = PackedField::iter_slice(slice).collect_vec();
		let mut packed_slice = PackedSliceMut::new_with_len(slice, 3);
		check_collection(&packed_slice, &values[..3]);
		check_collection_get_set(&mut packed_slice, &mut random);
	}
}

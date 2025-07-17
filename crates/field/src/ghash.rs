// Copyright 2023-2025 Irreducible Inc.

//! Binary field implementation of GF(2^128) with a modulus of X^128 + X^7 + X^2 + X + 1.
//! This is the GHASH field used in AES-GCM.

use std::{
	any::TypeId,
	fmt::{self, Debug, Display, Formatter},
	iter::{Product, Sum},
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use binius_utils::{
	DeserializeBytes, SerializationError, SerializationMode, SerializeBytes,
	bytes::{Buf, BufMut},
	iter::IterExtensions,
};
use bytemuck::{Pod, TransparentWrapper, Zeroable};
use rand::{
	Rng,
	distr::{Distribution, StandardUniform},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{
	arithmetic_traits::InvertOrZero,
	binary_field::{BinaryField, BinaryField1b, TowerField},
	error::Error,
	extension::ExtensionField,
	underlier::WithUnderlier,
};
use crate::{
	Field,
	arch::packed_ghash_128::PackedBinaryGhash1x128b,
	arithmetic_traits::Square,
	binary_field_arithmetic::{
		invert_or_zero_using_packed, multiple_using_packed, square_using_packed,
	},
	underlier::{IterationMethods, IterationStrategy, NumCast, U1, UnderlierWithBitOps},
};

#[derive(
	Default,
	Clone,
	Copy,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Hash,
	Zeroable,
	bytemuck::TransparentWrapper,
)]
#[repr(transparent)]
pub struct BinaryField128bGhash(pub(crate) u128);

impl BinaryField128bGhash {
	#[inline]
	pub fn new(value: u128) -> Self {
		Self(value)
	}
}

unsafe impl WithUnderlier for BinaryField128bGhash {
	type Underlier = u128;

	fn to_underlier(self) -> Self::Underlier {
		TransparentWrapper::peel(self)
	}

	fn to_underlier_ref(&self) -> &Self::Underlier {
		TransparentWrapper::peel_ref(self)
	}

	fn to_underlier_ref_mut(&mut self) -> &mut Self::Underlier {
		TransparentWrapper::peel_mut(self)
	}

	fn to_underliers_ref(val: &[Self]) -> &[Self::Underlier] {
		TransparentWrapper::peel_slice(val)
	}

	fn to_underliers_ref_mut(val: &mut [Self]) -> &mut [Self::Underlier] {
		TransparentWrapper::peel_slice_mut(val)
	}

	fn from_underlier(val: Self::Underlier) -> Self {
		TransparentWrapper::wrap(val)
	}

	fn from_underlier_ref(val: &Self::Underlier) -> &Self {
		TransparentWrapper::wrap_ref(val)
	}

	fn from_underlier_ref_mut(val: &mut Self::Underlier) -> &mut Self {
		TransparentWrapper::wrap_mut(val)
	}

	fn from_underliers_ref(val: &[Self::Underlier]) -> &[Self] {
		TransparentWrapper::wrap_slice(val)
	}

	fn from_underliers_ref_mut(val: &mut [Self::Underlier]) -> &mut [Self] {
		TransparentWrapper::wrap_slice_mut(val)
	}
}

impl Neg for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	fn neg(self) -> Self::Output {
		self
	}
}

impl Add<Self> for BinaryField128bGhash {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn add(self, rhs: Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Add<&Self> for BinaryField128bGhash {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn add(self, rhs: &Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Sub<Self> for BinaryField128bGhash {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn sub(self, rhs: Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Sub<&Self> for BinaryField128bGhash {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn sub(self, rhs: &Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Mul<Self> for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	fn mul(self, rhs: Self) -> Self::Output {
		multiple_using_packed::<PackedBinaryGhash1x128b>(self, rhs)
	}
}

impl Mul<&Self> for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	fn mul(self, rhs: &Self) -> Self::Output {
		self * *rhs
	}
}

impl AddAssign<Self> for BinaryField128bGhash {
	#[inline]
	fn add_assign(&mut self, rhs: Self) {
		*self = *self + rhs;
	}
}

impl AddAssign<&Self> for BinaryField128bGhash {
	#[inline]
	fn add_assign(&mut self, rhs: &Self) {
		*self = *self + rhs;
	}
}

impl SubAssign<Self> for BinaryField128bGhash {
	#[inline]
	fn sub_assign(&mut self, rhs: Self) {
		*self = *self - rhs;
	}
}

impl SubAssign<&Self> for BinaryField128bGhash {
	#[inline]
	fn sub_assign(&mut self, rhs: &Self) {
		*self = *self - rhs;
	}
}

impl MulAssign<Self> for BinaryField128bGhash {
	#[inline]
	fn mul_assign(&mut self, rhs: Self) {
		*self = *self * rhs;
	}
}

impl MulAssign<&Self> for BinaryField128bGhash {
	#[inline]
	fn mul_assign(&mut self, rhs: &Self) {
		*self = *self * rhs;
	}
}

impl Sum<Self> for BinaryField128bGhash {
	#[inline]
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Self::ZERO, |acc, x| acc + x)
	}
}

impl<'a> Sum<&'a Self> for BinaryField128bGhash {
	#[inline]
	fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
		iter.fold(Self::ZERO, |acc, x| acc + x)
	}
}

impl Product<Self> for BinaryField128bGhash {
	#[inline]
	fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Self::ONE, |acc, x| acc * x)
	}
}

impl<'a> Product<&'a Self> for BinaryField128bGhash {
	#[inline]
	fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
		iter.fold(Self::ONE, |acc, x| acc * x)
	}
}

impl ConstantTimeEq for BinaryField128bGhash {
	#[inline]
	fn ct_eq(&self, other: &Self) -> Choice {
		self.0.ct_eq(&other.0)
	}
}

impl ConditionallySelectable for BinaryField128bGhash {
	#[inline]
	fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
		Self(ConditionallySelectable::conditional_select(&a.0, &b.0, choice))
	}
}

impl Square for BinaryField128bGhash {
	#[inline]
	fn square(self) -> Self {
		square_using_packed::<PackedBinaryGhash1x128b>(self)
	}
}

impl Field for BinaryField128bGhash {
	const ZERO: Self = Self(0);
	const ONE: Self = Self(1);
	const CHARACTERISTIC: usize = 2;

	fn double(&self) -> Self {
		Self(0)
	}
}

impl Distribution<BinaryField128bGhash> for StandardUniform {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BinaryField128bGhash {
		BinaryField128bGhash(rng.random())
	}
}

impl InvertOrZero for BinaryField128bGhash {
	#[inline]
	fn invert_or_zero(self) -> Self {
		invert_or_zero_using_packed::<PackedBinaryGhash1x128b>(self)
	}
}

impl From<u128> for BinaryField128bGhash {
	#[inline]
	fn from(value: u128) -> Self {
		Self(value)
	}
}

impl From<BinaryField128bGhash> for u128 {
	#[inline]
	fn from(value: BinaryField128bGhash) -> Self {
		value.0
	}
}

impl Display for BinaryField128bGhash {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "0x{repr:0>32x}", repr = self.0)
	}
}

impl Debug for BinaryField128bGhash {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "BinaryField128bGhash({self})")
	}
}

unsafe impl Pod for BinaryField128bGhash {}

impl TryInto<BinaryField1b> for BinaryField128bGhash {
	type Error = ();

	#[inline]
	fn try_into(self) -> Result<BinaryField1b, Self::Error> {
		let result = CtOption::new(BinaryField1b::ZERO, self.ct_eq(&Self::ZERO))
			.or_else(|| CtOption::new(BinaryField1b::ONE, self.ct_eq(&Self::ONE)));
		Option::from(result).ok_or(())
	}
}

impl From<BinaryField1b> for BinaryField128bGhash {
	#[inline]
	fn from(value: BinaryField1b) -> Self {
		debug_assert_eq!(Self::ZERO, Self(0));

		Self(Self::ONE.0 & u128::fill_with_bit(value.val().val()))
	}
}

impl Add<BinaryField1b> for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	fn add(self, rhs: BinaryField1b) -> Self::Output {
		self + Self::from(rhs)
	}
}

impl Sub<BinaryField1b> for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	fn sub(self, rhs: BinaryField1b) -> Self::Output {
		self - Self::from(rhs)
	}
}

impl Mul<BinaryField1b> for BinaryField128bGhash {
	type Output = Self;

	#[inline]
	#[allow(clippy::suspicious_arithmetic_impl)]
	fn mul(self, rhs: BinaryField1b) -> Self::Output {
		crate::tracing::trace_multiplication!(BinaryField128bGhash, BinaryField1b);

		Self(self.0 & u128::fill_with_bit(u8::from(rhs.0)))
	}
}

impl AddAssign<BinaryField1b> for BinaryField128bGhash {
	#[inline]
	fn add_assign(&mut self, rhs: BinaryField1b) {
		*self = *self + rhs;
	}
}

impl SubAssign<BinaryField1b> for BinaryField128bGhash {
	#[inline]
	fn sub_assign(&mut self, rhs: BinaryField1b) {
		*self = *self - rhs;
	}
}

impl MulAssign<BinaryField1b> for BinaryField128bGhash {
	#[inline]
	fn mul_assign(&mut self, rhs: BinaryField1b) {
		*self = *self * rhs;
	}
}

impl Add<BinaryField128bGhash> for BinaryField1b {
	type Output = BinaryField128bGhash;

	#[inline]
	fn add(self, rhs: BinaryField128bGhash) -> Self::Output {
		rhs + self
	}
}

impl Sub<BinaryField128bGhash> for BinaryField1b {
	type Output = BinaryField128bGhash;

	#[inline]
	fn sub(self, rhs: BinaryField128bGhash) -> Self::Output {
		rhs - self
	}
}

impl Mul<BinaryField128bGhash> for BinaryField1b {
	type Output = BinaryField128bGhash;

	#[inline]
	fn mul(self, rhs: BinaryField128bGhash) -> Self::Output {
		rhs * self
	}
}

impl ExtensionField<BinaryField1b> for BinaryField128bGhash {
	const LOG_DEGREE: usize = 7;

	#[inline]
	fn basis_checked(i: usize) -> Result<Self, Error> {
		if i >= 128 {
			return Err(Error::ExtensionDegreeMismatch);
		}
		Ok(Self::new(1 << i))
	}

	#[inline]
	fn from_bases_sparse(
		base_elems: impl IntoIterator<Item = BinaryField1b>,
		log_stride: usize,
	) -> Result<Self, Error> {
		if log_stride != 7 {
			return Err(Error::ExtensionDegreeMismatch);
		}
		let value = base_elems
			.into_iter()
			.enumerate()
			.fold(0, |value, (i, elem)| value | (u128::from(elem.0) << i));
		Ok(Self::new(value))
	}

	#[inline]
	fn iter_bases(&self) -> impl Iterator<Item = BinaryField1b> {
		IterationMethods::<U1, Self::Underlier>::value_iter(self.0)
			.map_skippable(BinaryField1b::from)
	}

	#[inline]
	fn into_iter_bases(self) -> impl Iterator<Item = BinaryField1b> {
		IterationMethods::<U1, Self::Underlier>::value_iter(self.0)
			.map_skippable(BinaryField1b::from)
	}

	#[inline]
	unsafe fn get_base_unchecked(&self, i: usize) -> BinaryField1b {
		BinaryField1b(U1::num_cast_from(self.0 >> i))
	}
}

impl SerializeBytes for BinaryField128bGhash {
	fn serialize(
		&self,
		write_buf: impl BufMut,
		mode: SerializationMode,
	) -> Result<(), SerializationError> {
		match mode {
			SerializationMode::Native => self.0.serialize(write_buf, mode),
			SerializationMode::CanonicalTower => {
				todo!("Implement canonical tower serialization for GHASH")
			}
		}
	}
}

impl DeserializeBytes for BinaryField128bGhash {
	fn deserialize(read_buf: impl Buf, mode: SerializationMode) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		match mode {
			SerializationMode::Native => Ok(Self(DeserializeBytes::deserialize(read_buf, mode)?)),
			SerializationMode::CanonicalTower => {
				todo!("Implement canonical tower deserialization for GHASH")
			}
		}
	}
}

impl BinaryField for BinaryField128bGhash {
	const MULTIPLICATIVE_GENERATOR: Self = Self(0x2); // TODO: Find actual multiplicative generator for GHASH field
}

impl TowerField for BinaryField128bGhash {
	type Canonical = Self;

	fn min_tower_level(self) -> usize {
		match self {
			Self::ZERO | Self::ONE => 0,
			_ => 7,
		}
	}

	fn mul_primitive(self, _iota: usize) -> Result<Self, Error> {
		// This method could be implemented by multiplying by isomorphic alpha value
		// But it's not being used as for now
		unimplemented!()
	}
}

#[inline(always)]
pub fn is_ghash_tower<F: TowerField>() -> bool {
	TypeId::of::<F>() == TypeId::of::<BinaryField128bGhash>()
		|| TypeId::of::<F>() == TypeId::of::<BinaryField1b>()
}

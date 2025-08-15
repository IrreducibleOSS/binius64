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
	DeserializeBytes, SerializationError, SerializeBytes,
	bytes::{Buf, BufMut},
	iter::IterExtensions,
};
use bytemuck::{Pod, TransparentWrapper, Zeroable};
use rand::{
	Rng,
	distr::{Distribution, StandardUniform},
};

use super::{
	arithmetic_traits::InvertOrZero,
	binary_field::{BinaryField, BinaryField1b, TowerField},
	error::Error,
	extension::ExtensionField,
	underlier::WithUnderlier,
};
use crate::{
	AESTowerField8b, Field,
	arch::packed_ghash_128::PackedBinaryGhash1x128b,
	arithmetic_traits::Square,
	binary_field_arithmetic::{
		invert_or_zero_using_packed, multiple_using_packed, square_using_packed,
	},
	linear_transformation::{FieldLinearTransformation, Transformation},
	transpose::square_transforms_extension_field,
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
	pub const fn new(value: u128) -> Self {
		Self(value)
	}

	#[inline]
	pub fn mul_x(self) -> Self {
		let val = self.to_underlier();
		let shifted = val << 1;

		// GHASH irreducible polynomial: x^128 + x^7 + x^2 + x + 1
		// When the high bit is set, we need to XOR with the reduction polynomial 0x87
		// All 1s if the top bit is set, all 0s otherwise
		let mask = (val >> 127).wrapping_neg();
		let result = shifted ^ (0x87 & mask);

		Self::from_underlier(result)
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
		if self == Self::ZERO {
			Ok(BinaryField1b::ZERO)
		} else if self == Self::ONE {
			Ok(BinaryField1b::ONE)
		} else {
			Err(())
		}
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

	#[inline]
	fn square_transpose(values: &mut [Self]) -> Result<(), Error> {
		square_transforms_extension_field::<BinaryField1b, Self>(values)
			.map_err(|_| Error::ExtensionDegreeMismatch)
	}
}

impl SerializeBytes for BinaryField128bGhash {
	fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.0.serialize(write_buf)
	}
}

impl DeserializeBytes for BinaryField128bGhash {
	fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		Ok(Self(DeserializeBytes::deserialize(read_buf)?))
	}
}

impl BinaryField for BinaryField128bGhash {
	const MULTIPLICATIVE_GENERATOR: Self = Self(0x494ef99794d5244f9152df59d87a9186);
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

pub const GHASH_TO_POLYVAL_TRANSFORMATION: FieldLinearTransformation<
	crate::polyval::BinaryField128bPolyval,
> = FieldLinearTransformation::new_const(&[
	crate::polyval::BinaryField128bPolyval(0xc2000000000000000000000000000001),
	crate::polyval::BinaryField128bPolyval(0x944dd5f5b43f7ac4876845d1b184bdc7),
	crate::polyval::BinaryField128bPolyval(0x95dee109cd2cda72f15bb7c943635eaa),
	crate::polyval::BinaryField128bPolyval(0xbb79ad7a1f4f7a86cdad5c4e926cf845),
	crate::polyval::BinaryField128bPolyval(0xc46a8ec0685186900e77d57e86cdcafb),
	crate::polyval::BinaryField128bPolyval(0xa84f0a129eb834bb68f28980cd82e241),
	crate::polyval::BinaryField128bPolyval(0x83cc00a43bdfa90fd8100311df5edc29),
	crate::polyval::BinaryField128bPolyval(0x47f14c058c98f0bb2c9b824805e3ae9b),
	crate::polyval::BinaryField128bPolyval(0x2d6fa6b4c72ba881ccdb55cc4ec3a31c),
	crate::polyval::BinaryField128bPolyval(0x1f58c089b445440f672bd265318d5244),
	crate::polyval::BinaryField128bPolyval(0xcd1cfa3878b533842d9957c766bf5164),
	crate::polyval::BinaryField128bPolyval(0xcc19f47bfd4f81aa57f89116c4a10d0d),
	crate::polyval::BinaryField128bPolyval(0x5e13d19200068fd3aa4d26dc814fa72c),
	crate::polyval::BinaryField128bPolyval(0x100eda7e77917daa46ff32a04f296905),
	crate::polyval::BinaryField128bPolyval(0x6a6584352ad71441c04dc8eee8e39c71),
	crate::polyval::BinaryField128bPolyval(0x569c895c4f8559882c192148ac8be42d),
	crate::polyval::BinaryField128bPolyval(0xb1ddd94113ebcbdcec5ec0e3f9ce8baf),
	crate::polyval::BinaryField128bPolyval(0x876a8aa146478581100faef5737ae3f6),
	crate::polyval::BinaryField128bPolyval(0x2227fc3e77655374a1dba2fc6ff51469),
	crate::polyval::BinaryField128bPolyval(0xdc03b57df30c618667760051808a31af),
	crate::polyval::BinaryField128bPolyval(0x6f7412630abc83fae4731b3172e69924),
	crate::polyval::BinaryField128bPolyval(0xe84e0b1e1a49f0b56acc2e9793b29361),
	crate::polyval::BinaryField128bPolyval(0x06ec815ba453d69c11ed47dc826c2629),
	crate::polyval::BinaryField128bPolyval(0xa33dd4ae130e6449c64cd55ebf9186cb),
	crate::polyval::BinaryField128bPolyval(0xbfeb95483412040ad081de5e5dc7bc61),
	crate::polyval::BinaryField128bPolyval(0xe201d3b7886adc92fa91fa13b519c02d),
	crate::polyval::BinaryField128bPolyval(0xb77f42543d896adc095f2c784c080659),
	crate::polyval::BinaryField128bPolyval(0x074561ca3597328da4d8a9739bab5941),
	crate::polyval::BinaryField128bPolyval(0xeae0085c4ec0eed2c79cbabbba3eaaea),
	crate::polyval::BinaryField128bPolyval(0x6a9a1a1289934e39c0160a8850b28e14),
	crate::polyval::BinaryField128bPolyval(0x5d34e0e30548cf00e7b190e730f56725),
	crate::polyval::BinaryField128bPolyval(0x216a308a8b117d7c24b152a1261f42e6),
	crate::polyval::BinaryField128bPolyval(0x6b91ecd895e17bafa11e7a8e88b36cb2),
	crate::polyval::BinaryField128bPolyval(0x547324dc51987bcef5e57963beae2bd3),
	crate::polyval::BinaryField128bPolyval(0x7787142e5da78676e8f8c088a3bfe070),
	crate::polyval::BinaryField128bPolyval(0x1395f0a3b0b23d3d37e97a2e521d8b00),
	crate::polyval::BinaryField128bPolyval(0x0089ab0168df6752ae571466f2db2e49),
	crate::polyval::BinaryField128bPolyval(0x88199925f985bbef31ca3e993f3e2c64),
	crate::polyval::BinaryField128bPolyval(0x0f36f0f46d1108b2e78570a79acaf5f6),
	crate::polyval::BinaryField128bPolyval(0x1a50fc4f36da7c3468b823f680fbe614),
	crate::polyval::BinaryField128bPolyval(0x47a12ffccab058ced8a926e319361050),
	crate::polyval::BinaryField128bPolyval(0xab0c10bf64df631f77a2667b5ff4fa0c),
	crate::polyval::BinaryField128bPolyval(0xdd1bf498a726d80c9a00ac0c2c449438),
	crate::polyval::BinaryField128bPolyval(0xa8912cf320f94054ae95f6efb2cbe321),
	crate::polyval::BinaryField128bPolyval(0x72d3fd953e3b964b94970241f6076e29),
	crate::polyval::BinaryField128bPolyval(0x9fa46ea7e5baddccb78b2ce01b92ed5d),
	crate::polyval::BinaryField128bPolyval(0x55aa311d9c6fbbdddf251b17a68b5497),
	crate::polyval::BinaryField128bPolyval(0xe5090f20fd3274b4b10fb82d919439eb),
	crate::polyval::BinaryField128bPolyval(0xba3324c4ee18a5c9b09f0fbe9c36bb6d),
	crate::polyval::BinaryField128bPolyval(0xc0a08d26afba863016fe9754b674a21c),
	crate::polyval::BinaryField128bPolyval(0x755df942f918ccd1fc17f7f77ff04661),
	crate::polyval::BinaryField128bPolyval(0x8e6a7a776265525650a284548f042645),
	crate::polyval::BinaryField128bPolyval(0x36604add7d60ab8a991de031945f64c3),
	crate::polyval::BinaryField128bPolyval(0xb1da40d0465379b7e853ecd020fa9b14),
	crate::polyval::BinaryField128bPolyval(0xe5855d03e3f808a8be257ceb52971e70),
	crate::polyval::BinaryField128bPolyval(0xa07e24e15ddf81f1036963f1d88336b6),
	crate::polyval::BinaryField128bPolyval(0xd7eecf2ed67def6c2c69dea18babb2db),
	crate::polyval::BinaryField128bPolyval(0xff19b715b9819acd4fbafd4aab1a4e83),
	crate::polyval::BinaryField128bPolyval(0x40a4409d2933f9f4dda3374868bfac9f),
	crate::polyval::BinaryField128bPolyval(0x2fc4d29a711e26801ae70c548105a3fe),
	crate::polyval::BinaryField128bPolyval(0xd0a7995be7423fb7ecdb7a37a967ed15),
	crate::polyval::BinaryField128bPolyval(0xdb46974a626f6c94c68c77fac77cbf79),
	crate::polyval::BinaryField128bPolyval(0x3545420fdae53fcd855628a9637676e3),
	crate::polyval::BinaryField128bPolyval(0x2719e45194c24ada21a12f8e124a10f7),
	crate::polyval::BinaryField128bPolyval(0x6ddc82a8e6cda9ab99e1a24dc4019218),
	crate::polyval::BinaryField128bPolyval(0x43e1cc01e2d643eda4b942f01c5f4f01),
	crate::polyval::BinaryField128bPolyval(0xe7739cb0fc8b087ead209ea3ba3b7730),
	crate::polyval::BinaryField128bPolyval(0xe49a758f719d5d3e209d8ccf1c2cfc55),
	crate::polyval::BinaryField128bPolyval(0x7ecdaa0fedb074a4e6dff83541bc0ffe),
	crate::polyval::BinaryField128bPolyval(0x62f0b1f28f3cc93c600838d7f4e00fae),
	crate::polyval::BinaryField128bPolyval(0x07d5c0c80d9dcb66f0e54cab17a74f51),
	crate::polyval::BinaryField128bPolyval(0x94a3bac012127d2a4799e43f10346d34),
	crate::polyval::BinaryField128bPolyval(0x04e7f5b9af9b3b32562d34415976a555),
	crate::polyval::BinaryField128bPolyval(0xf01f02abce0d7698da1039ea06eba45d),
	crate::polyval::BinaryField128bPolyval(0x7ecbaf96cfe0dd2211e12cb0ea21ef61),
	crate::polyval::BinaryField128bPolyval(0x8d3d926855f5eab23eab173cbd92cca6),
	crate::polyval::BinaryField128bPolyval(0x5db79f89adea22828f64e5d6e237cd75),
	crate::polyval::BinaryField128bPolyval(0xab6895bc5b345ada1f94b5fa39110a2d),
	crate::polyval::BinaryField128bPolyval(0x225ce73ad25eb0245d943b5834e32cce),
	crate::polyval::BinaryField128bPolyval(0x48f7d720297715b658819f44a593f401),
	crate::polyval::BinaryField128bPolyval(0x7d07b3f8414616fe9bf701d138824db6),
	crate::polyval::BinaryField128bPolyval(0x7eccfbf166fb4920822e48fd8854cc65),
	crate::polyval::BinaryField128bPolyval(0x87f59ddf123377c9439851235e188939),
	crate::polyval::BinaryField128bPolyval(0xeeaef3c882043054bde413ec06905aaa),
	crate::polyval::BinaryField128bPolyval(0xc164894522f4e12ce371b828001e26ea),
	crate::polyval::BinaryField128bPolyval(0x10ca87d592f1c9b5c57b4e98a875c545),
	crate::polyval::BinaryField128bPolyval(0xa1a7985e8c2116c7184d319731aedc19),
	crate::polyval::BinaryField128bPolyval(0xa9fdf8b949e25eb2ddd7b4b43db78201),
	crate::polyval::BinaryField128bPolyval(0x175e005dbf565530ad252d5fb057bf3c),
	crate::polyval::BinaryField128bPolyval(0xa27fb1ce9c30f86ab0e07aa46f178940),
	crate::polyval::BinaryField128bPolyval(0x7c41dee659308fbd55a57e0132942fdf),
	crate::polyval::BinaryField128bPolyval(0x0dd13c21d6e831ec90822dc03afeef64),
	crate::polyval::BinaryField128bPolyval(0xd84d2951e6b54a89dcc34ca312bb0009),
	crate::polyval::BinaryField128bPolyval(0xae54e440bceef933434de19cf4a211f7),
	crate::polyval::BinaryField128bPolyval(0x5f4ec22b1c6f83654612b65a33ab6cce),
	crate::polyval::BinaryField128bPolyval(0x2272cbdd29678345f7ff593695e01719),
	crate::polyval::BinaryField128bPolyval(0x784a742d6e7a4c318d7aa7911a2d0104),
	crate::polyval::BinaryField128bPolyval(0x1b51b2af3e2cf57ed4871d9e4351b658),
	crate::polyval::BinaryField128bPolyval(0x889906019909f3ea120477b2179b0cae),
	crate::polyval::BinaryField128bPolyval(0x4a72aa08abad9fea7221d35380d43e96),
	crate::polyval::BinaryField128bPolyval(0xed13b089d5319074a5c1012a4c6b6228),
	crate::polyval::BinaryField128bPolyval(0x14cad28781f6679632100042fee612ee),
	crate::polyval::BinaryField128bPolyval(0xf7f263cb6dd828eb44ee7e0d36172529),
	crate::polyval::BinaryField128bPolyval(0xbc29753d9272bd162ff45d5f8549349f),
	crate::polyval::BinaryField128bPolyval(0xe83357af19ec579aa60f298835710ce2),
	crate::polyval::BinaryField128bPolyval(0x2ccdd5a99c675cee0032af873a4bc9f2),
	crate::polyval::BinaryField128bPolyval(0x1699cca0b1c49c62171c7b18ec750ecb),
	crate::polyval::BinaryField128bPolyval(0x8d53ffa05238f60fda559c0b8b3fa883),
	crate::polyval::BinaryField128bPolyval(0x2230ef04e9d7cbdb03e02c18ebe9f6aa),
	crate::polyval::BinaryField128bPolyval(0x78b314b001287da18444b6c32fc4c98e),
	crate::polyval::BinaryField128bPolyval(0x7256c40d5d3ef46abe43a1d38cd00b50),
	crate::polyval::BinaryField128bPolyval(0x470f34500d221b571e215b8234c6ed60),
	crate::polyval::BinaryField128bPolyval(0x2b65ef0d7f5cdbdde3e228af68187144),
	crate::polyval::BinaryField128bPolyval(0x524148c0a65649fb4160e77810689cc2),
	crate::polyval::BinaryField128bPolyval(0xd50b1d7ca7127f46babf0bb4d50f88d7),
	crate::polyval::BinaryField128bPolyval(0xf7e8e8399c62d0454fe19c7dfe057131),
	crate::polyval::BinaryField128bPolyval(0x385b519edcd0b7019f19f32548a58438),
	crate::polyval::BinaryField128bPolyval(0xb21dfe8c12f91b1aaa5a9e05cd67a32c),
	crate::polyval::BinaryField128bPolyval(0xd2b0b3a2bb68fcba4580c349919ae001),
	crate::polyval::BinaryField128bPolyval(0x6eeed3758208a9b041a0c471eb396097),
	crate::polyval::BinaryField128bPolyval(0x9080890111dc9f95c9ec4936849026ca),
	crate::polyval::BinaryField128bPolyval(0xf11a31d33393c8c575b367ef89038c17),
	crate::polyval::BinaryField128bPolyval(0x4efa48f8fbe59059f0bee4d3c270318b),
	crate::polyval::BinaryField128bPolyval(0x5fdc3fd5a6b548858321e892539364a2),
	crate::polyval::BinaryField128bPolyval(0xe998efe83f7cf7ac086a84e037a413ff),
	crate::polyval::BinaryField128bPolyval(0x431d758f84316acb9c3cb05b3f47b1c2),
	crate::polyval::BinaryField128bPolyval(0xa748b4c891720beae8d5445399863b34),
	crate::polyval::BinaryField128bPolyval(0x3e052a357563d8e14f6442cebb327f06),
]);

impl From<BinaryField128bGhash> for crate::polyval::BinaryField128bPolyval {
	fn from(value: BinaryField128bGhash) -> Self {
		GHASH_TO_POLYVAL_TRANSFORMATION.transform(&value)
	}
}

pub const POLYVAL_TO_GHASH_TRANSFORMATION: FieldLinearTransformation<BinaryField128bGhash> =
	FieldLinearTransformation::new_const(&[
		BinaryField128bGhash(0x83ad91f69582bddf38d15180f9de45ad),
		BinaryField128bGhash(0x12f5319035acedbaaab4d02e8a509602),
		BinaryField128bGhash(0x3d11fd74d4f1053a27678cea68ee3fc6),
		BinaryField128bGhash(0xbf1f144bd8857f78f698028680f046a1),
		BinaryField128bGhash(0x74088d3b4f386e67e613d03f5b882b81),
		BinaryField128bGhash(0xbee84a17e4a0d8476cb7b43cd2b7f414),
		BinaryField128bGhash(0x140b53c4e7e3b1b2f6461f219efef613),
		BinaryField128bGhash(0x3ad713df46a560f83b0e5e557bdd9142),
		BinaryField128bGhash(0x8b4d516f2cdf81f62d906bd02c90d28f),
		BinaryField128bGhash(0x8723123bfd05bf8109a013fff815e851),
		BinaryField128bGhash(0xd7a69fc21f93c99f27ffe39517ad16ed),
		BinaryField128bGhash(0x458642bf3021abe811e9804ec2f2a82e),
		BinaryField128bGhash(0xf6aca42d3ff5066abd352c0b095812ce),
		BinaryField128bGhash(0x08e59653393a98396181c22da38ef6a4),
		BinaryField128bGhash(0x792e1c1ed48cf39988b035dffc216ee2),
		BinaryField128bGhash(0x2de297c5124ba29fdac83db7af971491),
		BinaryField128bGhash(0x34ed81dfd80af8ae6a11469d3a0be37c),
		BinaryField128bGhash(0x41afde873a1ebc8d43191f4702f549d2),
		BinaryField128bGhash(0xfa6c477c562e02ee6f96d051de46c361),
		BinaryField128bGhash(0xeaebba4870d31e1795c47003c4e6891f),
		BinaryField128bGhash(0x21bfe87f27c077cd36cc639c295c90ff),
		BinaryField128bGhash(0x18f98a721445aefc7b115d57a5a0d9c2),
		BinaryField128bGhash(0x6d736bed13f11bd35c134adc985bd000),
		BinaryField128bGhash(0x71f7fdf61814408428ce63937edb4409),
		BinaryField128bGhash(0x3935b81ee1d9d2aa878504bfef17d702),
		BinaryField128bGhash(0xbebf287f77a01d05eab27b58d9755cf5),
		BinaryField128bGhash(0x588bcefefbca207006b3f74dc152fcbf),
		BinaryField128bGhash(0xba8a8eb7235e907cb6127dc172f4836a),
		BinaryField128bGhash(0x70fdb8976770e320a1b13a412be89162),
		BinaryField128bGhash(0xf3fb597a59eab5a850106694a413a49d),
		BinaryField128bGhash(0x96a9e2666e1debee182e2d2b2e0d5dd2),
		BinaryField128bGhash(0x614b16d5b770d5be4136f498c0192c98),
		BinaryField128bGhash(0xce4258db7e777e06a02e81596987ce4d),
		BinaryField128bGhash(0x82eea79d952f848bb7a1e5dab172c493),
		BinaryField128bGhash(0x968787b2d5deb00d1945e0dcc8d135bf),
		BinaryField128bGhash(0x3524bbf64b9e849de8d00098a4be84cc),
		BinaryField128bGhash(0x4cdb6192ec4b52810dbfa1689a4e9312),
		BinaryField128bGhash(0x6de04f3f9c3bf82455f30438bc40e375),
		BinaryField128bGhash(0x8e96e710aad42ed4a24330470afac510),
		BinaryField128bGhash(0xaaf9f907fd0cf489ad6d7568b64f3914),
		BinaryField128bGhash(0xbf3199da5b38dfafaa0c01afad05f5fb),
		BinaryField128bGhash(0x0479669e84334e6a335674d1225bba40),
		BinaryField128bGhash(0x3dc24fd56612ed51bae349328d2699c3),
		BinaryField128bGhash(0xb3ff64dc9b9f18bb9db27e5cf469ce63),
		BinaryField128bGhash(0xb7b08ca23e82d9a9b6520994307d8478),
		BinaryField128bGhash(0xb63301a6277f347903ca96e3544475dd),
		BinaryField128bGhash(0x44960597f2e87930ab613422b24705b6),
		BinaryField128bGhash(0x1556e0a21774ced0f8c0aacf87b7caa9),
		BinaryField128bGhash(0xafe9506e1b7f1058980cfd4773818b89),
		BinaryField128bGhash(0x586318607d698631604a80acc1f966dd),
		BinaryField128bGhash(0x60be19ffd5065fb3d57dcaa6f9766fb8),
		BinaryField128bGhash(0xb6210adc982803415146965de637cf1f),
		BinaryField128bGhash(0xb659b4f2a4c3785ddf8248c2025f7f17),
		BinaryField128bGhash(0x0c2dc66495b1f3d8917b2c1d18d7295b),
		BinaryField128bGhash(0x92cb70cdd8d844bdbdae478d9a305b78),
		BinaryField128bGhash(0xda322e2f57015abf1ed59543a1323015),
		BinaryField128bGhash(0xbfb001978d15c5d3a195ed0915630082),
		BinaryField128bGhash(0x01caca15e7c9e9413ac875d2a4d6142f),
		BinaryField128bGhash(0x30ebc80d30ada6175867807c40467272),
		BinaryField128bGhash(0xffaa1e44f120478805f86db0df73bfb9),
		BinaryField128bGhash(0x8f63e915fe7b70648f1c6f9c19c3225f),
		BinaryField128bGhash(0x51c213f96dbf8447d3f9340830a37254),
		BinaryField128bGhash(0x781d828c1c90d00843d124bfb3d654c4),
		BinaryField128bGhash(0x25d62d8ef36b6bca3a4fb51e694668c4),
		BinaryField128bGhash(0x83a513579eda579397b14587eebe264d),
		BinaryField128bGhash(0x293bec00f4339e2a0eb2d935277c2816),
		BinaryField128bGhash(0xd216229d1912b163960fd30c8ef003db),
		BinaryField128bGhash(0xff913c3e74b087196169fd1677a0e7b3),
		BinaryField128bGhash(0x3049d7819ed5ba584b01579c97e2ea39),
		BinaryField128bGhash(0xee78235ebc75b56ec0f01074fb09aca4),
		BinaryField128bGhash(0x3c529c02a9bb04d8a6d4db2f8dec1130),
		BinaryField128bGhash(0xd6207e8a1765c40ea806614b3dd1add5),
		BinaryField128bGhash(0x9a815f8c624a0f8bc49c205623795148),
		BinaryField128bGhash(0x39fd6f039ca486ef80b9530e132061ba),
		BinaryField128bGhash(0x08e0f5bcd167bb370eae263e193ed316),
		BinaryField128bGhash(0xd663b5234d95e95bc73f823833307642),
		BinaryField128bGhash(0x9f723e83836c7034f6d0de44b69327e7),
		BinaryField128bGhash(0x97871cf64ae6803a7927fd16fad01ce2),
		BinaryField128bGhash(0x657342c2c1b92a8060d27bd7578267ee),
		BinaryField128bGhash(0x11e6621c69d62b2153a001bef84b5e9f),
		BinaryField128bGhash(0x7905d42b52a4d7cf23c3939ff5f0ebcc),
		BinaryField128bGhash(0x8358a5c04daccc9ae6dd10038d7bd892),
		BinaryField128bGhash(0x21411f9121c0cf82ce57897255591ac0),
		BinaryField128bGhash(0x783daa47e6f6f8edaef2f0e6225005b5),
		BinaryField128bGhash(0x39a14f31c6938dac3fbf05a149a7a51b),
		BinaryField128bGhash(0x4595bd8daafbcd17b601622bb6986544),
		BinaryField128bGhash(0x7533d58574b3645beb741e5ef1c3e3f7),
		BinaryField128bGhash(0xb7da75608f643d937e59577588cc0dda),
		BinaryField128bGhash(0x556d4f005fa90a5cc67d8e4ca200cfd1),
		BinaryField128bGhash(0xf7055b4e7f318d0e9f501f277ed049db),
		BinaryField128bGhash(0x8b3e77d687defdd4f02eb1b478eb09c0),
		BinaryField128bGhash(0x83085e93a8fccf6bccd32f138bb6152a),
		BinaryField128bGhash(0x71b7cda5881fb66ce6cf61538f91a382),
		BinaryField128bGhash(0x9aa041e6fbc9ffd0e663810cc7548af7),
		BinaryField128bGhash(0x8672546414d5fa66b30111660bc857ee),
		BinaryField128bGhash(0xd6832136912c7593bc87079b2e53c030),
		BinaryField128bGhash(0x11b4a30358935542218289f09c0659ed),
		BinaryField128bGhash(0xefd1691bcb105c03f674ef753ee2c865),
		BinaryField128bGhash(0xbfa7ea54ddb5ee70891951b1f7284a4c),
		BinaryField128bGhash(0x9fcd8c6cc379cc49cc3681996b596ec4),
		BinaryField128bGhash(0x87f84223132d99ffc9fa4e549378b792),
		BinaryField128bGhash(0x4c1a80abdc6620efdcd95aab468c37c3),
		BinaryField128bGhash(0x5d0eef2d3c86c3439b722bb1a96120da),
		BinaryField128bGhash(0x40b581f12cb827d17c561713f91798ed),
		BinaryField128bGhash(0xf25b91a79835c1aac50d7013b109be19),
		BinaryField128bGhash(0x9b6a413114a0b695b4cbdbe392fd26bc),
		BinaryField128bGhash(0x9e4f7ca1f1dade76f36420d0655ef1e4),
		BinaryField128bGhash(0x2d1365095406acae82c64ab662652c7f),
		BinaryField128bGhash(0xff224e0682868b78fad6230528a19d48),
		BinaryField128bGhash(0x1467ca3a52ac0c682a5660b035a2dda0),
		BinaryField128bGhash(0xbe7acdc28a2d87e7153c512d35ebbd60),
		BinaryField128bGhash(0x10b6481d192423271d30b7ed7a367d93),
		BinaryField128bGhash(0x01afdeffd35e5fde54e1a6f865fe82b9),
		BinaryField128bGhash(0xe3c6cc1d3201af2257c5a38b43d70191),
		BinaryField128bGhash(0xca90b45e3394828a63308fbdc813db85),
		BinaryField128bGhash(0x04e29eefcf4772d3ff94c1a90ddc8e79),
		BinaryField128bGhash(0x507e7bec7fbfc0543dd1cba4330511bd),
		BinaryField128bGhash(0x79453ea2e6412dc1e02e9f09f0cfc8af),
		BinaryField128bGhash(0x3994a7cf382ff3e9ba1fea4d86631551),
		BinaryField128bGhash(0xc6335d7c2449f71f26ede4bf1a096036),
		BinaryField128bGhash(0xb715594eb7756558cad0352d30b311b4),
		BinaryField128bGhash(0x15add135d0873278ba98255ee5bed35b),
		BinaryField128bGhash(0x00f1f1c928152ffecfc8e5d505ad2355),
		BinaryField128bGhash(0x281860e73954cbdb2e13e2f00c767502),
		BinaryField128bGhash(0x8b69509b312d6501ea618e11df04ea1e),
		BinaryField128bGhash(0xdac1600e3177fe0b629aa72ceb27316d),
		BinaryField128bGhash(0x860140d2541486c693c692c775187987),
		BinaryField128bGhash(0x1001001111110961118fe6196978ef70),
	]);

impl From<crate::polyval::BinaryField128bPolyval> for BinaryField128bGhash {
	fn from(value: crate::polyval::BinaryField128bPolyval) -> Self {
		POLYVAL_TO_GHASH_TRANSFORMATION.transform(&value)
	}
}

impl From<AESTowerField8b> for BinaryField128bGhash {
	fn from(value: AESTowerField8b) -> Self {
		const LOOKUP_TABLE: [BinaryField128bGhash; 256] = [
			BinaryField128bGhash(0x00000000000000000000000000000000),
			BinaryField128bGhash(0x00000000000000000000000000000001),
			BinaryField128bGhash(0x0dcb364640a222fe6b8330483c2e9849),
			BinaryField128bGhash(0x0dcb364640a222fe6b8330483c2e9848),
			BinaryField128bGhash(0x3d5bd35c94646a247573da4a5f7710ed),
			BinaryField128bGhash(0x3d5bd35c94646a247573da4a5f7710ec),
			BinaryField128bGhash(0x3090e51ad4c648da1ef0ea02635988a4),
			BinaryField128bGhash(0x3090e51ad4c648da1ef0ea02635988a5),
			BinaryField128bGhash(0x6d58c4e181f9199f41a12db1f974f3ac),
			BinaryField128bGhash(0x6d58c4e181f9199f41a12db1f974f3ad),
			BinaryField128bGhash(0x6093f2a7c15b3b612a221df9c55a6be5),
			BinaryField128bGhash(0x6093f2a7c15b3b612a221df9c55a6be4),
			BinaryField128bGhash(0x500317bd159d73bb34d2f7fba603e341),
			BinaryField128bGhash(0x500317bd159d73bb34d2f7fba603e340),
			BinaryField128bGhash(0x5dc821fb553f51455f51c7b39a2d7b08),
			BinaryField128bGhash(0x5dc821fb553f51455f51c7b39a2d7b09),
			BinaryField128bGhash(0xa72ec17764d7ced55e2f716f4ede412f),
			BinaryField128bGhash(0xa72ec17764d7ced55e2f716f4ede412e),
			BinaryField128bGhash(0xaae5f7312475ec2b35ac412772f0d966),
			BinaryField128bGhash(0xaae5f7312475ec2b35ac412772f0d967),
			BinaryField128bGhash(0x9a75122bf0b3a4f12b5cab2511a951c2),
			BinaryField128bGhash(0x9a75122bf0b3a4f12b5cab2511a951c3),
			BinaryField128bGhash(0x97be246db011860f40df9b6d2d87c98b),
			BinaryField128bGhash(0x97be246db011860f40df9b6d2d87c98a),
			BinaryField128bGhash(0xca760596e52ed74a1f8e5cdeb7aab283),
			BinaryField128bGhash(0xca760596e52ed74a1f8e5cdeb7aab282),
			BinaryField128bGhash(0xc7bd33d0a58cf5b4740d6c968b842aca),
			BinaryField128bGhash(0xc7bd33d0a58cf5b4740d6c968b842acb),
			BinaryField128bGhash(0xf72dd6ca714abd6e6afd8694e8dda26e),
			BinaryField128bGhash(0xf72dd6ca714abd6e6afd8694e8dda26f),
			BinaryField128bGhash(0xfae6e08c31e89f90017eb6dcd4f33a27),
			BinaryField128bGhash(0xfae6e08c31e89f90017eb6dcd4f33a26),
			BinaryField128bGhash(0x4d52354a3a3d8c865cb10fbabcf00118),
			BinaryField128bGhash(0x4d52354a3a3d8c865cb10fbabcf00119),
			BinaryField128bGhash(0x4099030c7a9fae7837323ff280de9951),
			BinaryField128bGhash(0x4099030c7a9fae7837323ff280de9950),
			BinaryField128bGhash(0x7009e616ae59e6a229c2d5f0e38711f5),
			BinaryField128bGhash(0x7009e616ae59e6a229c2d5f0e38711f4),
			BinaryField128bGhash(0x7dc2d050eefbc45c4241e5b8dfa989bc),
			BinaryField128bGhash(0x7dc2d050eefbc45c4241e5b8dfa989bd),
			BinaryField128bGhash(0x200af1abbbc495191d10220b4584f2b4),
			BinaryField128bGhash(0x200af1abbbc495191d10220b4584f2b5),
			BinaryField128bGhash(0x2dc1c7edfb66b7e77693124379aa6afd),
			BinaryField128bGhash(0x2dc1c7edfb66b7e77693124379aa6afc),
			BinaryField128bGhash(0x1d5122f72fa0ff3d6863f8411af3e259),
			BinaryField128bGhash(0x1d5122f72fa0ff3d6863f8411af3e258),
			BinaryField128bGhash(0x109a14b16f02ddc303e0c80926dd7a10),
			BinaryField128bGhash(0x109a14b16f02ddc303e0c80926dd7a11),
			BinaryField128bGhash(0xea7cf43d5eea4253029e7ed5f22e4037),
			BinaryField128bGhash(0xea7cf43d5eea4253029e7ed5f22e4036),
			BinaryField128bGhash(0xe7b7c27b1e4860ad691d4e9dce00d87e),
			BinaryField128bGhash(0xe7b7c27b1e4860ad691d4e9dce00d87f),
			BinaryField128bGhash(0xd7272761ca8e287777eda49fad5950da),
			BinaryField128bGhash(0xd7272761ca8e287777eda49fad5950db),
			BinaryField128bGhash(0xdaec11278a2c0a891c6e94d79177c893),
			BinaryField128bGhash(0xdaec11278a2c0a891c6e94d79177c892),
			BinaryField128bGhash(0x872430dcdf135bcc433f53640b5ab39b),
			BinaryField128bGhash(0x872430dcdf135bcc433f53640b5ab39a),
			BinaryField128bGhash(0x8aef069a9fb1793228bc632c37742bd2),
			BinaryField128bGhash(0x8aef069a9fb1793228bc632c37742bd3),
			BinaryField128bGhash(0xba7fe3804b7731e8364c892e542da376),
			BinaryField128bGhash(0xba7fe3804b7731e8364c892e542da377),
			BinaryField128bGhash(0xb7b4d5c60bd513165dcfb96668033b3f),
			BinaryField128bGhash(0xb7b4d5c60bd513165dcfb96668033b3e),
			BinaryField128bGhash(0x553e92e8bc0ae9a795ed1f57f3632d4d),
			BinaryField128bGhash(0x553e92e8bc0ae9a795ed1f57f3632d4c),
			BinaryField128bGhash(0x58f5a4aefca8cb59fe6e2f1fcf4db504),
			BinaryField128bGhash(0x58f5a4aefca8cb59fe6e2f1fcf4db505),
			BinaryField128bGhash(0x686541b4286e8383e09ec51dac143da0),
			BinaryField128bGhash(0x686541b4286e8383e09ec51dac143da1),
			BinaryField128bGhash(0x65ae77f268cca17d8b1df555903aa5e9),
			BinaryField128bGhash(0x65ae77f268cca17d8b1df555903aa5e8),
			BinaryField128bGhash(0x386656093df3f038d44c32e60a17dee1),
			BinaryField128bGhash(0x386656093df3f038d44c32e60a17dee0),
			BinaryField128bGhash(0x35ad604f7d51d2c6bfcf02ae363946a8),
			BinaryField128bGhash(0x35ad604f7d51d2c6bfcf02ae363946a9),
			BinaryField128bGhash(0x053d8555a9979a1ca13fe8ac5560ce0c),
			BinaryField128bGhash(0x053d8555a9979a1ca13fe8ac5560ce0d),
			BinaryField128bGhash(0x08f6b313e935b8e2cabcd8e4694e5645),
			BinaryField128bGhash(0x08f6b313e935b8e2cabcd8e4694e5644),
			BinaryField128bGhash(0xf210539fd8dd2772cbc26e38bdbd6c62),
			BinaryField128bGhash(0xf210539fd8dd2772cbc26e38bdbd6c63),
			BinaryField128bGhash(0xffdb65d9987f058ca0415e708193f42b),
			BinaryField128bGhash(0xffdb65d9987f058ca0415e708193f42a),
			BinaryField128bGhash(0xcf4b80c34cb94d56beb1b472e2ca7c8f),
			BinaryField128bGhash(0xcf4b80c34cb94d56beb1b472e2ca7c8e),
			BinaryField128bGhash(0xc280b6850c1b6fa8d532843adee4e4c6),
			BinaryField128bGhash(0xc280b6850c1b6fa8d532843adee4e4c7),
			BinaryField128bGhash(0x9f48977e59243eed8a63438944c99fce),
			BinaryField128bGhash(0x9f48977e59243eed8a63438944c99fcf),
			BinaryField128bGhash(0x9283a13819861c13e1e073c178e70787),
			BinaryField128bGhash(0x9283a13819861c13e1e073c178e70786),
			BinaryField128bGhash(0xa2134422cd4054c9ff1099c31bbe8f23),
			BinaryField128bGhash(0xa2134422cd4054c9ff1099c31bbe8f22),
			BinaryField128bGhash(0xafd872648de276379493a98b2790176a),
			BinaryField128bGhash(0xafd872648de276379493a98b2790176b),
			BinaryField128bGhash(0x186ca7a286376521c95c10ed4f932c55),
			BinaryField128bGhash(0x186ca7a286376521c95c10ed4f932c54),
			BinaryField128bGhash(0x15a791e4c69547dfa2df20a573bdb41c),
			BinaryField128bGhash(0x15a791e4c69547dfa2df20a573bdb41d),
			BinaryField128bGhash(0x253774fe12530f05bc2fcaa710e43cb8),
			BinaryField128bGhash(0x253774fe12530f05bc2fcaa710e43cb9),
			BinaryField128bGhash(0x28fc42b852f12dfbd7acfaef2ccaa4f1),
			BinaryField128bGhash(0x28fc42b852f12dfbd7acfaef2ccaa4f0),
			BinaryField128bGhash(0x7534634307ce7cbe88fd3d5cb6e7dff9),
			BinaryField128bGhash(0x7534634307ce7cbe88fd3d5cb6e7dff8),
			BinaryField128bGhash(0x78ff5505476c5e40e37e0d148ac947b0),
			BinaryField128bGhash(0x78ff5505476c5e40e37e0d148ac947b1),
			BinaryField128bGhash(0x486fb01f93aa169afd8ee716e990cf14),
			BinaryField128bGhash(0x486fb01f93aa169afd8ee716e990cf15),
			BinaryField128bGhash(0x45a48659d3083464960dd75ed5be575d),
			BinaryField128bGhash(0x45a48659d3083464960dd75ed5be575c),
			BinaryField128bGhash(0xbf4266d5e2e0abf497736182014d6d7a),
			BinaryField128bGhash(0xbf4266d5e2e0abf497736182014d6d7b),
			BinaryField128bGhash(0xb2895093a242890afcf051ca3d63f533),
			BinaryField128bGhash(0xb2895093a242890afcf051ca3d63f532),
			BinaryField128bGhash(0x8219b5897684c1d0e200bbc85e3a7d97),
			BinaryField128bGhash(0x8219b5897684c1d0e200bbc85e3a7d96),
			BinaryField128bGhash(0x8fd283cf3626e32e89838b806214e5de),
			BinaryField128bGhash(0x8fd283cf3626e32e89838b806214e5df),
			BinaryField128bGhash(0xd21aa2346319b26bd6d24c33f8399ed6),
			BinaryField128bGhash(0xd21aa2346319b26bd6d24c33f8399ed7),
			BinaryField128bGhash(0xdfd1947223bb9095bd517c7bc417069f),
			BinaryField128bGhash(0xdfd1947223bb9095bd517c7bc417069e),
			BinaryField128bGhash(0xef417168f77dd84fa3a19679a74e8e3b),
			BinaryField128bGhash(0xef417168f77dd84fa3a19679a74e8e3a),
			BinaryField128bGhash(0xe28a472eb7dffab1c822a6319b601672),
			BinaryField128bGhash(0xe28a472eb7dffab1c822a6319b601673),
			BinaryField128bGhash(0x93252331bf042b11512625b1f09fa87e),
			BinaryField128bGhash(0x93252331bf042b11512625b1f09fa87f),
			BinaryField128bGhash(0x9eee1577ffa609ef3aa515f9ccb13037),
			BinaryField128bGhash(0x9eee1577ffa609ef3aa515f9ccb13036),
			BinaryField128bGhash(0xae7ef06d2b6041352455fffbafe8b893),
			BinaryField128bGhash(0xae7ef06d2b6041352455fffbafe8b892),
			BinaryField128bGhash(0xa3b5c62b6bc263cb4fd6cfb393c620da),
			BinaryField128bGhash(0xa3b5c62b6bc263cb4fd6cfb393c620db),
			BinaryField128bGhash(0xfe7de7d03efd328e1087080009eb5bd2),
			BinaryField128bGhash(0xfe7de7d03efd328e1087080009eb5bd3),
			BinaryField128bGhash(0xf3b6d1967e5f10707b04384835c5c39b),
			BinaryField128bGhash(0xf3b6d1967e5f10707b04384835c5c39a),
			BinaryField128bGhash(0xc326348caa9958aa65f4d24a569c4b3f),
			BinaryField128bGhash(0xc326348caa9958aa65f4d24a569c4b3e),
			BinaryField128bGhash(0xceed02caea3b7a540e77e2026ab2d376),
			BinaryField128bGhash(0xceed02caea3b7a540e77e2026ab2d377),
			BinaryField128bGhash(0x340be246dbd3e5c40f0954debe41e951),
			BinaryField128bGhash(0x340be246dbd3e5c40f0954debe41e950),
			BinaryField128bGhash(0x39c0d4009b71c73a648a6496826f7118),
			BinaryField128bGhash(0x39c0d4009b71c73a648a6496826f7119),
			BinaryField128bGhash(0x0950311a4fb78fe07a7a8e94e136f9bc),
			BinaryField128bGhash(0x0950311a4fb78fe07a7a8e94e136f9bd),
			BinaryField128bGhash(0x049b075c0f15ad1e11f9bedcdd1861f5),
			BinaryField128bGhash(0x049b075c0f15ad1e11f9bedcdd1861f4),
			BinaryField128bGhash(0x595326a75a2afc5b4ea8796f47351afd),
			BinaryField128bGhash(0x595326a75a2afc5b4ea8796f47351afc),
			BinaryField128bGhash(0x549810e11a88dea5252b49277b1b82b4),
			BinaryField128bGhash(0x549810e11a88dea5252b49277b1b82b5),
			BinaryField128bGhash(0x6408f5fbce4e967f3bdba32518420a10),
			BinaryField128bGhash(0x6408f5fbce4e967f3bdba32518420a11),
			BinaryField128bGhash(0x69c3c3bd8eecb4815058936d246c9259),
			BinaryField128bGhash(0x69c3c3bd8eecb4815058936d246c9258),
			BinaryField128bGhash(0xde77167b8539a7970d972a0b4c6fa966),
			BinaryField128bGhash(0xde77167b8539a7970d972a0b4c6fa967),
			BinaryField128bGhash(0xd3bc203dc59b856966141a437041312f),
			BinaryField128bGhash(0xd3bc203dc59b856966141a437041312e),
			BinaryField128bGhash(0xe32cc527115dcdb378e4f0411318b98b),
			BinaryField128bGhash(0xe32cc527115dcdb378e4f0411318b98a),
			BinaryField128bGhash(0xeee7f36151ffef4d1367c0092f3621c2),
			BinaryField128bGhash(0xeee7f36151ffef4d1367c0092f3621c3),
			BinaryField128bGhash(0xb32fd29a04c0be084c3607bab51b5aca),
			BinaryField128bGhash(0xb32fd29a04c0be084c3607bab51b5acb),
			BinaryField128bGhash(0xbee4e4dc44629cf627b537f28935c283),
			BinaryField128bGhash(0xbee4e4dc44629cf627b537f28935c282),
			BinaryField128bGhash(0x8e7401c690a4d42c3945ddf0ea6c4a27),
			BinaryField128bGhash(0x8e7401c690a4d42c3945ddf0ea6c4a26),
			BinaryField128bGhash(0x83bf3780d006f6d252c6edb8d642d26e),
			BinaryField128bGhash(0x83bf3780d006f6d252c6edb8d642d26f),
			BinaryField128bGhash(0x7959d70ce1ee694253b85b6402b1e849),
			BinaryField128bGhash(0x7959d70ce1ee694253b85b6402b1e848),
			BinaryField128bGhash(0x7492e14aa14c4bbc383b6b2c3e9f7000),
			BinaryField128bGhash(0x7492e14aa14c4bbc383b6b2c3e9f7001),
			BinaryField128bGhash(0x44020450758a036626cb812e5dc6f8a4),
			BinaryField128bGhash(0x44020450758a036626cb812e5dc6f8a5),
			BinaryField128bGhash(0x49c93216352821984d48b16661e860ed),
			BinaryField128bGhash(0x49c93216352821984d48b16661e860ec),
			BinaryField128bGhash(0x140113ed601770dd121976d5fbc51be5),
			BinaryField128bGhash(0x140113ed601770dd121976d5fbc51be4),
			BinaryField128bGhash(0x19ca25ab20b55223799a469dc7eb83ac),
			BinaryField128bGhash(0x19ca25ab20b55223799a469dc7eb83ad),
			BinaryField128bGhash(0x295ac0b1f4731af9676aac9fa4b20b08),
			BinaryField128bGhash(0x295ac0b1f4731af9676aac9fa4b20b09),
			BinaryField128bGhash(0x2491f6f7b4d138070ce99cd7989c9341),
			BinaryField128bGhash(0x2491f6f7b4d138070ce99cd7989c9340),
			BinaryField128bGhash(0xc61bb1d9030ec2b6c4cb3ae603fc8533),
			BinaryField128bGhash(0xc61bb1d9030ec2b6c4cb3ae603fc8532),
			BinaryField128bGhash(0xcbd0879f43ace048af480aae3fd21d7a),
			BinaryField128bGhash(0xcbd0879f43ace048af480aae3fd21d7b),
			BinaryField128bGhash(0xfb406285976aa892b1b8e0ac5c8b95de),
			BinaryField128bGhash(0xfb406285976aa892b1b8e0ac5c8b95df),
			BinaryField128bGhash(0xf68b54c3d7c88a6cda3bd0e460a50d97),
			BinaryField128bGhash(0xf68b54c3d7c88a6cda3bd0e460a50d96),
			BinaryField128bGhash(0xab43753882f7db29856a1757fa88769f),
			BinaryField128bGhash(0xab43753882f7db29856a1757fa88769e),
			BinaryField128bGhash(0xa688437ec255f9d7eee9271fc6a6eed6),
			BinaryField128bGhash(0xa688437ec255f9d7eee9271fc6a6eed7),
			BinaryField128bGhash(0x9618a6641693b10df019cd1da5ff6672),
			BinaryField128bGhash(0x9618a6641693b10df019cd1da5ff6673),
			BinaryField128bGhash(0x9bd39022563193f39b9afd5599d1fe3b),
			BinaryField128bGhash(0x9bd39022563193f39b9afd5599d1fe3a),
			BinaryField128bGhash(0x613570ae67d90c639ae44b894d22c41c),
			BinaryField128bGhash(0x613570ae67d90c639ae44b894d22c41d),
			BinaryField128bGhash(0x6cfe46e8277b2e9df1677bc1710c5c55),
			BinaryField128bGhash(0x6cfe46e8277b2e9df1677bc1710c5c54),
			BinaryField128bGhash(0x5c6ea3f2f3bd6647ef9791c31255d4f1),
			BinaryField128bGhash(0x5c6ea3f2f3bd6647ef9791c31255d4f0),
			BinaryField128bGhash(0x51a595b4b31f44b98414a18b2e7b4cb8),
			BinaryField128bGhash(0x51a595b4b31f44b98414a18b2e7b4cb9),
			BinaryField128bGhash(0x0c6db44fe62015fcdb456638b45637b0),
			BinaryField128bGhash(0x0c6db44fe62015fcdb456638b45637b1),
			BinaryField128bGhash(0x01a68209a6823702b0c656708878aff9),
			BinaryField128bGhash(0x01a68209a6823702b0c656708878aff8),
			BinaryField128bGhash(0x3136671372447fd8ae36bc72eb21275d),
			BinaryField128bGhash(0x3136671372447fd8ae36bc72eb21275c),
			BinaryField128bGhash(0x3cfd515532e65d26c5b58c3ad70fbf14),
			BinaryField128bGhash(0x3cfd515532e65d26c5b58c3ad70fbf15),
			BinaryField128bGhash(0x8b49849339334e30987a355cbf0c842b),
			BinaryField128bGhash(0x8b49849339334e30987a355cbf0c842a),
			BinaryField128bGhash(0x8682b2d579916ccef3f9051483221c62),
			BinaryField128bGhash(0x8682b2d579916ccef3f9051483221c63),
			BinaryField128bGhash(0xb61257cfad572414ed09ef16e07b94c6),
			BinaryField128bGhash(0xb61257cfad572414ed09ef16e07b94c7),
			BinaryField128bGhash(0xbbd96189edf506ea868adf5edc550c8f),
			BinaryField128bGhash(0xbbd96189edf506ea868adf5edc550c8e),
			BinaryField128bGhash(0xe6114072b8ca57afd9db18ed46787787),
			BinaryField128bGhash(0xe6114072b8ca57afd9db18ed46787786),
			BinaryField128bGhash(0xebda7634f8687551b25828a57a56efce),
			BinaryField128bGhash(0xebda7634f8687551b25828a57a56efcf),
			BinaryField128bGhash(0xdb4a932e2cae3d8baca8c2a7190f676a),
			BinaryField128bGhash(0xdb4a932e2cae3d8baca8c2a7190f676b),
			BinaryField128bGhash(0xd681a5686c0c1f75c72bf2ef2521ff23),
			BinaryField128bGhash(0xd681a5686c0c1f75c72bf2ef2521ff22),
			BinaryField128bGhash(0x2c6745e45de480e5c6554433f1d2c504),
			BinaryField128bGhash(0x2c6745e45de480e5c6554433f1d2c505),
			BinaryField128bGhash(0x21ac73a21d46a21badd6747bcdfc5d4d),
			BinaryField128bGhash(0x21ac73a21d46a21badd6747bcdfc5d4c),
			BinaryField128bGhash(0x113c96b8c980eac1b3269e79aea5d5e9),
			BinaryField128bGhash(0x113c96b8c980eac1b3269e79aea5d5e8),
			BinaryField128bGhash(0x1cf7a0fe8922c83fd8a5ae31928b4da0),
			BinaryField128bGhash(0x1cf7a0fe8922c83fd8a5ae31928b4da1),
			BinaryField128bGhash(0x413f8105dc1d997a87f4698208a636a8),
			BinaryField128bGhash(0x413f8105dc1d997a87f4698208a636a9),
			BinaryField128bGhash(0x4cf4b7439cbfbb84ec7759ca3488aee1),
			BinaryField128bGhash(0x4cf4b7439cbfbb84ec7759ca3488aee0),
			BinaryField128bGhash(0x7c6452594879f35ef287b3c857d12645),
			BinaryField128bGhash(0x7c6452594879f35ef287b3c857d12644),
			BinaryField128bGhash(0x71af641f08dbd1a0990483806bffbe0c),
			BinaryField128bGhash(0x71af641f08dbd1a0990483806bffbe0d),
		];

		LOOKUP_TABLE[value.0 as usize]
	}
}

#[inline(always)]
pub fn is_ghash_tower<F: TowerField>() -> bool {
	TypeId::of::<F>() == TypeId::of::<BinaryField128bGhash>()
		|| TypeId::of::<F>() == TypeId::of::<BinaryField1b>()
}

#[cfg(test)]
mod tests {
	use proptest::{prelude::any, proptest};

	use super::*;
	use crate::{
		AESTowerField128b, binary_field::tests::is_binary_field_valid_generator,
		polyval::BinaryField128bPolyval,
	};

	#[test]
	fn test_ghash_mul() {
		let a = BinaryField128bGhash(1u128);
		let b = BinaryField128bGhash(1u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(1u128));

		let a = BinaryField128bGhash(1u128);
		let b = BinaryField128bGhash(2u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(2u128));

		let a = BinaryField128bGhash(1u128);
		let b = BinaryField128bGhash(1297182698762987u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(1297182698762987u128));

		let a = BinaryField128bGhash(2u128);
		let b = BinaryField128bGhash(2u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(4u128));

		let a = BinaryField128bGhash(2u128);
		let b = BinaryField128bGhash(3u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(6u128));

		let a = BinaryField128bGhash(3u128);
		let b = BinaryField128bGhash(3u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(5u128));

		let a = BinaryField128bGhash(1u128 << 127);
		let b = BinaryField128bGhash(2u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(0b10000111));

		let a = BinaryField128bGhash((1u128 << 127) + 1);
		let b = BinaryField128bGhash(2u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(0b10000101));

		let a = BinaryField128bGhash(3u128 << 126);
		let b = BinaryField128bGhash(2u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(0b10000111 + (1u128 << 127)));

		let a = BinaryField128bGhash(1u128 << 127);
		let b = BinaryField128bGhash(4u128);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from(0b10000111 << 1));

		let a = BinaryField128bGhash(1u128 << 127);
		let b = BinaryField128bGhash(1u128 << 122);
		let c = a * b;

		assert_eq!(c, BinaryField128bGhash::from((0b00000111 << 121) + 0b10000111));
	}

	#[test]
	fn test_polyval_x_is_polynomial_root() {
		let x = BinaryField128bPolyval::new(0x2);
		let x = BinaryField128bGhash::from(x);

		let polyval_polynomial_value =
			x.pow([128]) + x.pow([127]) + x.pow([126]) + x.pow([121]) + BinaryField128bGhash::ONE;

		assert_eq!(polyval_polynomial_value, BinaryField128bGhash::ZERO);
	}

	#[test]
	fn test_multiplicative_generator() {
		assert!(is_binary_field_valid_generator::<BinaryField128bGhash>());
	}

	#[test]
	fn test_mul_x() {
		let test_cases = [
			0x0,                                    // Zero
			0x1,                                    // One
			0x2,                                    // Two
			0x80000000000000000000000000000000u128, // High bit set
			0x40000000000000000000000000000000u128, // Second highest bit
			0xffffffffffffffffffffffffffffffffu128, // All bits set
			0x87u128,                               // GHASH reduction polynomial
			0x21ac73a21d46a21badd6747bcdfc5d4d,     // Random value
		];

		for &value in &test_cases {
			let field_val = BinaryField128bGhash::new(value);
			let mul_x_result = field_val.mul_x();
			let regular_mul_result = field_val * BinaryField128bGhash::new(2u128);

			assert_eq!(
				mul_x_result, regular_mul_result,
				"mul_x and regular multiplication by 2 differ for value {:#x}",
				value
			);
		}
	}

	proptest! {
		#[test]
		fn test_to_from_polyval_basis(a_val in any::<u128>(), b_val in any::<u128>()) {
			let a_tower = BinaryField128bGhash::new(a_val);
			let b_tower = BinaryField128bGhash::new(b_val);
			let a_polyval = BinaryField128bPolyval::from(a_tower);
			let b_polyval = BinaryField128bPolyval::from(b_tower);
			assert_eq!(BinaryField128bGhash::from(a_polyval * b_polyval), a_tower * b_tower);
		}

		#[test]
		fn test_conversion_roundtrip(a in any::<u128>()) {
			let a_val = BinaryField128bPolyval(a);
			let converted = BinaryField128bGhash::from(a_val);
			assert_eq!(a_val, BinaryField128bPolyval::from(converted));

			let a_val = BinaryField128bGhash(a);
			let converted = BinaryField128bPolyval::from(a_val);
			assert_eq!(a_val, BinaryField128bGhash::from(converted));
		}

		#[test]
		fn test_conversion_mul_consistency(a in any::<u128>(), b in any::<u128>()) {
			let a_val = BinaryField128bGhash::new(a);
			let b_val = BinaryField128bGhash::new(b);
			let converted_a = BinaryField128bPolyval::from(a_val);
			let converted_b = BinaryField128bPolyval::from(b_val);
			assert_eq!(BinaryField128bPolyval::from(a_val * b_val), converted_a * converted_b);
		}

		#[test]
		fn tests_conversion_from_aes8(a in any::<u8>()) {
			let a_val = AESTowerField8b::new(a);
			let direct_conversion = BinaryField128bGhash::from(a_val);
			let indirect_conversion = BinaryField128bGhash::from(BinaryField128bPolyval::from(AESTowerField128b::from(a_val)));
			assert_eq!(direct_conversion, indirect_conversion);
		}

		#[test]
		fn test_conversion_from_aes_consistency(a in any::<u8>(), b in any::<u8>()) {
			let a_val = AESTowerField8b::new(a);
			let b_val = AESTowerField8b::new(b);
			let converted_a = BinaryField128bGhash::from(a_val);
			let converted_b = BinaryField128bGhash::from(b_val);
			assert_eq!(BinaryField128bGhash::from(a_val * b_val), converted_a * converted_b);
		}
	}
}

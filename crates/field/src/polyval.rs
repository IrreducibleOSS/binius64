// Copyright 2023-2025 Irreducible Inc.

//! Binary field implementation of GF(2^128) with a modulus of X^128 + X^127 + X^126 + x^121 + 1.

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
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{
	aes_field::AESTowerField128b,
	arithmetic_traits::InvertOrZero,
	binary_field::{BinaryField, BinaryField1b, BinaryField128b, TowerField},
	error::Error,
	extension::ExtensionField,
	underlier::WithUnderlier,
};
use crate::{
	Field,
	arch::packed_polyval_128::PackedBinaryPolyval1x128b,
	arithmetic_traits::Square,
	binary_field_arithmetic::{
		invert_or_zero_using_packed, multiple_using_packed, square_using_packed,
	},
	linear_transformation::{FieldLinearTransformation, Transformation},
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
pub struct BinaryField128bPolyval(pub(crate) u128);

impl BinaryField128bPolyval {
	#[inline]
	pub fn new(value: u128) -> Self {
		Self(value).to_montgomery()
	}
}

unsafe impl WithUnderlier for BinaryField128bPolyval {
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

impl Neg for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	fn neg(self) -> Self::Output {
		self
	}
}

impl Add<Self> for BinaryField128bPolyval {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn add(self, rhs: Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Add<&Self> for BinaryField128bPolyval {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn add(self, rhs: &Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Sub<Self> for BinaryField128bPolyval {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn sub(self, rhs: Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Sub<&Self> for BinaryField128bPolyval {
	type Output = Self;

	#[allow(clippy::suspicious_arithmetic_impl)]
	fn sub(self, rhs: &Self) -> Self::Output {
		Self(self.0 ^ rhs.0)
	}
}

impl Mul<Self> for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	fn mul(self, rhs: Self) -> Self::Output {
		multiple_using_packed::<PackedBinaryPolyval1x128b>(self, rhs)
	}
}

impl Mul<&Self> for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	fn mul(self, rhs: &Self) -> Self::Output {
		self * *rhs
	}
}

impl AddAssign<Self> for BinaryField128bPolyval {
	#[inline]
	fn add_assign(&mut self, rhs: Self) {
		*self = *self + rhs;
	}
}

impl AddAssign<&Self> for BinaryField128bPolyval {
	#[inline]
	fn add_assign(&mut self, rhs: &Self) {
		*self = *self + rhs;
	}
}

impl SubAssign<Self> for BinaryField128bPolyval {
	#[inline]
	fn sub_assign(&mut self, rhs: Self) {
		*self = *self - rhs;
	}
}

impl SubAssign<&Self> for BinaryField128bPolyval {
	#[inline]
	fn sub_assign(&mut self, rhs: &Self) {
		*self = *self - rhs;
	}
}

impl MulAssign<Self> for BinaryField128bPolyval {
	#[inline]
	fn mul_assign(&mut self, rhs: Self) {
		*self = *self * rhs;
	}
}

impl MulAssign<&Self> for BinaryField128bPolyval {
	#[inline]
	fn mul_assign(&mut self, rhs: &Self) {
		*self = *self * rhs;
	}
}

impl Sum<Self> for BinaryField128bPolyval {
	#[inline]
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Self::ZERO, |acc, x| acc + x)
	}
}

impl<'a> Sum<&'a Self> for BinaryField128bPolyval {
	#[inline]
	fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
		iter.fold(Self::ZERO, |acc, x| acc + x)
	}
}

impl Product<Self> for BinaryField128bPolyval {
	#[inline]
	fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Self::ONE, |acc, x| acc * x)
	}
}

impl<'a> Product<&'a Self> for BinaryField128bPolyval {
	#[inline]
	fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
		iter.fold(Self::ONE, |acc, x| acc * x)
	}
}

impl ConstantTimeEq for BinaryField128bPolyval {
	#[inline]
	fn ct_eq(&self, other: &Self) -> Choice {
		self.0.ct_eq(&other.0)
	}
}

impl ConditionallySelectable for BinaryField128bPolyval {
	#[inline]
	fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
		Self(ConditionallySelectable::conditional_select(&a.0, &b.0, choice))
	}
}

impl Square for BinaryField128bPolyval {
	#[inline]
	fn square(self) -> Self {
		square_using_packed::<PackedBinaryPolyval1x128b>(self)
	}
}

impl Field for BinaryField128bPolyval {
	const ZERO: Self = Self(0);
	const ONE: Self = Self(0xc2000000000000000000000000000001);
	const CHARACTERISTIC: usize = 2;

	fn double(&self) -> Self {
		Self(0)
	}
}

impl Distribution<BinaryField128bPolyval> for StandardUniform {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BinaryField128bPolyval {
		BinaryField128bPolyval(rng.random())
	}
}

impl InvertOrZero for BinaryField128bPolyval {
	#[inline]
	fn invert_or_zero(self) -> Self {
		invert_or_zero_using_packed::<PackedBinaryPolyval1x128b>(self)
	}
}

impl From<u128> for BinaryField128bPolyval {
	#[inline]
	fn from(value: u128) -> Self {
		Self(value)
	}
}

impl From<BinaryField128bPolyval> for u128 {
	#[inline]
	fn from(value: BinaryField128bPolyval) -> Self {
		value.0
	}
}

impl Display for BinaryField128bPolyval {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "0x{repr:0>32x}", repr = self.from_montgomery().0)
	}
}

impl Debug for BinaryField128bPolyval {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "BinaryField128bPolyval({self})")
	}
}

impl BinaryField128bPolyval {
	#[inline]
	pub(super) fn to_montgomery(self) -> Self {
		self * Self(0x1e563df92ea7081b4563df92ea7081b5)
	}

	// Clippy wants us to use a reference here as API design
	// but we can ignore it as we'd need to copy otherwise.
	#[allow(clippy::wrong_self_convention)]
	pub(super) fn from_montgomery(self) -> Self {
		self * Self(1)
	}
}

unsafe impl Pod for BinaryField128bPolyval {}

impl TryInto<BinaryField1b> for BinaryField128bPolyval {
	type Error = ();

	#[inline]
	fn try_into(self) -> Result<BinaryField1b, Self::Error> {
		let result = CtOption::new(BinaryField1b::ZERO, self.ct_eq(&Self::ZERO))
			.or_else(|| CtOption::new(BinaryField1b::ONE, self.ct_eq(&Self::ONE)));
		Option::from(result).ok_or(())
	}
}

impl From<BinaryField1b> for BinaryField128bPolyval {
	#[inline]
	fn from(value: BinaryField1b) -> Self {
		debug_assert_eq!(Self::ZERO, Self(0));

		Self(Self::ONE.0 & u128::fill_with_bit(value.val().val()))
	}
}

impl Add<BinaryField1b> for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	fn add(self, rhs: BinaryField1b) -> Self::Output {
		self + Self::from(rhs)
	}
}

impl Sub<BinaryField1b> for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	fn sub(self, rhs: BinaryField1b) -> Self::Output {
		self - Self::from(rhs)
	}
}

impl Mul<BinaryField1b> for BinaryField128bPolyval {
	type Output = Self;

	#[inline]
	#[allow(clippy::suspicious_arithmetic_impl)]
	fn mul(self, rhs: BinaryField1b) -> Self::Output {
		crate::tracing::trace_multiplication!(BinaryField128bPolyval, BinaryField1b);

		Self(self.0 & u128::fill_with_bit(u8::from(rhs.0)))
	}
}

impl AddAssign<BinaryField1b> for BinaryField128bPolyval {
	#[inline]
	fn add_assign(&mut self, rhs: BinaryField1b) {
		*self = *self + rhs;
	}
}

impl SubAssign<BinaryField1b> for BinaryField128bPolyval {
	#[inline]
	fn sub_assign(&mut self, rhs: BinaryField1b) {
		*self = *self - rhs;
	}
}

impl MulAssign<BinaryField1b> for BinaryField128bPolyval {
	#[inline]
	fn mul_assign(&mut self, rhs: BinaryField1b) {
		*self = *self * rhs;
	}
}

impl Add<BinaryField128bPolyval> for BinaryField1b {
	type Output = BinaryField128bPolyval;

	#[inline]
	fn add(self, rhs: BinaryField128bPolyval) -> Self::Output {
		rhs + self
	}
}

impl Sub<BinaryField128bPolyval> for BinaryField1b {
	type Output = BinaryField128bPolyval;

	#[inline]
	fn sub(self, rhs: BinaryField128bPolyval) -> Self::Output {
		rhs - self
	}
}

impl Mul<BinaryField128bPolyval> for BinaryField1b {
	type Output = BinaryField128bPolyval;

	#[inline]
	fn mul(self, rhs: BinaryField128bPolyval) -> Self::Output {
		rhs * self
	}
}

impl ExtensionField<BinaryField1b> for BinaryField128bPolyval {
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
		// REVIEW: is this actually correct for a monomial field?
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

impl SerializeBytes for BinaryField128bPolyval {
	fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.0.serialize(write_buf)
	}
}

impl DeserializeBytes for BinaryField128bPolyval {
	fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		Ok(Self(DeserializeBytes::deserialize(read_buf)?))
	}
}

impl BinaryField for BinaryField128bPolyval {
	const MULTIPLICATIVE_GENERATOR: Self = Self(0x72bdf2504ce49c03105433c1c25a4a7);
}

impl TowerField for BinaryField128bPolyval {
	type Canonical = BinaryField128b;

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

pub const BINARY_TO_POLYVAL_TRANSFORMATION: FieldLinearTransformation<BinaryField128bPolyval> =
	FieldLinearTransformation::new_const(&[
		BinaryField128bPolyval(0xc2000000000000000000000000000001),
		BinaryField128bPolyval(0x21a09a4bf26aadcd3eb19c5f1a06b528),
		BinaryField128bPolyval(0xe62f1a804db43b94852cef0e61d7353d),
		BinaryField128bPolyval(0xadcde131ca862a6ba378ea68e992a5b6),
		BinaryField128bPolyval(0x5474611d07bdcd1f72e9bdc82ec4fe6c),
		BinaryField128bPolyval(0xf9a472d4a4965f4caa3532aa6258c986),
		BinaryField128bPolyval(0x10bd76c920260f81877681ed1a50b210),
		BinaryField128bPolyval(0xe7f3264523858ca36ef84934fdd225f2),
		BinaryField128bPolyval(0x586704bda927015fedb8ddceb7f825d6),
		BinaryField128bPolyval(0x552dab8acfd831aeb65f8aaec9cef096),
		BinaryField128bPolyval(0xeccdac666a363defde6792e475892fb3),
		BinaryField128bPolyval(0x4a621d01701247f6e4a8327e33d95aa2),
		BinaryField128bPolyval(0x8ed5002fed1f4b9a9a11840f87149e2d),
		BinaryField128bPolyval(0x3c65abbd41c759f0302467db5a791e09),
		BinaryField128bPolyval(0xc2df68a5949a96b3aa643692e93caaab),
		BinaryField128bPolyval(0x4455027df88c165117daf9822eb57383),
		BinaryField128bPolyval(0xc50e3a207f91d7cd6dd1e116d55455fb),
		BinaryField128bPolyval(0xc89c3920b9b24b755fd08543d8caf5a2),
		BinaryField128bPolyval(0xfa583eb935de76a2ec180360b6548830),
		BinaryField128bPolyval(0xc4d3d3b9938f3af77800a5cd03690171),
		BinaryField128bPolyval(0xe1faff3b895be1e2bec91c0836143b44),
		BinaryField128bPolyval(0x256bd50f868b82cf1c83552eeb1cd844),
		BinaryField128bPolyval(0x82fd35d590073ae9595cab38e9b59d79),
		BinaryField128bPolyval(0x08dadd230bc90e192304a2533cdce9e6),
		BinaryField128bPolyval(0xf4400f37acedc7d9502abeff6cead84c),
		BinaryField128bPolyval(0x5438d34e2b5b90328cc88b7384deedfb),
		BinaryField128bPolyval(0x7d798db71ef80a3e447cd7d1d4a0385d),
		BinaryField128bPolyval(0xa50d5ef4e33979db8012303dc09cbf35),
		BinaryField128bPolyval(0x91c4b5e29de5759e0bb337efbc5b8115),
		BinaryField128bPolyval(0xbbb0d4aaba0fab72848f461ed0a4b110),
		BinaryField128bPolyval(0x3c9de86b9a306d6d11cc078904076865),
		BinaryField128bPolyval(0xb5f43a166aa1f15f99db6d689ca1b370),
		BinaryField128bPolyval(0xa26153cb8c150af8243ecbd46378e59e),
		BinaryField128bPolyval(0xccaa154bab1dd7aca876f81fe0c950ab),
		BinaryField128bPolyval(0x4185b7e3ee1dddbc761a6139cdb07755),
		BinaryField128bPolyval(0x2c9f95285b7aa574653ed207337325f2),
		BinaryField128bPolyval(0xc8ba616ab131bfd242195c4c82d54dbb),
		BinaryField128bPolyval(0x2a9b07221a34865faa36a28da1ab1c24),
		BinaryField128bPolyval(0x7e6e572804b548a88b92900e0196dd39),
		BinaryField128bPolyval(0x4e9060deff44c9ef9882a0015debd575),
		BinaryField128bPolyval(0x00a3a4d8c163c95ac7ac9a5b424e1c65),
		BinaryField128bPolyval(0xf67c7eb5dde73d96f8f5eecba6033679),
		BinaryField128bPolyval(0x54d78d187bbb57d19b536094ba539fde),
		BinaryField128bPolyval(0x76c553699edc5d4a033139975ab7f264),
		BinaryField128bPolyval(0x74ae8da43b2f587df3e41bbf5c6be650),
		BinaryField128bPolyval(0x8a2941b59774c41acd850aa6098e5fd2),
		BinaryField128bPolyval(0x9ddf65660a6f8f3c0058165a063de84c),
		BinaryField128bPolyval(0xbb52da733635cc3d1ff02ef96ee64cf3),
		BinaryField128bPolyval(0x564032a0d5d3773b7b7ed18bebf1c668),
		BinaryField128bPolyval(0xef5c765e64b24b1b00222054ff0040ef),
		BinaryField128bPolyval(0xade661c18acba6233d484726e6249bee),
		BinaryField128bPolyval(0x9939ba35c969cdeea29f2ef849c2d170),
		BinaryField128bPolyval(0x2b100b39761d4f23eb42d05b80174ce2),
		BinaryField128bPolyval(0xfbc25b179830f9eec765bd6229125d6c),
		BinaryField128bPolyval(0xb58e089ebe7ad0b2698e30184ab93141),
		BinaryField128bPolyval(0x53874933a148be94d12025afa876234c),
		BinaryField128bPolyval(0x41bbc7902188f4e9880f1d81fa580ffb),
		BinaryField128bPolyval(0xea4199916a5d127d25da1fe777b2dcbb),
		BinaryField128bPolyval(0xe7bc816547efbe987d9359ee0de0c287),
		BinaryField128bPolyval(0x02e0f1f67e7139835892155a7addd9da),
		BinaryField128bPolyval(0xdc6beb6eade9f875e74955ca950af235),
		BinaryField128bPolyval(0x786d616edeadfa356453a78d8f103230),
		BinaryField128bPolyval(0xe84e70191accaddac8034da936737487),
		BinaryField128bPolyval(0x012b8669ff3f451e5363edfddd37fb3c),
		BinaryField128bPolyval(0x756209f0893e96877833c194b9c943a0),
		BinaryField128bPolyval(0xb2ac9efc9a1891369f63bd1e0d1439ac),
		BinaryField128bPolyval(0x4de88e9a5bbb4c3df650cc3994c3d2d8),
		BinaryField128bPolyval(0x8de7b5c85c07f3359849e7c85e426b54),
		BinaryField128bPolyval(0xcadd54ae6a7e72a4f184e6761cf226d4),
		BinaryField128bPolyval(0xcdb182fb8d95496f55b5f3952f81bc30),
		BinaryField128bPolyval(0x40013bc3c81722753a05bb2aca01a02e),
		BinaryField128bPolyval(0x704e7ce55e9033883e97351591adf18a),
		BinaryField128bPolyval(0xf330cd9a74a5e884988c3f36567d26f4),
		BinaryField128bPolyval(0x18f4535304c0d74ac3bdf09d78cbde50),
		BinaryField128bPolyval(0xfe739c97fc26bed28885b838405c7e7e),
		BinaryField128bPolyval(0x492479260f2dcd8af980c3d74b3ec345),
		BinaryField128bPolyval(0x96b6440a34de0aad4ea2f744396691af),
		BinaryField128bPolyval(0x98355d1b4f7cfb03960a59aa564a7a26),
		BinaryField128bPolyval(0x2703fda0532095ca8b1886b12ca37d64),
		BinaryField128bPolyval(0x59c9dabe49bebf6b468c3c120f142822),
		BinaryField128bPolyval(0xf8f3c35c671bac841b14381a592e6cdd),
		BinaryField128bPolyval(0xd7b888791bd83b13d80d2e9324894861),
		BinaryField128bPolyval(0x113ab0405354dd1c5aab9658137fa73f),
		BinaryField128bPolyval(0xae56192d5e9c309e461f797121b28ce6),
		BinaryField128bPolyval(0xb7927ec7a84c2e04811a6dac6b997783),
		BinaryField128bPolyval(0x9e2f8d67fc600703ba9b4189ce751cb4),
		BinaryField128bPolyval(0x574e95df2d8bb9e2c8fc29729eb723ca),
		BinaryField128bPolyval(0x38bc6fc47739c06cd9fa20f9a5088f26),
		BinaryField128bPolyval(0x69d3b9b1d9483174b3c38d8f95ce7a5f),
		BinaryField128bPolyval(0xd6e4bb147cc82b6e90e27e882f18640d),
		BinaryField128bPolyval(0x027338db641804d985cd9fece12f7adc),
		BinaryField128bPolyval(0x523cb73968169ccce76f523928c4364e),
		BinaryField128bPolyval(0xcdcf898117f927208a11b0dcc941f2f6),
		BinaryField128bPolyval(0xc908287814c8cba67f7892fec7a5b217),
		BinaryField128bPolyval(0x92b99988bb26215d104968d4cbbb285a),
		BinaryField128bPolyval(0x4dbca8fd835d00ea4b95692534ef5068),
		BinaryField128bPolyval(0xcd8b92c8a6e0e65e167a2b851f32fd9c),
		BinaryField128bPolyval(0xc3473dfda9f97d6ac1e2d544628e7845),
		BinaryField128bPolyval(0x0260e7badc64dbfde0dc39a240365722),
		BinaryField128bPolyval(0x3966125b40fe2bca9719c80e41953868),
		BinaryField128bPolyval(0xac0211506eda3cba57b709a360d4a2c7),
		BinaryField128bPolyval(0x0e4f0e47d02fedd15b337fefa219c52b),
		BinaryField128bPolyval(0x1d5907ccdc659f7aace675511f754ee3),
		BinaryField128bPolyval(0x4ad5b368eaddc4bb097284863b2a5b6e),
		BinaryField128bPolyval(0x2eae07273b8c4fc5cef553a4a46cde5b),
		BinaryField128bPolyval(0x096a310e7b1e3a3179d4a3b5d8dd9396),
		BinaryField128bPolyval(0x8c81362eeb1656a91dde08d05018a353),
		BinaryField128bPolyval(0x387e59e44cc0d53fecf7f057b6fdba0b),
		BinaryField128bPolyval(0x9d29670bbd0e8051ac82d91ca97561d6),
		BinaryField128bPolyval(0xaf1310d0f5cac4e89714e48065be74a4),
		BinaryField128bPolyval(0x9b684a3865c2b59c411d14182a36fb6b),
		BinaryField128bPolyval(0x3e7de163516ffdcaca22b4e848340fbe),
		BinaryField128bPolyval(0x3c37dbe331de4b0dc2f5db315d5e7fda),
		BinaryField128bPolyval(0x19e7f4b53ff86990e3d5a1c40c3769a0),
		BinaryField128bPolyval(0x56469ab32b2b82e8cc93fdb1b14a4775),
		BinaryField128bPolyval(0x9c01cefde47816300d8ad49d260bb71b),
		BinaryField128bPolyval(0x6100101b8cebde7381366fec1e4e52c0),
		BinaryField128bPolyval(0xa28d30c3cbd8b69632143fa65158ee4f),
		BinaryField128bPolyval(0x3db7a902ec509e58151c45f71eee6368),
		BinaryField128bPolyval(0x42d5a505e8ab70097107d37d79ebbaba),
		BinaryField128bPolyval(0xe47b83247cb2b162c7d6d15c84cca8ce),
		BinaryField128bPolyval(0x076caf0e23541c753e4c87ff505737a5),
		BinaryField128bPolyval(0x590a8d1cdbd17ae83980f5d1d3b84a89),
		BinaryField128bPolyval(0x77d649ff61a7cd0da53497edd34c4204),
		BinaryField128bPolyval(0xefbe0c34eeab379ea4a8feed84fd3993),
		BinaryField128bPolyval(0x90540cf7957a8a3051629cdde777f968),
		BinaryField128bPolyval(0x8749050496dd288244c49c70aa92831f),
		BinaryField128bPolyval(0x0fc80b1d600406b2370368d94947961a),
	]);

impl From<BinaryField128b> for BinaryField128bPolyval {
	fn from(value: BinaryField128b) -> Self {
		BINARY_TO_POLYVAL_TRANSFORMATION.transform(&value)
	}
}

pub const POLYVAL_TO_BINARY_TRANSFORMATION: FieldLinearTransformation<BinaryField128b> =
	FieldLinearTransformation::new_const(&[
		BinaryField128b(0x66e1d645d7eb87dca8fc4d30a32dadcc),
		BinaryField128b(0x53ca87ba77172fd8c5675d78c59c1901),
		BinaryField128b(0x1a9cf63d31827dcda15acb755a948567),
		BinaryField128b(0xa8f28bdf6d29cee2474b0401a99f6c0a),
		BinaryField128b(0x4eefa9efe87ed19c06b39ca9799c8d73),
		BinaryField128b(0x06ec578f505abf1e9885a6b2bc494f3e),
		BinaryField128b(0x70ecdfe1f601f8509a96d3fb9cd3348a),
		BinaryField128b(0xcb0d16fc7f13733deb25f618fc3faf28),
		BinaryField128b(0x4e9a97aa2c84139ffcb578115fcbef3c),
		BinaryField128b(0xc6de6210afe8c6bd9a441bffe19219ad),
		BinaryField128b(0x73e3e8a7c59748601be5bf1e30c488d3),
		BinaryField128b(0x1f6d67e2e64bd6c4b39e7f4bb37dce9c),
		BinaryField128b(0xc34135d567eada885f5095b4c155f3b5),
		BinaryField128b(0x23f165958d59a55e4790b8e2e37330e4),
		BinaryField128b(0x4f2be978f16908e405b88802add08d17),
		BinaryField128b(0x6442b00f5bbf4009907936513c3a7d45),
		BinaryField128b(0xac63f0397d911a7a5d61b9f18137026f),
		BinaryField128b(0x8e70543ae0e43313edf07cbc6698e144),
		BinaryField128b(0xcb417a646d59f652aa5a07984066d026),
		BinaryField128b(0xf028de8dd616318735bd8f76de7bb84e),
		BinaryField128b(0x2e03a12472d21599f15b4bcaa9bf186c),
		BinaryField128b(0x54a376cc03e5b2cfa27d8e48d1b9ca76),
		BinaryField128b(0xd22894c253031b1b201b87da07cb58ae),
		BinaryField128b(0x6bc1416afea6308ff77d902dd5d2a563),
		BinaryField128b(0x9958ecd28adbebf850055f8ac3095121),
		BinaryField128b(0x595a1b37062233d7e6bb6f54c227fb91),
		BinaryField128b(0x41ffcfcdda4583c4f671558ee315d809),
		BinaryField128b(0x780c2490f3e5cb4763e982ec4b3e6ea2),
		BinaryField128b(0xf7a450b35931fa76722a6b9037b6db34),
		BinaryField128b(0xe21991100e84821328592772430ad07e),
		BinaryField128b(0x360d4079f62863cc60c65ec87d6f9277),
		BinaryField128b(0xd898bfa0b076cc4eaca590e7a60dbe92),
		BinaryField128b(0xcaacddd5e114fe5c2e1647fc34b549bf),
		BinaryField128b(0x3042e34911c28e90617776ddb2d3f888),
		BinaryField128b(0x3728a3b0da53cdfecfd8455b13cb9b14),
		BinaryField128b(0x2f2eb3d5bc7b2c48a7c643bffbddc6b2),
		BinaryField128b(0x3b71a5c04010c0aa501b04302706b908),
		BinaryField128b(0x0701845b090e79bb9be54df766e48c51),
		BinaryField128b(0x1e9eac7bf45b14c8db06fcfff7408f78),
		BinaryField128b(0x6b1b8e39a339423d0eb3bef69eee8b0b),
		BinaryField128b(0x8b06616385967df95d3a99cff1edcf0a),
		BinaryField128b(0x5d921137890a3ded58e1dd1a51fe6a30),
		BinaryField128b(0x828ed6fba42805b2628b705d38121acc),
		BinaryField128b(0x9b7a95220e9d5b0ff70ecb6116cabd81),
		BinaryField128b(0x0eb9055cb11711ed047f136cab751c88),
		BinaryField128b(0xd6f590777c17a6d0ca451290f7d5c78a),
		BinaryField128b(0x401a922a6461fbe691f910cb0893e71f),
		BinaryField128b(0x15a549308bc53902c927ebad9ed253f7),
		BinaryField128b(0x45dccafc72a584480f340a43f11a1b84),
		BinaryField128b(0x19d2a2c057d60656e6d3e20451335d5b),
		BinaryField128b(0x035af143a5827a0f99197c8b9a811454),
		BinaryField128b(0x7ee35d174ad7cc692191fd0e013f163a),
		BinaryField128b(0xc4c0401d841f965c9599fac8831effa9),
		BinaryField128b(0x63e809a843fc04f84acfca3fc5630691),
		BinaryField128b(0xdb2f3301594e3de49fb7d78e2d6643c4),
		BinaryField128b(0x1b31772535984ef93d709319cc130a7c),
		BinaryField128b(0x036dc9c884cd6d6c918071b62a0593f3),
		BinaryField128b(0x4700cd0e81c88045132360b078027103),
		BinaryField128b(0xdfa3f35eb236ea63b0350e17ed2d625d),
		BinaryField128b(0xf0fd7c7760099f1ac28be91822978e15),
		BinaryField128b(0x852a1eba3ad160e95034e9eed1f21205),
		BinaryField128b(0x4a07dd461892df45ca9efee1701763c3),
		BinaryField128b(0xadbbaa0add4c82fe85fd61b42f707384),
		BinaryField128b(0x5c63d0673f33c0f2c231db13f0e15600),
		BinaryField128b(0x24ddc1516501135626e0e794dd4b3076),
		BinaryField128b(0xb60c601bbf72924e38afd02d201fb05b),
		BinaryField128b(0x2ef68918f416caca84334bcf70649aeb),
		BinaryField128b(0x0b72a3124c504bcad815534c707343f2),
		BinaryField128b(0xcfd8b2076040c43d5d396f8523d80fe0),
		BinaryField128b(0x098d9daf64154a63504192bb27cc65e1),
		BinaryField128b(0x3ae44070642e6720283621f8fb6a6704),
		BinaryField128b(0x19cd9b2843d0ff936bfe2b373f47fd05),
		BinaryField128b(0x451e2e4159c78e65db10450431d26122),
		BinaryField128b(0x797b753e29b9d0e9423b36807c70f3ae),
		BinaryField128b(0xa8d0e8ba9bb634f6ea30600915664e22),
		BinaryField128b(0xdf8c74bbd66f86809c504cb944475b0a),
		BinaryField128b(0x32831a457ced3a417a5a94d498128018),
		BinaryField128b(0x1aca728985936a6147119b9b5f00350e),
		BinaryField128b(0x6f436d64b4ee1a556b66764ed05bb1db),
		BinaryField128b(0x25930eaed3fd982915e483cb21e5a1a2),
		BinaryField128b(0x21735f5eb346e56006bf1d7e151780ab),
		BinaryField128b(0x55fc6f607f10e17f805eb16d7bd5345c),
		BinaryField128b(0x4b4d289591f878114965292af4aeb57e),
		BinaryField128b(0x30608bc7444bcbaff67998c1883c1cf3),
		BinaryField128b(0xa12a72abe4152e4a657c6e6395404343),
		BinaryField128b(0x7579186d4e0959dec73f9cd68fb0e2fb),
		BinaryField128b(0xb5560ce63f7894cc965c822892b7bfda),
		BinaryField128b(0x6b06d7165072861eba63d9fd645995d7),
		BinaryField128b(0x359f439f5ec9107dde3c8ef8f9bf4e29),
		BinaryField128b(0xcbfe7985c6006a46105821cd8b55b06b),
		BinaryField128b(0x2110b3b51f5397ef1129fb9076474061),
		BinaryField128b(0x1928478b6f3275c944c33b275c388c47),
		BinaryField128b(0x23f978e6a0a54802437111aa4652421a),
		BinaryField128b(0xe8c526bf924dc5cd1dd32dbedd310f5b),
		BinaryField128b(0xa0ac29f901f79ed5f43c73d22a05c8e4),
		BinaryField128b(0x55e0871c6e97408f47f4635b747145ea),
		BinaryField128b(0x6c2114c3381f53667d3c2dfefd1ebcb3),
		BinaryField128b(0x42d23c18722fbd58863c3aceaaa3eef7),
		BinaryField128b(0xbb0821ab38d5de133838f8408a72fdf1),
		BinaryField128b(0x035d7239054762b131fa387773bb9153),
		BinaryField128b(0x8fa898aafe8b154f9ab652e8979139e7),
		BinaryField128b(0x6a383e5cd4a16923c658193f16cb726c),
		BinaryField128b(0x9948caa8c6cefb0182022f32ae3f68b9),
		BinaryField128b(0x8d2a8decf9855bd4df7bac577ed73b44),
		BinaryField128b(0x09c7b8300f0f984259d548c5aa959879),
		BinaryField128b(0x92e16d2d24e070efdca8b8e134047afc),
		BinaryField128b(0x47d8621457f4118aaf24877fb5031512),
		BinaryField128b(0x25576941a55f0a0c19583a966a85667f),
		BinaryField128b(0xb113cad79cd35f2e83fda3bc6285a8dc),
		BinaryField128b(0xc76968eecb2748d0c3e6318431ffe580),
		BinaryField128b(0x7211122aa7e7f6fe39e6618395b68416),
		BinaryField128b(0x88463599bf7d3e92f450d00a45146d11),
		BinaryField128b(0x6e12b7d5adf95da33bbb7f79a18ee123),
		BinaryField128b(0xe0a98ac4025bc568eaca7e7b7280ff16),
		BinaryField128b(0xc13fc79f6c35048df274057ac892ff77),
		BinaryField128b(0x93c1a3145d4e47dee39cae4de47eb505),
		BinaryField128b(0x780064be3036df98f1e5d7c53bdbd52b),
		BinaryField128b(0x48c467b5cec265628b709172ecaff561),
		BinaryField128b(0x5bbbab77ce5552ff7682094560524a7e),
		BinaryField128b(0x551537ef6048831fb128fec4e4a23a63),
		BinaryField128b(0xe7ef397fcc095ead439317a13568b284),
		BinaryField128b(0xbc5d2927eac0a720f9d75d62d92c6332),
		BinaryField128b(0x3bfeb420021f93e9b2bc992b5b59e61e),
		BinaryField128b(0xc651dc438e2f1bc64af1b7307b574ed9),
		BinaryField128b(0xbfe0a17ee2b777542a1ddb55413a4e43),
		BinaryField128b(0xa062da2427df3d1a7dfc01c05d732a32),
		BinaryField128b(0x1e4889fd72b70ecf93417ba0b085e1e8),
		BinaryField128b(0xc4f4769f4f9c2e33c26a6bf2ca842f17),
	]);

impl From<BinaryField128bPolyval> for BinaryField128b {
	fn from(value: BinaryField128bPolyval) -> Self {
		POLYVAL_TO_BINARY_TRANSFORMATION.transform(&value)
	}
}

pub const AES_TO_POLYVAL_TRANSFORMATION: FieldLinearTransformation<BinaryField128bPolyval> =
	FieldLinearTransformation::new_const(&[
		BinaryField128bPolyval(0xc2000000000000000000000000000001),
		BinaryField128bPolyval(0xe632e878241983acfe888a04c4d9a761),
		BinaryField128bPolyval(0xac11ddf4a4b79d5c48ac4c527597b579),
		BinaryField128bPolyval(0x6b9e5d3f1b690b05f3313f030e46356c),
		BinaryField128bPolyval(0x2b04f6e5ed1de8f556e7d64ddd06e9cb),
		BinaryField128bPolyval(0x31001e7abbe11a74c26378b8a5589564),
		BinaryField128bPolyval(0xa7698d9fd5f16f53cb2ea07a2e92f955),
		BinaryField128bPolyval(0xfc2bf21f1b48c91511a841fb19894992),
		BinaryField128bPolyval(0x586704bda927015fedb8ddceb7f825d6),
		BinaryField128bPolyval(0x141f1af5b6fc687390fa434e9b3df535),
		BinaryField128bPolyval(0xe2fab31ae2a86c482d15591868e50692),
		BinaryField128bPolyval(0x5b1ab4f647466009452d4152d4a2d9b7),
		BinaryField128bPolyval(0x5e0f7136a0b09b8039655d2dea094bf2),
		BinaryField128bPolyval(0x6f2075bc8788f28152a66d96ce4680bb),
		BinaryField128bPolyval(0x4140c7bd1f7aedd86b92e5fd101ee1c6),
		BinaryField128bPolyval(0xdde2a8ec4d0e54eeb5a4a25f51c6e4fa),
		BinaryField128bPolyval(0xc50e3a207f91d7cd6dd1e116d55455fb),
		BinaryField128bPolyval(0xfa1ac734a9812f783652ef8b68356a41),
		BinaryField128bPolyval(0x36513023ad98424cb71c04fe89e160a7),
		BinaryField128bPolyval(0x049537ba21f47f9b04d482dde77f1d35),
		BinaryField128bPolyval(0x62da2377f5423631f244f3eb099cf2b7),
		BinaryField128bPolyval(0x4a23f578b5ea2846dcc6c290ef1e8aaa),
		BinaryField128bPolyval(0x6e95c9eedf7f47b3d594d365d23f0664),
		BinaryField128bPolyval(0xd2a1e8b6757668d5c29a321b50d6f02d),
		BinaryField128bPolyval(0xf4400f37acedc7d9502abeff6cead84c),
		BinaryField128bPolyval(0xf200b20bda2bad094b52961d78c3b76d),
		BinaryField128bPolyval(0x6d80e955976082ba5db58a84889d3418),
		BinaryField128bPolyval(0x44c1b7aca2c318b69501d626d8e3e1be),
		BinaryField128bPolyval(0xfc140c4a4801a6f1ca47bea4142a8e09),
		BinaryField128bPolyval(0xe7dc049975b85a68922acd362cba0aae),
		BinaryField128bPolyval(0x0d2181f080634f18c69d05ea5068dcc7),
		BinaryField128bPolyval(0x66b185642341f6a71c11a443ec30bcfa),
		BinaryField128bPolyval(0xa26153cb8c150af8243ecbd46378e59e),
		BinaryField128bPolyval(0x8f3b44831e624145fb0b4dffddbd0338),
		BinaryField128bPolyval(0x238a42154a23b1278ba6133fa32887d2),
		BinaryField128bPolyval(0xaea5e0bd0f23bb3755ca8a198e51a02c),
		BinaryField128bPolyval(0x382af0a162eb58f6888bd591d34850ee),
		BinaryField128bPolyval(0x7c7ab1035fd703fdaef544d7f152f9ff),
		BinaryField128bPolyval(0xd81f70c2928c2a2e45c3ff8900f225b7),
		BinaryField128bPolyval(0x05d5f641d32186b75064f07fefaade44),
		BinaryField128bPolyval(0x00a3a4d8c163c95ac7ac9a5b424e1c65),
		BinaryField128bPolyval(0xdc951260493c96fca603481ab501d438),
		BinaryField128bPolyval(0x99400402d352c6a6879277fa8e022149),
		BinaryField128bPolyval(0x3bebf7af750eace1e434f9a5925288ee),
		BinaryField128bPolyval(0x9f171f736eff43513721ae2942afe01d),
		BinaryField128bPolyval(0xe3e184abe50f7387c5fdd01faf6c95d3),
		BinaryField128bPolyval(0x1fae32af2dc4238dcce57975be1b2400),
		BinaryField128bPolyval(0x282116c0f04b6707698f1ea25790ea10),
		BinaryField128bPolyval(0x564032a0d5d3773b7b7ed18bebf1c668),
		BinaryField128bPolyval(0xe40d8bdaad8fdd00b3f004e706e35b10),
		BinaryField128bPolyval(0x675892c7e2ead5594ef74c71079069d2),
		BinaryField128bPolyval(0x25e285580c933861739d2b031eb4b2d3),
		BinaryField128bPolyval(0x51e78b32d4dd25445b2d1f30689d6abb),
		BinaryField128bPolyval(0x133994dbfd8ce08ae714538d557eb150),
		BinaryField128bPolyval(0x278247597906a3b1f990119cde5ffb24),
		BinaryField128bPolyval(0xef387e28a39a63ed81710b9bdbc74005),
		BinaryField128bPolyval(0x41bbc7902188f4e9880f1d81fa580ffb),
		BinaryField128bPolyval(0x415afa934ada855ba61bbef36d27db58),
		BinaryField128bPolyval(0xe477f6fac6a1c2057662a149aa0ae061),
		BinaryField128bPolyval(0xe98aee0eeb136ee02e2be740d058fe5d),
		BinaryField128bPolyval(0x777ead11e8dc98c5ffd710b823fc5093),
		BinaryField128bPolyval(0xa4e9927e7da484643651b5532106b1e3),
		BinaryField128bPolyval(0x9fdfc576fcf0b33b829f1a052e9355f2),
		BinaryField128bPolyval(0x342bbe0ad297a239b415fc050f1a23f7),
		BinaryField128bPolyval(0x756209f0893e96877833c194b9c943a0),
		BinaryField128bPolyval(0xc763ed07e05784c3ca283e12f9f22368),
		BinaryField128bPolyval(0xb04147b7592c8c80508e1ee45b2c4806),
		BinaryField128bPolyval(0x4f0557d1988f518b39bd6fc3c2fba372),
		BinaryField128bPolyval(0x7259d355775035632bfb7b003178ae0e),
		BinaryField128bPolyval(0x7826c6a2e9e37bbd991ef41faa246832),
		BinaryField128bPolyval(0x4d12f861b14f57602cd121d6622efcf6),
		BinaryField128bPolyval(0x47979b6dc50802e344b543260f9f14e4),
		BinaryField128bPolyval(0xf330cd9a74a5e884988c3f36567d26f4),
		BinaryField128bPolyval(0xb9d4fca088a982f6a9add501644e56b2),
		BinaryField128bPolyval(0xee9e3f0fbab5cc33378947fd04769519),
		BinaryField128bPolyval(0x0819f0cb4253a5ab7cb10f583ce13537),
		BinaryField128bPolyval(0x0ba10d161c76ba69a4b68d140886097a),
		BinaryField128bPolyval(0x7850cec4236f7ea4698d1b15707a8bf8),
		BinaryField128bPolyval(0x5a712763179ba0a99e8bbe5e3b73146f),
		BinaryField128bPolyval(0x8d825f45c33f7a1f45be2e3938a0fcfc),
		BinaryField128bPolyval(0xf8f3c35c671bac841b14381a592e6cdd),
		BinaryField128bPolyval(0x96d15acd59e4c4852735c30c972140ee),
		BinaryField128bPolyval(0x87d0c6a97af12deec54ecfd097c5a4ff),
		BinaryField128bPolyval(0x4152fe90327dcbe147e8771ba0334ba1),
		BinaryField128bPolyval(0xb6793169bc400bfc14ed05b58db2b472),
		BinaryField128bPolyval(0x071df72b3ce39b686d6f52b53e608c7a),
		BinaryField128bPolyval(0xcf97a03df90400718aff5257888970f5),
		BinaryField128bPolyval(0xa05e7602d3f74d882329c158a0ad9f37),
		BinaryField128bPolyval(0x69d3b9b1d9483174b3c38d8f95ce7a5f),
		BinaryField128bPolyval(0x54882e1b0f3f749397cbeff7c70f0c73),
		BinaryField128bPolyval(0x1df3271f8f5398ff2937a4f0fd041cfa),
		BinaryField128bPolyval(0xc964a4d09783b7483c1845943333022b),
		BinaryField128bPolyval(0x64991e811d81abc5cef407bebff096bd),
		BinaryField128bPolyval(0x12a6345cacc97a7992ad6647c2833af8),
		BinaryField128bPolyval(0xe04112ac095f1c67b9792b0fb82cc4fe),
		BinaryField128bPolyval(0x744c1206d550d565d994fe159c5cd699),
		BinaryField128bPolyval(0xcd8b92c8a6e0e65e167a2b851f32fd9c),
		BinaryField128bPolyval(0x994beaf6226f215c7b4187e0c36e08a6),
		BinaryField128bPolyval(0x71d346897647348c7eb7752a3a893424),
		BinaryField128bPolyval(0xb0f49cce03da921b5f8999cc18311b43),
		BinaryField128bPolyval(0x45b6960f54a16e547a329f79210629d0),
		BinaryField128bPolyval(0x4535377d8b9718b1f6991e57fea36922),
		BinaryField128bPolyval(0xbf97b9a9bda638f42cc98233021d69fd),
		BinaryField128bPolyval(0x02e346c80352ad186c77b88c9f9317d0),
		BinaryField128bPolyval(0x2eae07273b8c4fc5cef553a4a46cde5b),
		BinaryField128bPolyval(0x86c51811ef12c72fcabfc51b2a2e0c2a),
		BinaryField128bPolyval(0x8a828ea9f6b97e5c3b0b4c6faed116e6),
		BinaryField128bPolyval(0x0f69898966b112c45f01e70a26142623),
		BinaryField128bPolyval(0x109173f0af80af37cf9d6ef791d2feed),
		BinaryField128bPolyval(0x984655091ad81e2befa87a6688ddc784),
		BinaryField128bPolyval(0x21851b1a985e40395abe3d15fff2d770),
		BinaryField128bPolyval(0x045610d75e4ee7b53deb1c4149179a3a),
		BinaryField128bPolyval(0x3c37dbe331de4b0dc2f5db315d5e7fda),
		BinaryField128bPolyval(0x09ca74968860fc3d723b7966d8574ce1),
		BinaryField128bPolyval(0x8892f14b27f8e4d1b01efa51eeaa4ad4),
		BinaryField128bPolyval(0xc7339f4d332b0fa99f58a62453d76401),
		BinaryField128bPolyval(0xfc81ac07b51d1d165b5525b77bf5f969),
		BinaryField128bPolyval(0x7bdcb39270e3891d486160e47bc4015c),
		BinaryField128bPolyval(0x7967964f6e9d62b6b50a50ee51c927d2),
		BinaryField128bPolyval(0xd11b8526eed516e3dfa7b8e2b17bbf40),
		BinaryField128bPolyval(0xe47b83247cb2b162c7d6d15c84cca8ce),
		BinaryField128bPolyval(0x5136c420c1a70a4b697e000c637ec876),
		BinaryField128bPolyval(0x2114cffeda72b157abb70ae549b39e97),
		BinaryField128bPolyval(0x7f72edec22f7d7caac7b78cbca5ce3bb),
		BinaryField128bPolyval(0xfb5ac3eb65636373828e242c79ef5046),
		BinaryField128bPolyval(0x8819e336afff44542a76ee524a033645),
		BinaryField128bPolyval(0x8be0251a2790b20b19f6343efaf425e7),
		BinaryField128bPolyval(0x2a49adc1114d5dcf91783fafe0542c8a),
	]);

impl From<AESTowerField128b> for BinaryField128bPolyval {
	fn from(value: AESTowerField128b) -> Self {
		AES_TO_POLYVAL_TRANSFORMATION.transform(&value)
	}
}

pub const POLYVAL_TO_AES_TRANSFORMARION: FieldLinearTransformation<AESTowerField128b> =
	FieldLinearTransformation::new_const(&[
		AESTowerField128b(0xaffaa99fa8aa55f93974735e68d0882a),
		AESTowerField128b(0x402655567dde6c49c7aea09cc7d73e01),
		AESTowerField128b(0x83d724035fe42d2bd4ad27c1ad3be9ae),
		AESTowerField128b(0x39940944fe609647237fb001386aff50),
		AESTowerField128b(0xce1a381a1790a4d70cbbd7389dd705cd),
		AESTowerField128b(0x0ca7f0b9fdade73367e9d9ba5ac3cfbe),
		AESTowerField128b(0x70a744fa2401c4fddb871879d718ee08),
		AESTowerField128b(0x275ddf74916ecd03aa3c243f74bf3461),
		AESTowerField128b(0xcedb8685d1e86e6a74b79cd21c271a02),
		AESTowerField128b(0x7a451fd334177a5bdb9e82c9fa373e88),
		AESTowerField128b(0xcd4617d8c786c2a3824ae7335ec6b418),
		AESTowerField128b(0x32feae47f77fa9c6bb6b917fbb2d96d7),
		AESTowerField128b(0xcb2fef14aeabf5b41cfd3ab6774c95b7),
		AESTowerField128b(0x3029123a0510641d238bea4746cd5e4b),
		AESTowerField128b(0xcfdc169c294eec4bb1eab4bc88a505de),
		AESTowerField128b(0x139206e1ace72eed8b9d52fc020e2d9f),
		AESTowerField128b(0x891e28b32d8a8320a0a2eb295953bc42),
		AESTowerField128b(0xb8704d0efb4be36ea6282c5aaf67fa9e),
		AESTowerField128b(0x272f2013fe10244185ad0d672eafa581),
		AESTowerField128b(0x28614505a9df5f55ef5bb97c4521eace),
		AESTowerField128b(0x6dbdd43dcc19626629ac7f2638e73fff),
		AESTowerField128b(0x4d687c2abd4aba97692db8c2a4eb267c),
		AESTowerField128b(0x19613bca40bd82828d8255f50d271135),
		AESTowerField128b(0xf2772ff3c8d95eb9252d8bd01419641e),
		AESTowerField128b(0x6611a71908f4aac4fdb11c08cbedfc8c),
		AESTowerField128b(0x10ad82530c31e3a8f757424dca80798a),
		AESTowerField128b(0x2fc9972bf59fe5c624714cb8466249ed),
		AESTowerField128b(0x9c5c3d8b954a27231e16e4a77fbe4369),
		AESTowerField128b(0x2565fdbb105f787cccddf28b530af4ee),
		AESTowerField128b(0x473e8ad3e0e8e46e611080cc9350a590),
		AESTowerField128b(0x525d2e9d24611e2aa37a1d9a2d42377d),
		AESTowerField128b(0x4967e7d5067c2ace89648bf6d95de637),
		AESTowerField128b(0x2689f814fa63c8a16ddf2374eeb7c3e7),
		AESTowerField128b(0x5e9246c3d2cab88ba27d7cf8ba18c4b4),
		AESTowerField128b(0x53616806f5402bc897499fac6e27da63),
		AESTowerField128b(0x6c6dbb145a21d1c2d87a93e779f87aba),
		AESTowerField128b(0x0f7164762ed37685fd82b05e800cebec),
		AESTowerField128b(0x0d01e8acede09d57da4a7325af4b04fc),
		AESTowerField128b(0x336b892198ac639af40c74c9252eb99c),
		AESTowerField128b(0xf282b8b368b39203e0bbe6246b1b0951),
		AESTowerField128b(0x090ca21ee9872dc5a00e669729a69750),
		AESTowerField128b(0xa037d253b55003a611faf883fcc8f35e),
		AESTowerField128b(0xe4b8a9796561b1ba1f0970a0b26f832a),
		AESTowerField128b(0xda203a31e0d6ace125e027a2df265b59),
		AESTowerField128b(0xe0ebb1a107ded2a6b0916eff84c18fb4),
		AESTowerField128b(0xa9998b7d2cded9a5269f6f8b25147b08),
		AESTowerField128b(0x2e8337dd13a279f78ac5d327ec36f632),
		AESTowerField128b(0x6264c35e09c7b3bc9b80aa886b194025),
		AESTowerField128b(0x9ff92674cc64e8c2e1ee5093298382e8),
		AESTowerField128b(0x3e196976f0a90cf1f71847b0fce3a0ac),
		AESTowerField128b(0xbdad299364e420e1663e2c09db59634d),
		AESTowerField128b(0x9046a0de7ea82a4e8c8a75e001bfdf0e),
		AESTowerField128b(0xc6762e8ee83287a13a66789ae533c938),
		AESTowerField128b(0x1e17ed399374b0c47e9726bfc71e0c8a),
		AESTowerField128b(0xf46ce30110ce034b6a0ba8b8d0af93c6),
		AESTowerField128b(0x825f7d3cef67cec50370363e2a6e502c),
		AESTowerField128b(0xbdfe9b9ae82bfeff8a58710addb13695),
		AESTowerField128b(0x23002be0599a589f6e30a3069cbc71bd),
		AESTowerField128b(0x4468951dba52ab1e06efe0dea6d01fa0),
		AESTowerField128b(0x28752c7da3ed6a83ca09163f3186b862),
		AESTowerField128b(0xe9dd33560ea4a316fdee161ba4946fb1),
		AESTowerField128b(0x7e0df8223f37449f266bc8fa70de1ecb),
		AESTowerField128b(0x88578550f872e4c8e975a2b66c70cde8),
		AESTowerField128b(0xa11ea5aebfe37694ca5ff46e28faf100),
		AESTowerField128b(0x3df877fc12016ef181fbf63bf87f5e7c),
		AESTowerField128b(0x0a5ca382e7cc37ceb234a5d08d3206ac),
		AESTowerField128b(0x6d24b53f98df2626e8e37f977013dbaa),
		AESTowerField128b(0x51cc686f72fd7f264962407270cd9394),
		AESTowerField128b(0x9749ba0da32ec603a0b342e93049e1fb),
		AESTowerField128b(0xed05d63413627e1efd2f3757802a12fa),
		AESTowerField128b(0x0e4b2e70136dae8d61528cc479f3aeb0),
		AESTowerField128b(0x3e2bda6193a5c936f2c8dc53bf2375b1),
		AESTowerField128b(0x9f336d2f107bb812f4d39fb05f19a231),
		AESTowerField128b(0x9d21c1be60eba516920f52582c709535),
		AESTowerField128b(0x39a51756da0aee24ab5ea3ed62afce31),
		AESTowerField128b(0x4404c057a9425458d7fd72eb9e23ac50),
		AESTowerField128b(0xe2e5839f2ca60e2f20ad3b15676f583f),
		AESTowerField128b(0x8326ccb5e936f3a223d2dada1c00efe0),
		AESTowerField128b(0x4293fe13b61b834cf2af7ccea5ac07f4),
		AESTowerField128b(0x3c36e03518756760624be5278c4ad469),
		AESTowerField128b(0x8ccd1c1dbb224aa30ce78e9062de5884),
		AESTowerField128b(0x4c7442a391d3fa91581d07fe2114eea1),
		AESTowerField128b(0x7f73613a8ac49cd2c31260dd9835b790),
		AESTowerField128b(0x5ea3097b9e7f2734249d6777b4028f95),
		AESTowerField128b(0xd4ddcc844b626d7e122c431e3a2e9393),
		AESTowerField128b(0xc19d3ffeceed10457bbfd7a9b9064779),
		AESTowerField128b(0xb7f15cf7bf9c3b2a87a1e461370be7f5),
		AESTowerField128b(0xf20ca8dffdcc5433561e487513103aa8),
		AESTowerField128b(0xef6a936a1d9bd32d4502b8c4c5e7ce60),
		AESTowerField128b(0x27c89de97a00f322d3118c2b094c06f2),
		AESTowerField128b(0x8cd3bbb73240861ad260798b7c232ea2),
		AESTowerField128b(0x3e61230942e2c19b9ecb0f80a1b20423),
		AESTowerField128b(0x30c59cf7d564c2bc9371d28522419283),
		AESTowerField128b(0x17c781e73773c72b8e18d0e6f85fe1ac),
		AESTowerField128b(0xd58960c501256b149802cd19ddb19a4b),
		AESTowerField128b(0x4cfb558f43862eb923981eacc0719fab),
		AESTowerField128b(0xff8c63cbb23240af2d02d0c875335abb),
		AESTowerField128b(0x9219023fcc6c5b1154020e9685681b25),
		AESTowerField128b(0x57ec8c84b214456eb2b2c42e08cc7529),
		AESTowerField128b(0xbda0ccb3b1231f075f78b27dcd578a40),
		AESTowerField128b(0xb9396785c80962cfdb0a4117868ab3f6),
		AESTowerField128b(0xf3b2bea115d44e307a113ebfdf27ccff),
		AESTowerField128b(0x66c226397a967901e4bc6ce235bf4feb),
		AESTowerField128b(0x05dd05a7c5e9ac15442189f090a80f9e),
		AESTowerField128b(0xed7bea5ee1e167921014c2c7853a679d),
		AESTowerField128b(0x37fafed03dfb701af939eafaeeb02074),
		AESTowerField128b(0x23491f63f098d208343d5591b7bd626f),
		AESTowerField128b(0x3cf04e2f641c505c3e110e87f3e9af91),
		AESTowerField128b(0x076e26a8d7181c6de575685a1fe939f9),
		AESTowerField128b(0x7b4e4f1b2780c2a5cbf75fe85fc94a58),
		AESTowerField128b(0xccd26fddd8f624c8b3f7a2e53a0ae8df),
		AESTowerField128b(0xb422ef66e72dbe3798fda5509f63fed2),
		AESTowerField128b(0x436f0b1488c5a0680f57919dd4b8fa30),
		AESTowerField128b(0xfb3808c6bcacc74fab269021cc58c9df),
		AESTowerField128b(0x77bf7b6affefb00594c0b1209a37c97d),
		AESTowerField128b(0x36776863a0ce234546d735734b90b7b1),
		AESTowerField128b(0x9c0013e65e524467294aa8c70ff414dc),
		AESTowerField128b(0xc2c6aeb796ca121f09708acca73499a2),
		AESTowerField128b(0xac57847d964c41c97ce4ed9fa3417e90),
		AESTowerField128b(0x4c62531aa3c2e5320761c8c64b690e1e),
		AESTowerField128b(0xf61ab3912aed1d889336ded4ef4fbae8),
		AESTowerField128b(0x5aa06080ab76d88dc5a8a01f48d11ee2),
		AESTowerField128b(0x0fc8b68dbc323616ba5a66dcac10f733),
		AESTowerField128b(0x7afcf993b86c827a7e290b5e21f0ce48),
		AESTowerField128b(0xe7fbd490470b7d4ddd8ef44c2f0ece93),
		AESTowerField128b(0xd51ff53d804403832d740176a0cddde2),
		AESTowerField128b(0x33c2b575cc0be097362f21d506e9fa17),
		AESTowerField128b(0xc6987c6acfd76de3caf3f29426e86cde),
	]);

impl From<BinaryField128bPolyval> for AESTowerField128b {
	fn from(value: BinaryField128bPolyval) -> Self {
		POLYVAL_TO_AES_TRANSFORMARION.transform(&value)
	}
}

#[inline(always)]
pub fn is_polyval_tower<F: TowerField>() -> bool {
	TypeId::of::<F>() == TypeId::of::<BinaryField128bPolyval>()
		|| TypeId::of::<F>() == TypeId::of::<BinaryField1b>()
}

#[cfg(test)]
mod tests {
	use binius_utils::{SerializeBytes, bytes::BytesMut};
	use proptest::prelude::*;
	use rand::prelude::*;

	use super::*;
	use crate::{
		AESTowerField128b, PackedAESBinaryField1x128b, PackedAESBinaryField2x128b,
		PackedAESBinaryField4x128b, PackedBinaryField1x128b, PackedBinaryField2x128b,
		PackedBinaryField4x128b, PackedField, Random,
		arch::{
			packed_polyval_256::PackedBinaryPolyval2x128b,
			packed_polyval_512::PackedBinaryPolyval4x128b,
		},
		binary_field::tests::is_binary_field_valid_generator,
		linear_transformation::PackedTransformationFactory,
	};

	#[test]
	fn test_display() {
		assert_eq!(
			"0x00000000000000000000000000000001",
			format!("{}", BinaryField128bPolyval::ONE)
		);
		assert_eq!(
			"0x2a9055e4e69a61f0b5cfd6f4161087ba",
			format!("{}", BinaryField128bPolyval::new(0x2a9055e4e69a61f0b5cfd6f4161087ba))
		);
	}

	proptest! {
		#[test]
		fn test_multiplicative_identity(v in any::<u128>()) {
			let v = BinaryField128bPolyval::new(v);
			assert_eq!(v, v * BinaryField128bPolyval::ONE);
		}
	}

	#[test]
	fn test_mul() {
		assert_eq!(
			BinaryField128bPolyval::new(0x2a9055e4e69a61f0b5cfd6f4161087ba)
				* BinaryField128bPolyval::new(0x3843cf87fb7c84e18276983bed670337),
			BinaryField128bPolyval::new(0x5b2619c8a035206a12100d7a171aa988)
		);
	}

	#[test]
	fn test_sqr() {
		assert_eq!(
			Square::square(BinaryField128bPolyval::new(0x2a9055e4e69a61f0b5cfd6f4161087ba)),
			BinaryField128bPolyval::new(0x59aba0d4ffa9dca427b5b489f293e529)
		);
	}

	#[test]
	fn test_multiplicative_generator() {
		assert!(is_binary_field_valid_generator::<BinaryField128bPolyval>());
	}

	fn test_packed_conversion<
		PT1: PackedField<Scalar: BinaryField> + PackedTransformationFactory<PT2>,
		PT2: PackedField<Scalar: BinaryField>,
	>(
		val: PT1,
		transformation: FieldLinearTransformation<PT2::Scalar>,
	) {
		let expected = PT2::from_fn(|i| transformation.transform(&val.get(i)));
		let transformed =
			<PT1 as PackedTransformationFactory<PT2>>::make_packed_transformation(transformation)
				.transform(&val);
		assert_eq!(transformed, expected);
	}

	proptest! {
		#[test]
		fn test_to_from_tower_basis(a_val in any::<u128>(), b_val in any::<u128>()) {
			let a_tower = BinaryField128b::new(a_val);
			let b_tower = BinaryField128b::new(b_val);
			let a_polyval = BinaryField128bPolyval::from(a_tower);
			let b_polyval = BinaryField128bPolyval::from(b_tower);
			assert_eq!(BinaryField128b::from(a_polyval * b_polyval), a_tower * b_tower);
		}

		#[test]
		fn test_conversion_roundtrip(a in any::<u128>()) {
			let a_val = BinaryField128bPolyval(a);
			let converted = BinaryField128b::from(a_val);
			assert_eq!(a_val, BinaryField128bPolyval::from(converted));

			let a_val = AESTowerField128b(a);
			let converted = BinaryField128bPolyval::from(a_val);
			assert_eq!(a_val, AESTowerField128b::from(converted));
		}

		#[test]
		fn test_conversion_mul_consistency(a in any::<u128>(), b in any::<u128>()) {
			let a_val = BinaryField128b::new(a);
			let b_val = BinaryField128b::new(b);
			let converted_a = BinaryField128bPolyval::from(a_val);
			let converted_b = BinaryField128bPolyval::from(b_val);
			assert_eq!(BinaryField128bPolyval::from(a_val * b_val), converted_a * converted_b);
		}

		#[test]
		fn test_conversion_128b(a in any::<u128>()) {
			test_packed_conversion::<PackedBinaryPolyval1x128b, PackedBinaryField1x128b>(a.into(), POLYVAL_TO_BINARY_TRANSFORMATION);
			test_packed_conversion::<PackedBinaryField1x128b, PackedBinaryPolyval1x128b>(a.into(), BINARY_TO_POLYVAL_TRANSFORMATION);

			test_packed_conversion::<PackedBinaryPolyval1x128b, PackedAESBinaryField1x128b>(a.into(), POLYVAL_TO_AES_TRANSFORMARION);
			test_packed_conversion::<PackedAESBinaryField1x128b, PackedBinaryPolyval1x128b>(a.into(), AES_TO_POLYVAL_TRANSFORMATION);
		}

		#[test]
		fn test_conversion_256b(a in any::<[u128; 2]>()) {
			test_packed_conversion::<PackedBinaryPolyval2x128b, PackedBinaryField2x128b>(a.into(), POLYVAL_TO_BINARY_TRANSFORMATION);
			test_packed_conversion::<PackedBinaryField2x128b, PackedBinaryPolyval2x128b>(a.into(), BINARY_TO_POLYVAL_TRANSFORMATION);

			test_packed_conversion::<PackedBinaryPolyval2x128b, PackedAESBinaryField2x128b>(a.into(), POLYVAL_TO_AES_TRANSFORMARION);
			test_packed_conversion::<PackedAESBinaryField2x128b, PackedBinaryPolyval2x128b>(a.into(), AES_TO_POLYVAL_TRANSFORMATION);
		}

		#[test]
		fn test_conversion_512b(a in any::<[u128; 4]>()) {
			test_packed_conversion::<PackedBinaryPolyval4x128b, PackedBinaryField4x128b>(PackedBinaryPolyval4x128b::from_underlier(a.into()), POLYVAL_TO_BINARY_TRANSFORMATION);
			test_packed_conversion::<PackedBinaryField4x128b, PackedBinaryPolyval4x128b>(PackedBinaryField4x128b::from_underlier(a.into()), BINARY_TO_POLYVAL_TRANSFORMATION);

			test_packed_conversion::<PackedBinaryPolyval4x128b, PackedAESBinaryField4x128b>(PackedBinaryPolyval4x128b::from_underlier(a.into()), POLYVAL_TO_AES_TRANSFORMARION);
			test_packed_conversion::<PackedAESBinaryField4x128b, PackedBinaryPolyval4x128b>(PackedAESBinaryField4x128b::from_underlier(a.into()), AES_TO_POLYVAL_TRANSFORMATION);
		}


		#[test]
		fn test_invert_or_zero(a_val in any::<u128>()) {
			let a = BinaryField128bPolyval::new(a_val);
			let a_invert = InvertOrZero::invert_or_zero(a);
			if a == BinaryField128bPolyval::ZERO {
				assert_eq!(a_invert, BinaryField128bPolyval::ZERO);
			} else {
				assert_eq!(a * a_invert, BinaryField128bPolyval::ONE);
			}
		}
	}

	/// Test that `invert` method properly wraps `invert_or_zero`
	#[test]
	fn test_invert() {
		let x = BinaryField128bPolyval::new(2);
		let y = x.invert().unwrap();

		assert_eq!(x * y, BinaryField128bPolyval::ONE);
	}

	#[test]
	fn test_conversion_from_1b() {
		assert_eq!(
			BinaryField128bPolyval::from(BinaryField1b::from(0)),
			BinaryField128bPolyval::ZERO
		);
		assert_eq!(
			BinaryField128bPolyval::from(BinaryField1b::from(1)),
			BinaryField128bPolyval::ONE
		);
	}

	#[test]
	fn test_serialization() {
		let mut buffer = BytesMut::new();
		let mut rng = StdRng::seed_from_u64(0);

		let b128_poly1 = BinaryField128bPolyval::random(&mut rng);
		let b128_poly2 = BinaryField128bPolyval::random(&mut rng);

		SerializeBytes::serialize(&b128_poly1, &mut buffer).unwrap();
		SerializeBytes::serialize(&b128_poly2, &mut buffer).unwrap();

		let mut read_buffer = buffer.freeze();

		assert_eq!(BinaryField128bPolyval::deserialize(&mut read_buffer).unwrap(), b128_poly1);
		assert_eq!(BinaryField128bPolyval::deserialize(&mut read_buffer).unwrap(), b128_poly2);
	}
}

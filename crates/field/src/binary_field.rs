// Copyright 2023-2025 Irreducible Inc.

use std::{
	any::TypeId,
	fmt::{Debug, Display, Formatter},
	iter::{Product, Sum},
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use binius_utils::{
	DeserializeBytes, SerializationError, SerializeBytes,
	bytes::{Buf, BufMut},
};
use bytemuck::{Pod, Zeroable};

use super::{
	binary_field_arithmetic::TowerFieldArithmetic, error::Error, extension::ExtensionField,
};
use crate::{
	Field,
	underlier::{U1, U2, U4},
};

/// A finite field with characteristic 2.
pub trait BinaryField: ExtensionField<BinaryField1b> {
	const N_BITS: usize = Self::DEGREE;
	const MULTIPLICATIVE_GENERATOR: Self;
}

/// A binary field *isomorphic* to a binary tower field.
///
/// The canonical binary field tower construction is specified in [DP23], section 2.3. This is a
/// family of binary fields with extension degree $2^{\iota}$ for any tower height $\iota$. This
/// trait can be implemented on any binary field *isomorphic* to the canonical tower field.
///
/// [DP23]: https://eprint.iacr.org/2023/1784
pub trait TowerField: BinaryField + From<Self::Canonical>
where
	Self::Canonical: From<Self>,
{
	/// The level $\iota$ in the tower, where this field is isomorphic to $T_{\iota}$.
	const TOWER_LEVEL: usize = Self::N_BITS.ilog2() as usize;

	/// The canonical field isomorphic to this tower field.
	/// Currently for every tower field, the canonical field is Fan-Paar's binary field of the same
	/// degree.
	type Canonical: TowerField + SerializeBytes + DeserializeBytes;

	/// Returns the smallest valid `TOWER_LEVEL` in the tower that can fit the same value.
	///
	/// Since which `TOWER_LEVEL` values are valid depends on the tower,
	/// `F::Canonical::from(elem).min_tower_level()` can return a different result
	/// from `elem.min_tower_level()`.
	fn min_tower_level(self) -> usize;

	/// Returns the i'th basis element of this field as an extension over the tower subfield with
	/// level $\iota$.
	fn basis(iota: usize, i: usize) -> Result<Self, Error> {
		if iota > Self::TOWER_LEVEL {
			return Err(Error::ExtensionDegreeTooHigh);
		}
		let n_basis_elts = 1 << (Self::TOWER_LEVEL - iota);
		if i >= n_basis_elts {
			return Err(Error::IndexOutOfRange {
				index: i,
				max: n_basis_elts,
			});
		}
		<Self as ExtensionField<BinaryField1b>>::basis_checked(i << iota)
	}

	/// Multiplies a field element by the canonical primitive element of the extension $T_{\iota +
	/// 1} / T_{iota}$.
	///
	/// We represent the tower field $T_{\iota + 1}$ as a vector space over $T_{\iota}$ with the
	/// basis $\{1, \beta^{(\iota)}_1\}$. This operation multiplies the element by
	/// $\beta^{(\iota)}_1$.
	///
	/// ## Throws
	///
	/// * `Error::ExtensionDegreeTooHigh` if `iota >= Self::TOWER_LEVEL`
	fn mul_primitive(self, iota: usize) -> Result<Self, Error> {
		Ok(self * <Self as ExtensionField<BinaryField1b>>::basis_checked(1 << iota)?)
	}
}

/// Returns the i'th basis element of `FExt` as a field extension of `FSub`.
///
/// This is an alias function for [`ExtensionField::basis`].
///
/// ## Pre-conditions
///
/// * `i` must be in the range $[0, d)$, where $d$ is the field extension degree.
#[inline]
pub fn ext_basis<FExt, FSub>(i: usize) -> FExt
where
	FSub: Field,
	FExt: ExtensionField<FSub>,
{
	<FExt as ExtensionField<FSub>>::basis(i)
}

pub(super) trait TowerExtensionField:
	TowerField
	+ ExtensionField<Self::DirectSubfield>
	+ From<(Self::DirectSubfield, Self::DirectSubfield)>
	+ Into<(Self::DirectSubfield, Self::DirectSubfield)>
{
	type DirectSubfield: TowerField;
}

/// Macro to generate an implementation of a BinaryField.
macro_rules! binary_field {
	($vis:vis $name:ident($typ:ty), $gen:expr) => {
		#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroable, bytemuck::TransparentWrapper)]
		#[repr(transparent)]
		$vis struct $name(pub(crate) $typ);

		impl $name {
			pub const fn new(value: $typ) -> Self {
				Self(value)
			}

			pub const fn val(self) -> $typ {
				self.0
			}
		}

		unsafe impl $crate::underlier::WithUnderlier for $name {
			type Underlier = $typ;

			fn to_underlier(self) -> Self::Underlier {
				::bytemuck::TransparentWrapper::peel(self)
			}

			fn to_underlier_ref(&self) -> &Self::Underlier {
				::bytemuck::TransparentWrapper::peel_ref(self)
			}

			fn to_underlier_ref_mut(&mut self) -> &mut Self::Underlier {
				::bytemuck::TransparentWrapper::peel_mut(self)
			}

			fn to_underliers_ref(val: &[Self]) -> &[Self::Underlier] {
				::bytemuck::TransparentWrapper::peel_slice(val)
			}

			fn to_underliers_ref_mut(val: &mut [Self]) -> &mut [Self::Underlier] {
				::bytemuck::TransparentWrapper::peel_slice_mut(val)
			}

			fn from_underlier(val: Self::Underlier) -> Self {
				::bytemuck::TransparentWrapper::wrap(val)
			}

			fn from_underlier_ref(val: &Self::Underlier) -> &Self {
				::bytemuck::TransparentWrapper::wrap_ref(val)
			}

			fn from_underlier_ref_mut(val: &mut Self::Underlier) -> &mut Self {
				::bytemuck::TransparentWrapper::wrap_mut(val)
			}

			fn from_underliers_ref(val: &[Self::Underlier]) -> &[Self] {
				::bytemuck::TransparentWrapper::wrap_slice(val)
			}

			fn from_underliers_ref_mut(val: &mut [Self::Underlier]) -> &mut [Self] {
				::bytemuck::TransparentWrapper::wrap_slice_mut(val)
			}
		}

		impl Neg for $name {
			type Output = Self;

			fn neg(self) -> Self::Output {
				self
			}
		}

		impl Add<Self> for $name {
			type Output = Self;

			#[allow(clippy::suspicious_arithmetic_impl)]
			fn add(self, rhs: Self) -> Self::Output {
				$name(self.0 ^ rhs.0)
			}
		}

		impl Add<&Self> for $name {
			type Output = Self;

			#[allow(clippy::suspicious_arithmetic_impl)]
			fn add(self, rhs: &Self) -> Self::Output {
				$name(self.0 ^ rhs.0)
			}
		}

		impl Sub<Self> for $name {
			type Output = Self;

			#[allow(clippy::suspicious_arithmetic_impl)]
			fn sub(self, rhs: Self) -> Self::Output {
				$name(self.0 ^ rhs.0)
			}
		}

		impl Sub<&Self> for $name {
			type Output = Self;

			#[allow(clippy::suspicious_arithmetic_impl)]
			fn sub(self, rhs: &Self) -> Self::Output {
				$name(self.0 ^ rhs.0)
			}
		}

		impl Mul<Self> for $name {
			type Output = Self;

			fn mul(self, rhs: Self) -> Self::Output {
				$crate::tracing::trace_multiplication!($name);

				TowerFieldArithmetic::multiply(self, rhs)
			}
		}

		impl Mul<&Self> for $name {
			type Output = Self;

			fn mul(self, rhs: &Self) -> Self::Output {
				self * *rhs
			}
		}

		impl AddAssign<Self> for $name {
			fn add_assign(&mut self, rhs: Self) {
				*self = *self + rhs;
			}
		}

		impl AddAssign<&Self> for $name {
			fn add_assign(&mut self, rhs: &Self) {
				*self = *self + *rhs;
			}
		}

		impl SubAssign<Self> for $name {
			fn sub_assign(&mut self, rhs: Self) {
				*self = *self - rhs;
			}
		}

		impl SubAssign<&Self> for $name {
			fn sub_assign(&mut self, rhs: &Self) {
				*self = *self - *rhs;
			}
		}

		impl MulAssign<Self> for $name {
			fn mul_assign(&mut self, rhs: Self) {
				*self = *self * rhs;
			}
		}

		impl MulAssign<&Self> for $name {
			fn mul_assign(&mut self, rhs: &Self) {
				*self = *self * rhs;
			}
		}

		impl Sum<Self> for $name {
			fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
				iter.fold(Self::ZERO, |acc, x| acc + x)
			}
		}

		impl<'a> Sum<&'a Self> for $name {
			fn sum<I: Iterator<Item=&'a Self>>(iter: I) -> Self {
				iter.fold(Self::ZERO, |acc, x| acc + x)
			}
		}

		impl Product<Self> for $name {
			fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
				iter.fold(Self::ONE, |acc, x| acc * x)
			}
		}

		impl<'a> Product<&'a Self> for $name {
			fn product<I: Iterator<Item=&'a Self>>(iter: I) -> Self {
				iter.fold(Self::ONE, |acc, x| acc * x)
			}
		}


		impl crate::arithmetic_traits::Square for $name {
			fn square(self) -> Self {
				TowerFieldArithmetic::square(self)
			}
		}

		impl Field for $name {
			const ZERO: Self = $name::new(<$typ as $crate::underlier::UnderlierWithBitOps>::ZERO);
			const ONE: Self = $name::new(<$typ as $crate::underlier::UnderlierWithBitOps>::ONE);
			const CHARACTERISTIC: usize = 2;

			fn double(&self) -> Self {
				Self::ZERO
			}
		}

		impl ::rand::distr::Distribution<$name> for ::rand::distr::StandardUniform {
			fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
				$name(rng.random())
			}
		}

		impl Display for $name {
			fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
				write!(f, "0x{repr:0>width$x}", repr=self.val(), width=Self::N_BITS.max(4) / 4)
			}
		}

		impl Debug for $name {
			fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
				let structure_name = std::any::type_name::<$name>().split("::").last().expect("exist");

				write!(f, "{}({})",structure_name, self)
			}
		}

		impl BinaryField for $name {
			const MULTIPLICATIVE_GENERATOR: $name = $name($gen);
		}

		impl From<$typ> for $name {
			fn from(val: $typ) -> Self {
				return Self(val)
			}
		}

		impl From<$name> for $typ {
			fn from(val: $name) -> Self {
				return val.0
			}
		}
	}
}

pub(crate) use binary_field;

macro_rules! binary_subfield_mul_packed_128b {
	($subfield_name:ident, $field_name:ident, $subfield_packed:ident) => {
		cfg_if::cfg_if! {
			// HACK: Carve-out for accelerated packed field arithmetic. This is temporary until the
			// portable packed128b implementation is refactored to not rely on BinaryField mul.
			if #[cfg(all(target_arch = "x86_64", target_feature = "gfni", target_feature = "sse2"))] {
				impl Mul<$subfield_name> for $field_name {
					type Output = Self;

					fn mul(self, rhs: $subfield_name) -> Self::Output {
						use bytemuck::must_cast;
						use crate::$subfield_packed;

						let a = must_cast::<_, $subfield_packed>(self);
						must_cast(a * rhs)
					}
				}
			} else {
				impl Mul<$subfield_name> for $field_name {
					type Output = Self;

					fn mul(self, rhs: $subfield_name) -> Self::Output {
						$crate::tracing::trace_multiplication!($field_name, $subfield_name);

						let (a, b) = self.into();
						(a * rhs, b * rhs).into()
					}
				}
			}
		}
	};
}

pub(crate) use binary_subfield_mul_packed_128b;

macro_rules! mul_by_binary_field_1b {
	($name:ident) => {
		impl Mul<BinaryField1b> for $name {
			type Output = Self;

			#[inline]
			#[allow(clippy::suspicious_arithmetic_impl)]
			fn mul(self, rhs: BinaryField1b) -> Self::Output {
				use $crate::underlier::{UnderlierWithBitOps, WithUnderlier};

				$crate::tracing::trace_multiplication!(BinaryField128b, BinaryField1b);

				Self(self.0 & <$name as WithUnderlier>::Underlier::fill_with_bit(u8::from(rhs.0)))
			}
		}
	};
}

pub(crate) use mul_by_binary_field_1b;

macro_rules! binary_tower_subfield_mul {
	// HACK: Special case when the subfield is GF(2)
	(BinaryField1b, $name:ident) => {
		mul_by_binary_field_1b!($name);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField8b, BinaryField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			BinaryField8b,
			BinaryField128b,
			PackedBinaryField16x8b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField16b, BinaryField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			BinaryField16b,
			BinaryField128b,
			PackedBinaryField8x16b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField32b, BinaryField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			BinaryField32b,
			BinaryField128b,
			PackedBinaryField4x32b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField64b, BinaryField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			BinaryField64b,
			BinaryField128b,
			PackedBinaryField2x64b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(AESTowerField8b, AESTowerField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			AESTowerField8b,
			AESTowerField128b,
			PackedAESBinaryField16x8b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField16b, AESTowerField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			AESTowerField16b,
			AESTowerField128b,
			PackedAESBinaryField8x16b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField32b, AESTowerField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			AESTowerField32b,
			AESTowerField128b,
			PackedAESBinaryField4x32b
		);
	};
	// HACK: Special case when the field is GF(2^128)
	(BinaryField64b, AESTowerField128b) => {
		$crate::binary_field::binary_subfield_mul_packed_128b!(
			AESTowerField64b,
			AESTowerField128b,
			PackedAESBinaryField2x64b
		);
	};
	($subfield_name:ident, $name:ident) => {
		impl Mul<$subfield_name> for $name {
			type Output = Self;

			fn mul(self, rhs: $subfield_name) -> Self::Output {
				$crate::tracing::trace_multiplication!($name, $subfield_name);

				let (a, b) = self.into();
				(a * rhs, b * rhs).into()
			}
		}
	};
}

pub(crate) use binary_tower_subfield_mul;

macro_rules! impl_field_extension {
	($subfield_name:ident($subfield_typ:ty) < @$log_degree:expr => $name:ident($typ:ty)) => {
		impl TryFrom<$name> for $subfield_name {
			type Error = ();

			#[inline]
			fn try_from(elem: $name) -> Result<Self, Self::Error> {
				use $crate::underlier::NumCast;

				if elem.0 >> $subfield_name::N_BITS
					== <$typ as $crate::underlier::UnderlierWithBitOps>::ZERO
				{
					Ok($subfield_name::new(<$subfield_typ>::num_cast_from(elem.val())))
				} else {
					Err(())
				}
			}
		}

		impl From<$subfield_name> for $name {
			#[inline]
			fn from(elem: $subfield_name) -> Self {
				$name::new(<$typ>::from(elem.val()))
			}
		}

		impl Add<$subfield_name> for $name {
			type Output = Self;

			#[inline]
			fn add(self, rhs: $subfield_name) -> Self::Output {
				self + Self::from(rhs)
			}
		}

		impl Sub<$subfield_name> for $name {
			type Output = Self;

			#[inline]
			fn sub(self, rhs: $subfield_name) -> Self::Output {
				self - Self::from(rhs)
			}
		}

		impl AddAssign<$subfield_name> for $name {
			#[inline]
			fn add_assign(&mut self, rhs: $subfield_name) {
				*self = *self + rhs;
			}
		}

		impl SubAssign<$subfield_name> for $name {
			#[inline]
			fn sub_assign(&mut self, rhs: $subfield_name) {
				*self = *self - rhs;
			}
		}

		impl MulAssign<$subfield_name> for $name {
			#[inline]
			fn mul_assign(&mut self, rhs: $subfield_name) {
				*self = *self * rhs;
			}
		}

		impl Add<$name> for $subfield_name {
			type Output = $name;

			#[inline]
			fn add(self, rhs: $name) -> Self::Output {
				rhs + self
			}
		}

		impl Sub<$name> for $subfield_name {
			type Output = $name;

			#[allow(clippy::suspicious_arithmetic_impl)]
			#[inline]
			fn sub(self, rhs: $name) -> Self::Output {
				rhs + self
			}
		}

		impl Mul<$name> for $subfield_name {
			type Output = $name;

			#[inline]
			fn mul(self, rhs: $name) -> Self::Output {
				rhs * self
			}
		}

		impl ExtensionField<$subfield_name> for $name {
			const LOG_DEGREE: usize = $log_degree;

			#[inline]
			fn basis_checked(i: usize) -> Result<Self, Error> {
				use $crate::underlier::UnderlierWithBitOps;

				if i >= 1 << $log_degree {
					return Err(Error::ExtensionDegreeMismatch);
				}
				Ok(Self::new(<$typ>::ONE << (i * $subfield_name::N_BITS)))
			}

			#[inline]
			fn from_bases_sparse(
				base_elems: impl IntoIterator<Item = $subfield_name>,
				log_stride: usize,
			) -> Result<Self, Error> {
				use $crate::underlier::UnderlierWithBitOps;

				debug_assert!($name::N_BITS.is_power_of_two());
				let shift_step = ($subfield_name::N_BITS << log_stride) & ($name::N_BITS - 1);
				let mut value = <$typ>::ZERO;
				let mut shift = 0;

				for elem in base_elems.into_iter() {
					if shift >= $name::N_BITS {
						return Err(Error::ExtensionDegreeMismatch);
					}
					value |= <$typ>::from(elem.val()) << shift;
					shift += shift_step;
				}

				Ok(Self::new(value))
			}

			#[inline]
			fn iter_bases(&self) -> impl Iterator<Item = $subfield_name> {
				use $crate::underlier::{WithUnderlier, IterationMethods, IterationStrategy};
				use binius_utils::iter::IterExtensions;

				IterationMethods::<<$subfield_name as WithUnderlier>::Underlier, Self::Underlier>::ref_iter(&self.0)
					.map_skippable($subfield_name::from)
			}

			#[inline]
			fn into_iter_bases(self) -> impl Iterator<Item = $subfield_name> {
				use $crate::underlier::{WithUnderlier, IterationMethods, IterationStrategy};
				use binius_utils::iter::IterExtensions;

				IterationMethods::<<$subfield_name as WithUnderlier>::Underlier, Self::Underlier>::value_iter(self.0)
					.map_skippable($subfield_name::from)
			}

			#[inline]
			unsafe fn get_base_unchecked(&self, i: usize) -> $subfield_name {
				use $crate::underlier::{WithUnderlier, UnderlierWithBitOps};
				unsafe {
					$subfield_name::from_underlier(self.to_underlier().get_subvalue(i))
				}
			}

			#[inline]
			fn square_transpose(values: &mut [Self]) -> Result<(), Error> {
				crate::transpose::square_transforms_extension_field::<$subfield_name, Self>(values)
					.map_err(|_| Error::ExtensionDegreeMismatch)
			}
		}
	};
}

pub(crate) use impl_field_extension;

/// Internal trait to implement multiply by primitive
/// for the specific tower,
pub(super) trait MulPrimitive: Sized {
	fn mul_primitive(self, iota: usize) -> Result<Self, Error>;
}

#[macro_export]
macro_rules! binary_tower {
	(BinaryField1b($subfield_typ:ty $(, $canonical_subfield:ident)?) < $name:ident($typ:ty $(, $canonical:ident)?) $(< $extfield_name:ident($extfield_typ:ty $(, $canonical_ext:ident)?))+) => {
		binary_tower!([BinaryField1b::TOWER_LEVEL]; BinaryField1b($subfield_typ $(, $canonical_subfield)?) < $name($typ $(, $canonical)?) $(< $extfield_name($extfield_typ $(, $canonical_ext)?))+);
	};
	($subfield_name:ident($subfield_typ:ty $(, $canonical_subfield:ident)?) < $name:ident($typ:ty $(, $canonical:ident)?) $(< $extfield_name:ident($extfield_typ:ty $(, $canonical_ext:ident)?))+) => {
		binary_tower!([BinaryField1b::TOWER_LEVEL, $subfield_name::TOWER_LEVEL]; $subfield_name($subfield_typ $(, $canonical_subfield)?) < $name($typ $(, $canonical)?) $(< $extfield_name($extfield_typ $(, $canonical_ext)?))+);
	};
	([$($valid_tower_levels:tt)*]; $subfield_name:ident($subfield_typ:ty $(, $canonical_subfield:ident)?) < $name:ident($typ:ty)) => {
		binary_tower!([$($valid_tower_levels)*]; $subfield_name($subfield_typ $(, $canonical_subfield)?) < $name($typ, $name));
	};
	([$($valid_tower_levels:tt)*]; $subfield_name:ident($subfield_typ:ty $(, $canonical_subfield:ident)?) < $name:ident($typ:ty, $canonical:ident)) => {
		impl From<$name> for ($subfield_name, $subfield_name) {
			#[inline]
			fn from(src: $name) -> ($subfield_name, $subfield_name) {
				use $crate::underlier::NumCast;

				let lo = <$subfield_typ>::num_cast_from(src.0);
				let hi = <$subfield_typ>::num_cast_from(src.0 >> $subfield_name::N_BITS);
				($subfield_name::new(lo), $subfield_name::new(hi))
			}
		}

		impl From<($subfield_name, $subfield_name)> for $name {
			#[inline]
			fn from((a, b): ($subfield_name, $subfield_name)) -> Self {
				$name(<$typ>::from(a.val()) | (<$typ>::from(b.val()) << $subfield_name::N_BITS))
			}
		}

		impl TowerField for $name {
			const TOWER_LEVEL: usize = { $subfield_name::TOWER_LEVEL + 1 };

			type Canonical = $canonical;

			fn min_tower_level(self) -> usize {
				let zero = <$typ as $crate::underlier::UnderlierWithBitOps>::ZERO;
				for level in [$($valid_tower_levels)*] {
					if self.0 >> (1 << level) == zero {
						return level;
					}
				}
				Self::TOWER_LEVEL
			}

			fn mul_primitive(self, iota: usize) -> Result<Self, Error> {
				<Self as $crate::binary_field::MulPrimitive>::mul_primitive(self, iota)
			}
		}

		impl $crate::TowerExtensionField for $name {
			type DirectSubfield = $subfield_name;
		}

		binary_tower!($subfield_name($subfield_typ) < @1 => $name($typ));
	};
	([$($valid_tower_levels:tt)*]; $subfield_name:ident($subfield_typ:ty $(, $canonical_subfield:ident)?) < $name:ident($typ:ty $(, $canonical:ident)?) $(< $extfield_name:ident($extfield_typ:ty $(, $canonical_ext:ident)?))+) => {
		binary_tower!([$($valid_tower_levels)*]; $subfield_name($subfield_typ $(, $canonical_subfield)?) < $name($typ $(, $canonical)?));
		binary_tower!([$($valid_tower_levels)*, $name::TOWER_LEVEL]; $name($typ $(, $canonical)?) $(< $extfield_name($extfield_typ $(, $canonical_ext)?))+);
		binary_tower!($subfield_name($subfield_typ) < @2 => $($extfield_name($extfield_typ))<+);
	};
	($subfield_name:ident($subfield_typ:ty) < @$log_degree:expr => $name:ident($typ:ty)) => {
		$crate::binary_field::impl_field_extension!($subfield_name($subfield_typ) < @$log_degree => $name($typ));
		$crate::binary_field::binary_tower_subfield_mul!($subfield_name, $name);
	};
	($subfield_name:ident($subfield_typ:ty) < @$log_degree:expr => $name:ident($typ:ty) $(< $extfield_name:ident($extfield_typ:ty))+) => {
		binary_tower!($subfield_name($subfield_typ) < @$log_degree => $name($typ));
		binary_tower!($subfield_name($subfield_typ) < @$log_degree+1 => $($extfield_name($extfield_typ))<+);
	};
}

binary_field!(pub BinaryField1b(U1), U1::new(0x1));
binary_field!(pub BinaryField2b(U2), U2::new(0x2));
binary_field!(pub BinaryField4b(U4), U4::new(0x5));
binary_field!(pub BinaryField8b(u8), 0x2D);
binary_field!(pub BinaryField16b(u16), 0xE2DE);
binary_field!(pub BinaryField32b(u32), 0x03E21CEA);
binary_field!(pub BinaryField64b(u64), 0x070F870DCD9C1D88);
binary_field!(pub BinaryField128b(u128), 0x2E895399AF449ACE499596F6E5FCCAFAu128);

unsafe impl Pod for BinaryField8b {}
unsafe impl Pod for BinaryField16b {}
unsafe impl Pod for BinaryField32b {}
unsafe impl Pod for BinaryField64b {}
unsafe impl Pod for BinaryField128b {}

binary_tower!(
	BinaryField1b(U1)
	< BinaryField2b(U2)
	< BinaryField4b(U4)
	< BinaryField8b(u8)
	< BinaryField16b(u16)
	< BinaryField32b(u32)
	< BinaryField64b(u64)
	< BinaryField128b(u128)
);

#[inline(always)]
pub fn is_canonical_tower<F: TowerField>() -> bool {
	TypeId::of::<F::Canonical>() == TypeId::of::<F>()
}

macro_rules! serialize_deserialize {
	($bin_type:ty) => {
		impl SerializeBytes for $bin_type {
			fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
				self.0.serialize(write_buf)
			}
		}

		impl DeserializeBytes for $bin_type {
			fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError> {
				Ok(Self(DeserializeBytes::deserialize(read_buf)?))
			}
		}
	};
}

serialize_deserialize!(BinaryField1b);
serialize_deserialize!(BinaryField2b);
serialize_deserialize!(BinaryField4b);
serialize_deserialize!(BinaryField8b);
serialize_deserialize!(BinaryField16b);
serialize_deserialize!(BinaryField32b);
serialize_deserialize!(BinaryField64b);
serialize_deserialize!(BinaryField128b);

impl BinaryField1b {
	/// Creates value without checking that it is within valid range (0 or 1)
	///
	/// # Safety
	/// Value should not exceed 1
	#[inline]
	pub unsafe fn new_unchecked(val: u8) -> Self {
		debug_assert!(val < 2);

		Self::new(U1::new_unchecked(val))
	}
}

impl From<u8> for BinaryField1b {
	#[inline]
	fn from(val: u8) -> Self {
		Self::new(U1::new(val))
	}
}

impl From<BinaryField1b> for u8 {
	#[inline]
	fn from(value: BinaryField1b) -> Self {
		value.val().into()
	}
}

impl From<bool> for BinaryField1b {
	#[inline]
	fn from(value: bool) -> Self {
		Self::from(U1::new_unchecked(value.into()))
	}
}

impl BinaryField2b {
	/// Creates value without checking that it is within valid range (0 to 3)
	///
	/// # Safety
	/// Value should not exceed 3
	#[inline]
	pub unsafe fn new_unchecked(val: u8) -> Self {
		debug_assert!(val < 4);

		Self::new(U2::new_unchecked(val))
	}
}

impl From<u8> for BinaryField2b {
	#[inline]
	fn from(val: u8) -> Self {
		Self::new(U2::new(val))
	}
}

impl From<BinaryField2b> for u8 {
	#[inline]
	fn from(value: BinaryField2b) -> Self {
		value.val().into()
	}
}

impl BinaryField4b {
	/// Creates value without checking that it is within valid range (0 to 15)
	///
	/// # Safety
	/// Value should not exceed 15
	#[inline]
	pub unsafe fn new_unchecked(val: u8) -> Self {
		debug_assert!(val < 16);

		Self::new(U4::new_unchecked(val))
	}
}

impl From<u8> for BinaryField4b {
	#[inline]
	fn from(val: u8) -> Self {
		Self::new(U4::new(val))
	}
}

impl From<BinaryField4b> for u8 {
	#[inline]
	fn from(value: BinaryField4b) -> Self {
		value.val().into()
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use binius_utils::bytes::BytesMut;
	use proptest::prelude::*;

	use super::{
		BinaryField1b as BF1, BinaryField2b as BF2, BinaryField4b as BF4, BinaryField8b as BF8,
		BinaryField16b as BF16, BinaryField64b as BF64, *,
	};

	#[test]
	fn test_gf2_add() {
		assert_eq!(BF1::from(0) + BF1::from(0), BF1::from(0));
		assert_eq!(BF1::from(0) + BF1::from(1), BF1::from(1));
		assert_eq!(BF1::from(1) + BF1::from(0), BF1::from(1));
		assert_eq!(BF1::from(1) + BF1::from(1), BF1::from(0));
	}

	#[test]
	fn test_gf2_sub() {
		assert_eq!(BF1::from(0) - BF1::from(0), BF1::from(0));
		assert_eq!(BF1::from(0) - BF1::from(1), BF1::from(1));
		assert_eq!(BF1::from(1) - BF1::from(0), BF1::from(1));
		assert_eq!(BF1::from(1) - BF1::from(1), BF1::from(0));
	}

	#[test]
	fn test_gf2_mul() {
		assert_eq!(BF1::from(0) * BF1::from(0), BF1::from(0));
		assert_eq!(BF1::from(0) * BF1::from(1), BF1::from(0));
		assert_eq!(BF1::from(1) * BF1::from(0), BF1::from(0));
		assert_eq!(BF1::from(1) * BF1::from(1), BF1::from(1));
	}

	#[test]
	fn test_bin2b_mul() {
		assert_eq!(BF2::from(0x1) * BF2::from(0x0), BF2::from(0x0));
		assert_eq!(BF2::from(0x1) * BF2::from(0x1), BF2::from(0x1));
		assert_eq!(BF2::from(0x0) * BF2::from(0x3), BF2::from(0x0));
		assert_eq!(BF2::from(0x1) * BF2::from(0x2), BF2::from(0x2));
		assert_eq!(BF2::from(0x0) * BF2::from(0x1), BF2::from(0x0));
		assert_eq!(BF2::from(0x0) * BF2::from(0x2), BF2::from(0x0));
		assert_eq!(BF2::from(0x1) * BF2::from(0x3), BF2::from(0x3));
		assert_eq!(BF2::from(0x3) * BF2::from(0x0), BF2::from(0x0));
		assert_eq!(BF2::from(0x2) * BF2::from(0x0), BF2::from(0x0));
		assert_eq!(BF2::from(0x2) * BF2::from(0x2), BF2::from(0x3));
	}

	#[test]
	fn test_bin4b_mul() {
		assert_eq!(BF4::from(0x0) * BF4::from(0x0), BF4::from(0x0));
		assert_eq!(BF4::from(0x9) * BF4::from(0x0), BF4::from(0x0));
		assert_eq!(BF4::from(0x9) * BF4::from(0x4), BF4::from(0xa));
		assert_eq!(BF4::from(0x6) * BF4::from(0x0), BF4::from(0x0));
		assert_eq!(BF4::from(0x6) * BF4::from(0x7), BF4::from(0xc));
		assert_eq!(BF4::from(0x2) * BF4::from(0x0), BF4::from(0x0));
		assert_eq!(BF4::from(0x2) * BF4::from(0xa), BF4::from(0xf));
		assert_eq!(BF4::from(0x1) * BF4::from(0x0), BF4::from(0x0));
		assert_eq!(BF4::from(0x1) * BF4::from(0x8), BF4::from(0x8));
		assert_eq!(BF4::from(0x9) * BF4::from(0xb), BF4::from(0x8));
	}

	#[test]
	fn test_bin8b_mul() {
		assert_eq!(BF8::new(0x00) * BF8::new(0x00), BF8::new(0x00));
		assert_eq!(BF8::new(0x1b) * BF8::new(0xa8), BF8::new(0x09));
		assert_eq!(BF8::new(0x00) * BF8::new(0x00), BF8::new(0x00));
		assert_eq!(BF8::new(0x76) * BF8::new(0x51), BF8::new(0x84));
		assert_eq!(BF8::new(0x00) * BF8::new(0x00), BF8::new(0x00));
		assert_eq!(BF8::new(0xe4) * BF8::new(0x8f), BF8::new(0x0e));
		assert_eq!(BF8::new(0x00) * BF8::new(0x00), BF8::new(0x00));
		assert_eq!(BF8::new(0x42) * BF8::new(0x66), BF8::new(0xea));
		assert_eq!(BF8::new(0x00) * BF8::new(0x00), BF8::new(0x00));
		assert_eq!(BF8::new(0x68) * BF8::new(0xd0), BF8::new(0xc5));
	}

	#[test]
	fn test_bin16b_mul() {
		assert_eq!(BF16::new(0x0000) * BF16::new(0x0000), BF16::new(0x0000));
		assert_eq!(BF16::new(0x48a8) * BF16::new(0xf8a4), BF16::new(0x3656));
		assert_eq!(BF16::new(0xf8a4) * BF16::new(0xf8a4), BF16::new(0xe7e6));
		assert_eq!(BF16::new(0xf8a4) * BF16::new(0xf8a4), BF16::new(0xe7e6));
		assert_eq!(BF16::new(0x448b) * BF16::new(0x0585), BF16::new(0x47d3));
		assert_eq!(BF16::new(0x0585) * BF16::new(0x0585), BF16::new(0x8057));
		assert_eq!(BF16::new(0x0001) * BF16::new(0x6a57), BF16::new(0x6a57));
		assert_eq!(BF16::new(0x0001) * BF16::new(0x0001), BF16::new(0x0001));
		assert_eq!(BF16::new(0xf62c) * BF16::new(0x0dbd), BF16::new(0xa9da));
		assert_eq!(BF16::new(0xf62c) * BF16::new(0xf62c), BF16::new(0x37bb));
	}

	#[test]
	fn test_bin64b_mul() {
		assert_eq!(
			BF64::new(0x0000000000000000) * BF64::new(0x0000000000000000),
			BF64::new(0x0000000000000000)
		);
		assert_eq!(
			BF64::new(0xc84d619110831cef) * BF64::new(0x000000000000a14f),
			BF64::new(0x3565086d6b9ef595)
		);
		assert_eq!(
			BF64::new(0xa14f580107030300) * BF64::new(0x000000000000f404),
			BF64::new(0x83e7239eb819a6ac)
		);
		assert_eq!(
			BF64::new(0xf404210706070403) * BF64::new(0x0000000000006b44),
			BF64::new(0x790541c54ffa2ede)
		);
		assert_eq!(
			BF64::new(0x6b44000404006b44) * BF64::new(0x0000000000000013),
			BF64::new(0x7018004c4c007018)
		);
		assert_eq!(
			BF64::new(0x6b44000404006b44) * BF64::new(0x0000000000000013),
			BF64::new(0x7018004c4c007018)
		);
		assert_eq!(
			BF64::new(0x6b44000404006b44) * BF64::new(0x6b44000404006b44),
			BF64::new(0xc59751e6f1769000)
		);
		assert_eq!(
			BF64::new(0x6b44000404006b44) * BF64::new(0x6b44000404006b44),
			BF64::new(0xc59751e6f1769000)
		);
		assert_eq!(
			BF64::new(0x00000000000000eb) * BF64::new(0x000000000000fba1),
			BF64::new(0x0000000000007689)
		);
		assert_eq!(
			BF64::new(0x00000000000000eb) * BF64::new(0x000000000000fba1),
			BF64::new(0x0000000000007689)
		);
	}

	pub(crate) fn is_binary_field_valid_generator<F: BinaryField>() -> bool {
		// Binary fields should contain a multiplicative subgroup of size 2^n - 1
		let mut order = if F::N_BITS == 128 {
			u128::MAX
		} else {
			(1 << F::N_BITS) - 1
		};

		// Naive factorization of group order - represented as a multiset of prime factors
		let mut factorization = Vec::new();

		let mut prime = 2;
		while prime * prime <= order {
			while order.is_multiple_of(prime) {
				order /= prime;
				factorization.push(prime);
			}

			prime += if prime > 2 { 2 } else { 1 };
		}

		if order > 1 {
			factorization.push(order);
		}

		// Iterate over all divisors (some may be tested several times if order is non-square-free)
		for mask in 0..(1 << factorization.len()) {
			let mut divisor = 1;

			for (bit_index, &prime) in factorization.iter().enumerate() {
				if (1 << bit_index) & mask != 0 {
					divisor *= prime;
				}
			}

			// Compute pow(generator, divisor) in log time
			divisor = divisor.reverse_bits();

			let mut pow_divisor = F::ONE;
			while divisor > 0 {
				pow_divisor *= pow_divisor;

				if divisor & 1 != 0 {
					pow_divisor *= F::MULTIPLICATIVE_GENERATOR;
				}

				divisor >>= 1;
			}

			// Generator invariant
			let is_root_of_unity = pow_divisor == F::ONE;
			let is_full_group = mask + 1 == 1 << factorization.len();

			if is_root_of_unity && !is_full_group || !is_root_of_unity && is_full_group {
				return false;
			}
		}

		true
	}

	#[test]
	fn test_multiplicative_generators() {
		assert!(is_binary_field_valid_generator::<BF1>());
		assert!(is_binary_field_valid_generator::<BF2>());
		assert!(is_binary_field_valid_generator::<BF4>());
		assert!(is_binary_field_valid_generator::<BF8>());
		assert!(is_binary_field_valid_generator::<BF16>());
		assert!(is_binary_field_valid_generator::<BinaryField32b>());
		assert!(is_binary_field_valid_generator::<BF64>());
		assert!(is_binary_field_valid_generator::<BinaryField128b>());
	}

	proptest! {
		#[test]
		fn test_add_sub_subfields_is_commutative(a_val in any::<u8>(), b_val in any::<u64>()) {
			let (a, b) = (BinaryField8b::new(a_val), BinaryField16b::new(b_val as u16));
			assert_eq!(a + b, b + a);
			assert_eq!(a - b, -(b - a));

			let (a, b) = (BinaryField8b::new(a_val), BinaryField64b::new(b_val));
			assert_eq!(a + b, b + a);
			assert_eq!(a - b, -(b - a));
		}

		#[test]
		fn test_mul_subfields_is_commutative(a_val in any::<u8>(), b_val in any::<u64>()) {
			let (a, b) = (BinaryField8b::new(a_val), BinaryField16b::new(b_val as u16));
			assert_eq!(a * b, b * a);

			let (a, b) = (BinaryField8b::new(a_val), BinaryField64b::new(b_val));
			assert_eq!(a * b, b * a);
		}

		#[test]
		fn test_square_equals_mul(a_val in any::<u64>()) {
			let a = BinaryField64b::new(a_val);
			assert_eq!(a.square(), a * a);
		}
	}

	#[test]
	fn test_field_degrees() {
		assert_eq!(BinaryField1b::N_BITS, 1);
		assert_eq!(BinaryField2b::N_BITS, 2);
		assert_eq!(BinaryField4b::N_BITS, 4);
		assert_eq!(<BinaryField4b as ExtensionField<BinaryField2b>>::DEGREE, 2);
		assert_eq!(BinaryField8b::N_BITS, 8);
		assert_eq!(BinaryField128b::N_BITS, 128);

		assert_eq!(<BinaryField8b as ExtensionField<BinaryField2b>>::DEGREE, 4);
		assert_eq!(<BinaryField128b as ExtensionField<BinaryField2b>>::DEGREE, 64);
		assert_eq!(<BinaryField128b as ExtensionField<BinaryField8b>>::DEGREE, 16);
	}

	#[test]
	fn test_field_formatting() {
		assert_eq!(format!("{}", BinaryField4b::from(3)), "0x3");
		assert_eq!(format!("{}", BinaryField8b::from(3)), "0x03");
		assert_eq!(format!("{}", BinaryField32b::from(5)), "0x00000005");
		assert_eq!(format!("{}", BinaryField64b::from(5)), "0x0000000000000005");
	}

	#[test]
	fn test_extension_from_bases() {
		let a = BinaryField8b(0x01);
		let b = BinaryField8b(0x02);
		let c = BinaryField8b(0x03);
		let d = BinaryField8b(0x04);
		assert_eq!(
			<BinaryField32b as ExtensionField<BinaryField8b>>::from_bases([]).unwrap(),
			BinaryField32b(0)
		);
		assert_eq!(BinaryField32b::from_bases([a]).unwrap(), BinaryField32b(0x00000001));
		assert_eq!(BinaryField32b::from_bases([a, b]).unwrap(), BinaryField32b(0x00000201));
		assert_eq!(BinaryField32b::from_bases([a, b, c]).unwrap(), BinaryField32b(0x00030201));
		assert_eq!(BinaryField32b::from_bases([a, b, c, d]).unwrap(), BinaryField32b(0x04030201));
		assert!(BinaryField32b::from_bases([a, b, c, d, d]).is_err());
	}

	#[test]
	fn test_inverse_on_zero() {
		assert!(BinaryField1b::ZERO.invert().is_none());
		assert!(BinaryField2b::ZERO.invert().is_none());
		assert!(BinaryField4b::ZERO.invert().is_none());
		assert!(BinaryField8b::ZERO.invert().is_none());
		assert!(BinaryField16b::ZERO.invert().is_none());
		assert!(BinaryField32b::ZERO.invert().is_none());
		assert!(BinaryField64b::ZERO.invert().is_none());
		assert!(BinaryField128b::ZERO.invert().is_none());
	}

	proptest! {
		#[test]
		fn test_inverse_8b(val in 1u8..) {
			let x = BinaryField8b(val);
			let x_inverse = x.invert().unwrap();
			assert_eq!(x * x_inverse, BinaryField8b::ONE);
		}

		#[test]
		fn test_inverse_32b(val in 1u32..) {
			let x = BinaryField32b(val);
			let x_inverse = x.invert().unwrap();
			assert_eq!(x * x_inverse, BinaryField32b::ONE);
		}

		#[test]
		fn test_inverse_128b(val in 1u128..) {
			let x = BinaryField128b(val);
			let x_inverse = x.invert().unwrap();
			assert_eq!(x * x_inverse, BinaryField128b::ONE);
		}
	}

	fn test_mul_primitive<F: TowerField>(val: F, iota: usize) {
		let result = val.mul_primitive(iota);
		let expected =
			<F as ExtensionField<BinaryField1b>>::basis_checked(1 << iota).map(|b| val * b);
		assert_eq!(result.is_ok(), expected.is_ok());
		if result.is_ok() {
			assert_eq!(result.unwrap(), expected.unwrap());
		} else {
			assert!(matches!(result.unwrap_err(), Error::ExtensionDegreeMismatch));
		}
	}

	proptest! {
		#[test]
		fn test_mul_primitive_1b(val in 0u8..2u8, iota in 0usize..8) {
			test_mul_primitive::<BinaryField1b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_2b(val in 0u8..4u8, iota in 0usize..8) {
			test_mul_primitive::<BinaryField2b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_4b(val in 0u8..16u8, iota in 0usize..8) {
			test_mul_primitive::<BinaryField4b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_8b(val in 0u8.., iota in 0usize..8) {
			test_mul_primitive::<BinaryField8b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_16b(val in 0u16.., iota in 0usize..8) {
			test_mul_primitive::<BinaryField16b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_32b(val in 0u32.., iota in 0usize..8) {
			test_mul_primitive::<BinaryField32b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_64b(val in 0u64.., iota in 0usize..8) {
			test_mul_primitive::<BinaryField64b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_128b(val in 0u128.., iota in 0usize..8) {
			test_mul_primitive::<BinaryField128b>(val.into(), iota)
		}
	}

	#[test]
	fn test_serialization() {
		let mut buffer = BytesMut::new();
		let b1 = BinaryField1b::from(0x1);
		let b8 = BinaryField8b::new(0x12);
		let b2 = BinaryField2b::from(0x2);
		let b16 = BinaryField16b::new(0x3456);
		let b32 = BinaryField32b::new(0x789ABCDE);
		let b4 = BinaryField4b::from(0xa);
		let b64 = BinaryField64b::new(0x13579BDF02468ACE);
		let b128 = BinaryField128b::new(0x147AD0369CF258BE8899AABBCCDDEEFF);

		b1.serialize(&mut buffer).unwrap();
		b8.serialize(&mut buffer).unwrap();
		b2.serialize(&mut buffer).unwrap();
		b16.serialize(&mut buffer).unwrap();
		b32.serialize(&mut buffer).unwrap();
		b4.serialize(&mut buffer).unwrap();
		b64.serialize(&mut buffer).unwrap();
		b128.serialize(&mut buffer).unwrap();

		let mut read_buffer = buffer.freeze();

		assert_eq!(BinaryField1b::deserialize(&mut read_buffer).unwrap(), b1);
		assert_eq!(BinaryField8b::deserialize(&mut read_buffer).unwrap(), b8);
		assert_eq!(BinaryField2b::deserialize(&mut read_buffer).unwrap(), b2);
		assert_eq!(BinaryField16b::deserialize(&mut read_buffer).unwrap(), b16);
		assert_eq!(BinaryField32b::deserialize(&mut read_buffer).unwrap(), b32);
		assert_eq!(BinaryField4b::deserialize(&mut read_buffer).unwrap(), b4);
		assert_eq!(BinaryField64b::deserialize(&mut read_buffer).unwrap(), b64);
		assert_eq!(BinaryField128b::deserialize(&mut read_buffer).unwrap(), b128);
	}

	#[test]
	fn test_gf2_new_unchecked() {
		for i in 0..2 {
			assert_eq!(unsafe { BF1::new_unchecked(i) }, BF1::from(i));
		}
		// Assert a panic for higher values
		let result = std::panic::catch_unwind(|| unsafe { BF1::new_unchecked(2) });
		assert!(result.is_err(), "Expected a panic for value > 1, but no panic occurred");
	}

	#[test]
	fn test_bin2b_new_unchecked() {
		for i in 0..4 {
			assert_eq!(unsafe { BF2::new_unchecked(i) }, BF2::from(i));
		}
		// Assert a panic for higher values
		let result = std::panic::catch_unwind(|| unsafe { BF2::new_unchecked(4) });
		assert!(result.is_err(), "Expected a panic for value > 3, but no panic occurred");
	}

	#[test]
	fn test_bin4b_new_unchecked() {
		for i in 0..16 {
			assert_eq!(unsafe { BF4::new_unchecked(i) }, BF4::from(i));
		}
		// Assert a panic for higher values
		let result = std::panic::catch_unwind(|| unsafe { BF4::new_unchecked(16) });
		assert!(result.is_err(), "Expected a panic for value > 15, but no panic occurred");
	}
}

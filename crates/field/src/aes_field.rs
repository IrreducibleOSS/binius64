// Copyright 2024-2025 Irreducible Inc.

use std::{
	any::TypeId,
	fmt::{Debug, Display, Formatter},
	iter::{Product, Sum},
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use binius_utils::{
	DeserializeBytes, SerializationError, SerializationMode, SerializeBytes,
	bytes::{Buf, BufMut},
};
use bytemuck::{Pod, Zeroable};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::{
	BinaryField8b, Error, PackedExtension, PackedSubfield,
	arithmetic_traits::InvertOrZero,
	binary_field::{BinaryField, BinaryField1b, binary_field, impl_field_extension},
	binary_field_arithmetic::TowerFieldArithmetic,
	mul_by_binary_field_1b,
};
use crate::{
	BinaryField16b, BinaryField32b, BinaryField64b, BinaryField128b, ExtensionField, Field,
	TowerField,
	as_packed_field::AsPackedField,
	binary_field_arithmetic::{impl_arithmetic_using_packed, impl_mul_primitive},
	binary_tower,
	linear_transformation::{
		FieldLinearTransformation, PackedTransformationFactory, Transformation,
	},
	packed::PackedField,
	underlier::U1,
};

// These fields represent a tower based on AES GF(2^8) field (GF(256)/x^8+x^4+x^3+x+1)
// that is isomorphically included into binary tower, i.e.:
//  - AESTowerField16b is GF(2^16) / (x^2 + x * x_2 + 1) where `x_2` is 0x10 from
// BinaryField8b isomorphically projected to AESTowerField8b.
//  - AESTowerField32b is GF(2^32) / (x^2 + x * x_3 + 1), where `x_3` is 0x1000 from
//    AESTowerField16b.
//  ...
binary_field!(pub AESTowerField8b(u8), 0xD0);
binary_field!(pub AESTowerField16b(u16), 0x4745);
binary_field!(pub AESTowerField32b(u32), 0xBD478FAB);
binary_field!(pub AESTowerField64b(u64), 0x0DE1555D2BD78EB4);
binary_field!(pub AESTowerField128b(u128), 0x6DB54066349EDB96C33A87244A742678);

unsafe impl Pod for AESTowerField8b {}
unsafe impl Pod for AESTowerField16b {}
unsafe impl Pod for AESTowerField32b {}
unsafe impl Pod for AESTowerField64b {}
unsafe impl Pod for AESTowerField128b {}

binary_tower!(
	AESTowerField8b(u8, BinaryField8b)
	< AESTowerField16b(u16, BinaryField16b)
	< AESTowerField32b(u32, BinaryField32b)
	< AESTowerField64b(u64, BinaryField64b)
	< AESTowerField128b(u128, BinaryField128b)
);

impl_field_extension!(BinaryField1b(U1) < @3 => AESTowerField8b(u8));
impl_field_extension!(BinaryField1b(U1) < @4 => AESTowerField16b(u16));
impl_field_extension!(BinaryField1b(U1) < @5 => AESTowerField32b(u32));
impl_field_extension!(BinaryField1b(U1) < @6 => AESTowerField64b(u64));
impl_field_extension!(BinaryField1b(U1) < @7 => AESTowerField128b(u128));

mul_by_binary_field_1b!(AESTowerField8b);
mul_by_binary_field_1b!(AESTowerField16b);
mul_by_binary_field_1b!(AESTowerField32b);
mul_by_binary_field_1b!(AESTowerField64b);
mul_by_binary_field_1b!(AESTowerField128b);

impl_arithmetic_using_packed!(AESTowerField8b);
impl_arithmetic_using_packed!(AESTowerField16b);
impl_arithmetic_using_packed!(AESTowerField32b);
impl_arithmetic_using_packed!(AESTowerField64b);
impl_arithmetic_using_packed!(AESTowerField128b);

impl TowerField for AESTowerField8b {
	type Canonical = BinaryField8b;

	fn min_tower_level(self) -> usize {
		match self {
			Self::ZERO | Self::ONE => 0,
			_ => 3,
		}
	}

	fn mul_primitive(self, iota: usize) -> Result<Self, Error> {
		match iota {
			0..=1 => Ok(self * ISOMORPHIC_ALPHAS[iota]),
			2 => Ok(self.multiply_alpha()),
			_ => Err(Error::ExtensionDegreeMismatch),
		}
	}
}

/// Returns true if `F`` is AES tower field.
#[inline(always)]
pub fn is_aes_tower<F: TowerField>() -> bool {
	TypeId::of::<F>() == TypeId::of::<F>()
		|| TypeId::of::<F>() == TypeId::of::<AESTowerField16b>()
		|| TypeId::of::<F>() == TypeId::of::<AESTowerField32b>()
		|| TypeId::of::<F>() == TypeId::of::<AESTowerField64b>()
		|| TypeId::of::<F>() == TypeId::of::<AESTowerField128b>()
}

pub const AES_TO_BINARY_LINEAR_TRANSFORMATION: FieldLinearTransformation<BinaryField8b> =
	FieldLinearTransformation::new_const(&[
		BinaryField8b(0x01),
		BinaryField8b(0x3c),
		BinaryField8b(0x8c),
		BinaryField8b(0x8a),
		BinaryField8b(0x59),
		BinaryField8b(0x7a),
		BinaryField8b(0x53),
		BinaryField8b(0x27),
	]);

impl From<AESTowerField8b> for BinaryField8b {
	fn from(value: AESTowerField8b) -> Self {
		AES_TO_BINARY_LINEAR_TRANSFORMATION.transform(&value)
	}
}

pub const BINARY_TO_AES_LINEAR_TRANSFORMATION: FieldLinearTransformation<AESTowerField8b> =
	FieldLinearTransformation::new_const(&[
		AESTowerField8b(0x01),
		AESTowerField8b(0xbc),
		AESTowerField8b(0xb0),
		AESTowerField8b(0xec),
		AESTowerField8b(0xd3),
		AESTowerField8b(0x8d),
		AESTowerField8b(0x2e),
		AESTowerField8b(0x58),
	]);

impl From<BinaryField8b> for AESTowerField8b {
	fn from(value: BinaryField8b) -> Self {
		BINARY_TO_AES_LINEAR_TRANSFORMATION.transform(&value)
	}
}

/// A 3- step transformation :
/// 1. Cast to base b-bit packed field
/// 2. Apply linear transformation between aes and binary b8 tower fields
/// 3. Cast back to the target field
pub struct SubfieldTransformer<IF, OF, T> {
	inner_transform: T,
	_ip_pd: PhantomData<IF>,
	_op_pd: PhantomData<OF>,
}

impl<IF, OF, T> SubfieldTransformer<IF, OF, T> {
	const fn new(inner_transform: T) -> Self {
		Self {
			inner_transform,
			_ip_pd: PhantomData,
			_op_pd: PhantomData,
		}
	}
}

impl<IF, OF, IEP, OEP, T> Transformation<IEP, OEP> for SubfieldTransformer<IF, OF, T>
where
	IF: Field,
	OF: Field,
	IEP: PackedExtension<IF>,
	OEP: PackedExtension<OF>,
	T: Transformation<PackedSubfield<IEP, IF>, PackedSubfield<OEP, OF>>,
{
	fn transform(&self, input: &IEP) -> OEP {
		OEP::cast_ext(self.inner_transform.transform(IEP::cast_base_ref(input)))
	}
}

pub type AesToBinaryTransformation<IP, OP> = SubfieldTransformer<
	AESTowerField8b,
	BinaryField8b,
	<PackedSubfield<IP, AESTowerField8b> as PackedTransformationFactory<
		PackedSubfield<OP, BinaryField8b>,
	>>::PackedTransformation<&'static [BinaryField8b]>,
>;
pub type BinaryToAesTransformation<IP, OP> = SubfieldTransformer<
	BinaryField8b,
	AESTowerField8b,
	<PackedSubfield<IP, BinaryField8b> as PackedTransformationFactory<
		PackedSubfield<OP, AESTowerField8b>,
	>>::PackedTransformation<&'static [AESTowerField8b]>,
>;

/// Creates transformation object from AES tower to binary tower for packed field.
/// Note that creation of this object is not cheap, so it is better to create it once and reuse.
pub fn make_aes_to_binary_packed_transformer<IP, OP>() -> AesToBinaryTransformation<IP, OP>
where
	IP: PackedExtension<AESTowerField8b>,
	OP: PackedExtension<BinaryField8b>,
	PackedSubfield<IP, AESTowerField8b>:
		PackedTransformationFactory<PackedSubfield<OP, BinaryField8b>>,
{
	SubfieldTransformer::<AESTowerField8b, BinaryField8b, _>::new(PackedSubfield::<
		IP,
		AESTowerField8b,
	>::make_packed_transformation(
		AES_TO_BINARY_LINEAR_TRANSFORMATION,
	))
}

/// Creates transformation object from AES tower to binary tower for packed field.
/// Note that creation of this object is not cheap, so it is better to create it once and reuse.
pub fn make_binary_to_aes_packed_transformer<IP, OP>() -> BinaryToAesTransformation<IP, OP>
where
	IP: PackedExtension<BinaryField8b>,
	OP: PackedExtension<AESTowerField8b>,
	PackedSubfield<IP, BinaryField8b>:
		PackedTransformationFactory<PackedSubfield<OP, AESTowerField8b>>,
{
	SubfieldTransformer::<BinaryField8b, AESTowerField8b, _>::new(
		PackedSubfield::<IP, BinaryField8b>::make_packed_transformation(
			BINARY_TO_AES_LINEAR_TRANSFORMATION,
		),
	)
}

/// Values isomorphic to 0x02, 0x04 and 0x10 in BinaryField8b
const ISOMORPHIC_ALPHAS: [AESTowerField8b; 3] = [
	AESTowerField8b(0xBC),
	AESTowerField8b(0xB0),
	AESTowerField8b(0xD3),
];

// MulPrimitive implementation for AES tower
impl_mul_primitive!(AESTowerField16b,
	mul_by 0 => ISOMORPHIC_ALPHAS[0],
	mul_by 1 => ISOMORPHIC_ALPHAS[1],
	repack 2 => AESTowerField8b,
	repack 3 => AESTowerField16b,
);
impl_mul_primitive!(AESTowerField32b,
	mul_by 0 => ISOMORPHIC_ALPHAS[0],
	mul_by 1 => ISOMORPHIC_ALPHAS[1],
	repack 2 => AESTowerField8b,
	repack 3 => AESTowerField16b,
	repack 4 => AESTowerField32b,
);
impl_mul_primitive!(AESTowerField64b,
	mul_by 0 => ISOMORPHIC_ALPHAS[0],
	mul_by 1 => ISOMORPHIC_ALPHAS[1],
	repack 2 => AESTowerField8b,
	repack 3 => AESTowerField16b,
	repack 4 => AESTowerField32b,
	repack 5 => AESTowerField64b,
);
impl_mul_primitive!(AESTowerField128b,
	mul_by 0 => ISOMORPHIC_ALPHAS[0],
	mul_by 1 => ISOMORPHIC_ALPHAS[1],
	repack 2 => AESTowerField8b,
	repack 3 => AESTowerField16b,
	repack 4 => AESTowerField32b,
	repack 5 => AESTowerField64b,
	repack 6 => AESTowerField128b,
);

/// We use this function to define isomorphisms between AES and binary tower fields.
/// Repack field as 8b packed field and apply isomorphism for each 8b element
fn convert_as_packed_8b<F1, F2, Scalar1, Scalar2>(val: F1) -> F2
where
	Scalar1: Field,
	Scalar2: Field + From<Scalar1>,
	F1: AsPackedField<Scalar1>,
	F2: AsPackedField<Scalar2>,
{
	assert_eq!(F1::Packed::WIDTH, F2::Packed::WIDTH);

	let val_repacked = val.to_packed();
	let converted_repacked = F2::Packed::from_fn(|i| val_repacked.get(i).into());

	F2::from_packed(converted_repacked)
}

macro_rules! impl_tower_field_conversion {
	($aes_field:ty, $binary_field:ty) => {
		impl From<$aes_field> for $binary_field {
			fn from(value: $aes_field) -> Self {
				convert_as_packed_8b::<_, _, AESTowerField8b, BinaryField8b>(value)
			}
		}

		impl From<$binary_field> for $aes_field {
			fn from(value: $binary_field) -> Self {
				convert_as_packed_8b::<_, _, BinaryField8b, AESTowerField8b>(value)
			}
		}
	};
}

impl_tower_field_conversion!(AESTowerField16b, BinaryField16b);
impl_tower_field_conversion!(AESTowerField32b, BinaryField32b);
impl_tower_field_conversion!(AESTowerField64b, BinaryField64b);
impl_tower_field_conversion!(AESTowerField128b, BinaryField128b);

macro_rules! serialize_deserialize_non_canonical {
	($field:ident, canonical=$canonical:ident) => {
		impl SerializeBytes for $field {
			fn serialize(
				&self,
				write_buf: impl BufMut,
				mode: SerializationMode,
			) -> Result<(), SerializationError> {
				match mode {
					SerializationMode::Native => self.0.serialize(write_buf, mode),
					SerializationMode::CanonicalTower => {
						$canonical::from(*self).serialize(write_buf, mode)
					}
				}
			}
		}

		impl DeserializeBytes for $field {
			fn deserialize(
				read_buf: impl Buf,
				mode: SerializationMode,
			) -> Result<Self, SerializationError>
			where
				Self: Sized,
			{
				match mode {
					SerializationMode::Native => {
						Ok(Self(DeserializeBytes::deserialize(read_buf, mode)?))
					}
					SerializationMode::CanonicalTower => {
						Ok(Self::from($canonical::deserialize(read_buf, mode)?))
					}
				}
			}
		}
	};
}

serialize_deserialize_non_canonical!(AESTowerField8b, canonical = BinaryField8b);
serialize_deserialize_non_canonical!(AESTowerField16b, canonical = BinaryField16b);
serialize_deserialize_non_canonical!(AESTowerField32b, canonical = BinaryField32b);
serialize_deserialize_non_canonical!(AESTowerField64b, canonical = BinaryField64b);
serialize_deserialize_non_canonical!(AESTowerField128b, canonical = BinaryField128b);

#[cfg(test)]
mod tests {
	use binius_utils::{SerializationMode, SerializeBytes, bytes::BytesMut};
	use proptest::{arbitrary::any, proptest};

	use super::*;
	use crate::{
		PackedAESBinaryField4x32b, PackedAESBinaryField8x32b, PackedAESBinaryField16x32b,
		PackedBinaryField4x32b, PackedBinaryField8x32b, PackedBinaryField16x32b,
		binary_field::tests::is_binary_field_valid_generator, underlier::WithUnderlier,
	};

	fn check_square(f: impl Field) {
		assert_eq!(f.square(), f * f);
	}

	proptest! {
		#[test]
		fn test_square_8(a in any::<u8>()) {
			check_square(AESTowerField8b::from(a))
		}

		#[test]
		fn test_square_16(a in any::<u16>()) {
			check_square(AESTowerField16b::from(a))
		}

		#[test]
		fn test_square_32(a in any::<u32>()) {
			check_square(AESTowerField32b::from(a))
		}

		#[test]
		fn test_square_64(a in any::<u64>()) {
			check_square(AESTowerField64b::from(a))
		}

		#[test]
		fn test_square_128(a in any::<u128>()) {
			check_square(AESTowerField128b::from(a))
		}
	}

	fn check_invert(f: impl Field) {
		let inversed = f.invert();
		if f.is_zero() {
			assert!(inversed.is_none());
		} else {
			assert_eq!(inversed.unwrap() * f, Field::ONE);
		}
	}

	fn check_isomorphism_preserves_ops<F1: Field, F2: Field + From<F1>>(a: F1, b: F1) {
		assert_eq!(F2::from(a * b), F2::from(a) * F2::from(b));
		assert_eq!(F2::from(a + b), F2::from(a) + F2::from(b));
	}

	proptest! {
		#[test]
		fn test_invert_8(a in any::<u8>()) {
			check_invert(AESTowerField8b::from(a))
		}

		#[test]
		fn test_invert_16(a in any::<u16>()) {
			check_invert(AESTowerField16b::from(a))
		}

		#[test]
		fn test_invert_32(a in any::<u32>()) {
			check_invert(AESTowerField32b::from(a))
		}

		#[test]
		fn test_invert_64(a in any::<u64>()) {
			check_invert(AESTowerField64b::from(a))
		}

		#[test]
		fn test_invert_128(a in any::<u128>()) {
			check_invert(AESTowerField128b::from(a))
		}

		#[test]
		fn test_isomorphism_to_binary_tower8b_roundtrip(a in any::<u8>()) {
			let a_val = AESTowerField8b(a);
			let projected = BinaryField8b::from(a_val);
			let restored = AESTowerField8b::from(projected);
			assert_eq!(a_val, restored);
		}

		#[test]
		fn test_isomorphism_8b(a in any::<u8>(), b in any::<u8>()) {
			check_isomorphism_preserves_ops::<AESTowerField8b, BinaryField8b>(a.into(), b.into());
			check_isomorphism_preserves_ops::<BinaryField8b, AESTowerField8b>(a.into(), b.into());
		}

		#[test]
		fn test_isomorphism_16b(a in any::<u16>(), b in any::<u16>()) {
			check_isomorphism_preserves_ops::<AESTowerField16b, BinaryField16b>(a.into(), b.into());
			check_isomorphism_preserves_ops::<BinaryField16b, AESTowerField16b>(a.into(), b.into());
		}

		#[test]
		fn test_isomorphism_32b(a in any::<u32>(), b in any::<u32>()) {
			check_isomorphism_preserves_ops::<AESTowerField32b, BinaryField32b>(a.into(), b.into());
			check_isomorphism_preserves_ops::<BinaryField32b, AESTowerField32b>(a.into(), b.into());
		}

		#[test]
		fn test_isomorphism_64b(a in any::<u64>(), b in any::<u64>()) {
			check_isomorphism_preserves_ops::<AESTowerField64b, BinaryField64b>(a.into(), b.into());
			check_isomorphism_preserves_ops::<BinaryField64b, AESTowerField64b>(a.into(), b.into());
		}

		#[test]
		fn test_isomorphism_128b(a in any::<u128>(), b in any::<u128>()) {
			check_isomorphism_preserves_ops::<AESTowerField128b, BinaryField128b>(a.into(), b.into());
			check_isomorphism_preserves_ops::<BinaryField128b, AESTowerField128b>(a.into(), b.into());
		}
	}

	fn check_mul_by_one<F: Field>(f: F) {
		assert_eq!(F::ONE * f, f);
		assert_eq!(f * F::ONE, f);
	}

	fn check_commutative<F: Field>(f_1: F, f_2: F) {
		assert_eq!(f_1 * f_2, f_2 * f_1);
	}

	fn check_associativity_and_lineraity<F: Field>(f_1: F, f_2: F, f_3: F) {
		assert_eq!(f_1 * (f_2 * f_3), (f_1 * f_2) * f_3);
		assert_eq!(f_1 * (f_2 + f_3), f_1 * f_2 + f_1 * f_3);
	}

	fn check_mul<F: Field>(f_1: F, f_2: F, f_3: F) {
		check_mul_by_one(f_1);
		check_mul_by_one(f_2);
		check_mul_by_one(f_3);

		check_commutative(f_1, f_2);
		check_commutative(f_1, f_3);
		check_commutative(f_2, f_3);

		check_associativity_and_lineraity(f_1, f_2, f_3);
		check_associativity_and_lineraity(f_1, f_3, f_2);
		check_associativity_and_lineraity(f_2, f_1, f_3);
		check_associativity_and_lineraity(f_2, f_3, f_1);
		check_associativity_and_lineraity(f_3, f_1, f_2);
		check_associativity_and_lineraity(f_3, f_2, f_1);
	}

	proptest! {
		#[test]
		fn test_mul_8(a in any::<u8>(), b in any::<u8>(), c in any::<u8>()) {
			check_mul(AESTowerField8b::from(a), AESTowerField8b::from(b), AESTowerField8b::from(c))
		}

		#[test]
		fn test_mul_16(a in any::<u16>(), b in any::<u16>(), c in any::<u16>()) {
			check_mul(AESTowerField16b::from(a), AESTowerField16b::from(b), AESTowerField16b::from(c))
		}

		#[test]
		fn test_mul_32(a in any::<u32>(), b in any::<u32>(), c in any::<u32>()) {
			check_mul(AESTowerField32b::from(a), AESTowerField32b::from(b), AESTowerField32b::from(c))
		}

		#[test]
		fn test_mul_64(a in any::<u64>(), b in any::<u64>(), c in any::<u64>()) {
			check_mul(AESTowerField64b::from(a), AESTowerField64b::from(b), AESTowerField64b::from(c))
		}

		#[test]
		fn test_mul_128(a in any::<u128>(), b in any::<u128>(), c in any::<u128>()) {
			check_mul(AESTowerField128b::from(a), AESTowerField128b::from(b), AESTowerField128b::from(c))
		}

		#[test]
		fn test_conversion_roundtrip(a in any::<u8>()) {
			let a_val = AESTowerField8b(a);
			let converted = BinaryField8b::from(a_val);
			assert_eq!(a_val, AESTowerField8b::from(converted));
		}
	}

	#[test]
	fn test_multiplicative_generators() {
		assert!(is_binary_field_valid_generator::<AESTowerField8b>());
		assert!(is_binary_field_valid_generator::<AESTowerField16b>());
		assert!(is_binary_field_valid_generator::<AESTowerField32b>());
		assert!(is_binary_field_valid_generator::<AESTowerField64b>());
		assert!(is_binary_field_valid_generator::<AESTowerField128b>());
	}

	fn test_mul_primitive<F: TowerField + WithUnderlier<Underlier: From<u8>>>(val: F, iota: usize) {
		let result = val.mul_primitive(iota);
		let expected = match iota {
			0..=2 => {
				Ok(val
					* F::from_underlier(F::Underlier::from(ISOMORPHIC_ALPHAS[iota].to_underlier())))
			}
			_ => <F as ExtensionField<BinaryField1b>>::basis_checked(1 << iota).map(|b| val * b),
		};
		assert_eq!(result.is_ok(), expected.is_ok());
		if result.is_ok() {
			assert_eq!(result.unwrap(), expected.unwrap());
		} else {
			assert!(matches!(result.unwrap_err(), Error::ExtensionDegreeMismatch));
		}
	}

	proptest! {
		#[test]
		fn test_mul_primitive_8b(val in 0u8.., iota in 3usize..8) {
			test_mul_primitive::<AESTowerField8b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_16b(val in 0u16.., iota in 3usize..8) {
			test_mul_primitive::<AESTowerField16b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_32b(val in 0u32.., iota in 3usize..8) {
			test_mul_primitive::<AESTowerField32b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_64b(val in 0u64.., iota in 3usize..8) {
			test_mul_primitive::<AESTowerField64b>(val.into(), iota)
		}

		#[test]
		fn test_mul_primitive_128b(val in 0u128.., iota in 3usize..8) {
			test_mul_primitive::<AESTowerField128b>(val.into(), iota)
		}
	}

	fn convert_pairwise<IP, OP>(val: IP) -> OP
	where
		IP: PackedField + WithUnderlier,
		OP: PackedField<Scalar: From<IP::Scalar>> + WithUnderlier<Underlier = IP::Underlier>,
	{
		OP::from_fn(|i| val.get(i).into())
	}

	proptest! {
		#[test]
		fn test_aes_to_binary_packed_transform_128(val in 0u128..) {
			let transform = make_aes_to_binary_packed_transformer::<PackedAESBinaryField4x32b, PackedBinaryField4x32b>();
			let input = PackedAESBinaryField4x32b::from(val);
			let result: PackedBinaryField4x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}

		#[test]
		fn test_binary_to_aes_packed_transform_128(val in 0u128..) {
			let transform = make_binary_to_aes_packed_transformer::<PackedBinaryField4x32b, PackedAESBinaryField4x32b>();
			let input = PackedBinaryField4x32b::from(val);
			let result: PackedAESBinaryField4x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}

		#[test]
		fn test_aes_to_binary_packed_transform_256(val in any::<[u128; 2]>()) {
			let transform = make_aes_to_binary_packed_transformer::<PackedAESBinaryField8x32b, PackedBinaryField8x32b>();
			let input = PackedAESBinaryField8x32b::from(val);
			let result: PackedBinaryField8x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}

		#[test]
		fn test_binary_to_aes_packed_transform_256(val in any::<[u128; 2]>()) {
			let transform = make_binary_to_aes_packed_transformer::<PackedBinaryField8x32b, PackedAESBinaryField8x32b>();
			let input = PackedBinaryField8x32b::from(val);
			let result: PackedAESBinaryField8x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}

		#[test]
		fn test_aes_to_binary_packed_transform_512(val in any::<[u128; 4]>()) {
			let transform = make_aes_to_binary_packed_transformer::<PackedAESBinaryField16x32b, PackedBinaryField16x32b>();
			let input = PackedAESBinaryField16x32b::from_underlier(val.into());
			let result: PackedBinaryField16x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}

		#[test]
		fn test_binary_to_aes_packed_transform_512(val in any::<[u128; 4]>()) {
			let transform = make_binary_to_aes_packed_transformer::<PackedBinaryField16x32b, PackedAESBinaryField16x32b>();
			let input = PackedBinaryField16x32b::from_underlier(val.into());
			let result: PackedAESBinaryField16x32b = transform.transform(&input);
			assert_eq!(result, convert_pairwise(input));
		}
	}

	#[test]
	fn test_canonical_serialization() {
		let mut buffer = BytesMut::new();
		let mut rng = rand::rng();
		let aes8 = <AESTowerField8b as Field>::random(&mut rng);
		let aes16 = <AESTowerField16b as Field>::random(&mut rng);
		let aes32 = <AESTowerField32b as Field>::random(&mut rng);
		let aes64 = <AESTowerField64b as Field>::random(&mut rng);
		let aes128 = <AESTowerField128b as Field>::random(&mut rng);

		let mode = SerializationMode::CanonicalTower;

		SerializeBytes::serialize(&aes8, &mut buffer, mode).unwrap();
		SerializeBytes::serialize(&aes16, &mut buffer, mode).unwrap();
		SerializeBytes::serialize(&aes32, &mut buffer, mode).unwrap();
		SerializeBytes::serialize(&aes64, &mut buffer, mode).unwrap();
		SerializeBytes::serialize(&aes128, &mut buffer, mode).unwrap();

		SerializeBytes::serialize(&aes128, &mut buffer, mode).unwrap();

		let mut read_buffer = buffer.freeze();

		assert_eq!(AESTowerField8b::deserialize(&mut read_buffer, mode).unwrap(), aes8);
		assert_eq!(AESTowerField16b::deserialize(&mut read_buffer, mode).unwrap(), aes16);
		assert_eq!(AESTowerField32b::deserialize(&mut read_buffer, mode).unwrap(), aes32);
		assert_eq!(AESTowerField64b::deserialize(&mut read_buffer, mode).unwrap(), aes64);
		assert_eq!(AESTowerField128b::deserialize(&mut read_buffer, mode).unwrap(), aes128);

		assert_eq!(BinaryField128b::deserialize(&mut read_buffer, mode).unwrap(), aes128.into())
	}
}

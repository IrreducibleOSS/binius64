// Copyright 2024-2025 Irreducible Inc.

use std::{
	any::TypeId,
	fmt::{Debug, Display, Formatter},
	iter::{Product, Sum},
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use binius_utils::{
	DeserializeBytes, SerializationError, SerializeBytes,
	bytes::{Buf, BufMut},
};
use bytemuck::{Pod, Zeroable};

use super::{
	BinaryField8b, Error, PackedExtension, PackedSubfield,
	arithmetic_traits::InvertOrZero,
	binary_field::{BinaryField, BinaryField1b, binary_field, impl_field_extension},
	binary_field_arithmetic::TowerFieldArithmetic,
	mul_by_binary_field_1b,
};
use crate::{
	ExtensionField, Field, TowerField,
	binary_field_arithmetic::impl_arithmetic_using_packed,
	linear_transformation::{
		FieldLinearTransformation, PackedTransformationFactory, Transformation,
	},
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

unsafe impl Pod for AESTowerField8b {}

impl_field_extension!(BinaryField1b(U1) < @3 => AESTowerField8b(u8));

mul_by_binary_field_1b!(AESTowerField8b);

impl_arithmetic_using_packed!(AESTowerField8b);

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
	TypeId::of::<F>() == TypeId::of::<AESTowerField8b>()
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

macro_rules! serialize_deserialize_non_canonical {
	($field:ident, canonical=$canonical:ident) => {
		impl SerializeBytes for $field {
			fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
				self.0.serialize(write_buf)
			}
		}

		impl DeserializeBytes for $field {
			fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError>
			where
				Self: Sized,
			{
				Ok(Self(DeserializeBytes::deserialize(read_buf)?))
			}
		}
	};
}

serialize_deserialize_non_canonical!(AESTowerField8b, canonical = BinaryField8b);

#[cfg(test)]
mod tests {
	use binius_utils::{SerializeBytes, bytes::BytesMut};
	use proptest::{arbitrary::any, proptest};
	use rand::prelude::*;

	use super::*;
	use crate::{
		Random, binary_field::tests::is_binary_field_valid_generator, underlier::WithUnderlier,
	};

	fn check_square(f: impl Field) {
		assert_eq!(f.square(), f * f);
	}

	proptest! {
		#[test]
		fn test_square_8(a in any::<u8>()) {
			check_square(AESTowerField8b::from(a))
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
		fn test_conversion_roundtrip(a in any::<u8>()) {
			let a_val = AESTowerField8b(a);
			let converted = BinaryField8b::from(a_val);
			assert_eq!(a_val, AESTowerField8b::from(converted));
		}
	}

	#[test]
	fn test_multiplicative_generators() {
		assert!(is_binary_field_valid_generator::<AESTowerField8b>());
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
	}

	#[test]
	fn test_serialization() {
		let mut buffer = BytesMut::new();
		let mut rng = StdRng::seed_from_u64(0);
		let aes8 = AESTowerField8b::random(&mut rng);

		SerializeBytes::serialize(&aes8, &mut buffer).unwrap();

		let mut read_buffer = buffer.freeze();

		assert_eq!(AESTowerField8b::deserialize(&mut read_buffer).unwrap(), aes8);
	}
}

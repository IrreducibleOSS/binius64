// Copyright 2024-2025 Irreducible Inc.

use std::{
	arch::aarch64::*,
	ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, Shr},
};

use binius_utils::{
	DeserializeBytes, SerializationError, SerializationMode, SerializeBytes,
	bytes::{Buf, BufMut},
	serialization::{assert_enough_data_for, assert_enough_space_for},
};
use bytemuck::{Pod, Zeroable};
use derive_more::Not;
use rand::{
	Rng,
	distr::{Distribution, StandardUniform},
};
use seq_macro::seq;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::super::portable::{
	packed::{PackedPrimitiveType, impl_pack_scalar},
	packed_arithmetic::{UnderlierWithBitConstants, interleave_mask_even, interleave_mask_odd},
};
use crate::{
	BinaryField,
	arch::binary_utils::{as_array_mut, as_array_ref},
	arithmetic_traits::Broadcast,
	tower_levels::TowerLevel,
	underlier::{
		NumCast, SmallU, U1, U2, U4, UnderlierType, UnderlierWithBitOps, WithUnderlier,
		impl_divisible, impl_iteration, transpose_128b_values, unpack_lo_128b_fallback,
	},
};

/// 128-bit value that is used for 128-bit SIMD operations
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Pod, Zeroable, Not)]
#[repr(transparent)]
pub struct M128(pub u128);

impl M128 {
	pub const fn from_le_bytes(bytes: [u8; 16]) -> Self {
		Self(u128::from_le_bytes(bytes))
	}

	pub const fn from_be_bytes(bytes: [u8; 16]) -> Self {
		Self(u128::from_be_bytes(bytes))
	}

	#[inline]
	pub fn shuffle_u8(self, src: [u8; 16]) -> Self {
		unsafe { vqtbl1q_u8(self.into(), Self::from_le_bytes(src).into()).into() }
	}
}

impl From<M128> for u128 {
	fn from(value: M128) -> Self {
		value.0
	}
}
impl From<M128> for uint8x16_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_u8_p128(value.0) }
	}
}
impl From<M128> for uint16x8_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_u16_p128(value.0) }
	}
}
impl From<M128> for uint32x4_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_u32_p128(value.0) }
	}
}
impl From<M128> for uint64x2_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_u64_p128(value.0) }
	}
}
impl From<M128> for poly8x16_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_p8_p128(value.0) }
	}
}
impl From<M128> for poly16x8_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_p16_p128(value.0) }
	}
}
impl From<M128> for poly64x2_t {
	fn from(value: M128) -> Self {
		unsafe { vreinterpretq_p64_p128(value.0) }
	}
}

impl From<u128> for M128 {
	fn from(value: u128) -> Self {
		Self(value)
	}
}
impl From<u64> for M128 {
	fn from(value: u64) -> Self {
		Self(value as u128)
	}
}
impl From<u32> for M128 {
	fn from(value: u32) -> Self {
		Self(value as u128)
	}
}
impl From<u16> for M128 {
	fn from(value: u16) -> Self {
		Self(value as u128)
	}
}
impl From<u8> for M128 {
	fn from(value: u8) -> Self {
		Self(value as u128)
	}
}

impl<const N: usize> From<SmallU<N>> for M128 {
	fn from(value: SmallU<N>) -> Self {
		Self::from(value.val() as u128)
	}
}

impl From<uint8x16_t> for M128 {
	fn from(value: uint8x16_t) -> Self {
		Self(unsafe { vreinterpretq_p128_u8(value) })
	}
}
impl From<uint16x8_t> for M128 {
	fn from(value: uint16x8_t) -> Self {
		Self(unsafe { vreinterpretq_p128_u16(value) })
	}
}
impl From<uint32x4_t> for M128 {
	fn from(value: uint32x4_t) -> Self {
		Self(unsafe { vreinterpretq_p128_u32(value) })
	}
}
impl From<uint64x2_t> for M128 {
	fn from(value: uint64x2_t) -> Self {
		Self(unsafe { vreinterpretq_p128_u64(value) })
	}
}
impl From<poly8x16_t> for M128 {
	fn from(value: poly8x16_t) -> Self {
		Self(unsafe { vreinterpretq_p128_p8(value) })
	}
}
impl From<poly16x8_t> for M128 {
	fn from(value: poly16x8_t) -> Self {
		Self(unsafe { vreinterpretq_p128_p16(value) })
	}
}
impl From<poly64x2_t> for M128 {
	fn from(value: poly64x2_t) -> Self {
		Self(unsafe { vreinterpretq_p128_p64(value) })
	}
}

impl SerializeBytes for M128 {
	fn serialize(
		&self,
		mut write_buf: impl BufMut,
		_mode: SerializationMode,
	) -> Result<(), SerializationError> {
		assert_enough_space_for(&write_buf, std::mem::size_of::<Self>())?;

		write_buf.put_u128_le(self.0);

		Ok(())
	}
}

impl DeserializeBytes for M128 {
	fn deserialize(
		mut read_buf: impl Buf,
		_mode: SerializationMode,
	) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		assert_enough_data_for(&read_buf, std::mem::size_of::<Self>())?;

		Ok(Self(read_buf.get_u128_le()))
	}
}

impl_divisible!(@pairs M128, u128, u64, u32, u16, u8);
impl_pack_scalar!(M128);

impl BitAnd for M128 {
	type Output = Self;

	#[inline]
	fn bitand(self, rhs: Self) -> Self::Output {
		unsafe { vandq_u8(self.into(), rhs.into()).into() }
	}
}

impl BitAndAssign for M128 {
	fn bitand_assign(&mut self, rhs: Self) {
		*self = *self & rhs;
	}
}

impl BitOr for M128 {
	type Output = Self;

	#[inline]
	fn bitor(self, rhs: Self) -> Self::Output {
		unsafe { vorrq_u8(self.into(), rhs.into()).into() }
	}
}

impl BitOrAssign for M128 {
	fn bitor_assign(&mut self, rhs: Self) {
		*self = *self | rhs;
	}
}

impl BitXor for M128 {
	type Output = Self;

	#[inline]
	fn bitxor(self, rhs: Self) -> Self::Output {
		unsafe { veorq_u8(self.into(), rhs.into()).into() }
	}
}

impl BitXorAssign for M128 {
	fn bitxor_assign(&mut self, rhs: Self) {
		*self = *self ^ rhs;
	}
}

impl Shr<usize> for M128 {
	type Output = Self;

	#[inline]
	fn shr(self, rhs: usize) -> Self::Output {
		Self(self.0 >> rhs)
	}
}

impl Shl<usize> for M128 {
	type Output = Self;

	#[inline]
	fn shl(self, rhs: usize) -> Self::Output {
		Self(self.0 << rhs)
	}
}

impl ConstantTimeEq for M128 {
	fn ct_eq(&self, other: &Self) -> subtle::Choice {
		self.0.ct_eq(&other.0)
	}
}

impl ConditionallySelectable for M128 {
	fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
		ConditionallySelectable::conditional_select(&u128::from(*a), &u128::from(*b), choice).into()
	}
}

impl Distribution<M128> for StandardUniform {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> M128 {
		M128(rng.random())
	}
}

impl std::fmt::Display for M128 {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let data: u128 = (*self).into();
		write!(f, "{data:02X?}")
	}
}

impl std::fmt::Debug for M128 {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "M128({self})")
	}
}

impl UnderlierType for M128 {
	const LOG_BITS: usize = 7;
}

impl UnderlierWithBitOps for M128 {
	const ZERO: Self = Self(0);
	const ONE: Self = Self(1);
	const ONES: Self = Self(u128::MAX);

	fn fill_with_bit(val: u8) -> Self {
		Self(u128::fill_with_bit(val))
	}

	#[inline(always)]
	unsafe fn get_subvalue<T>(&self, i: usize) -> T
	where
		T: WithUnderlier,
		T::Underlier: NumCast<Self>,
	{
		let result = match T::Underlier::BITS {
			1 | 2 | 4 => {
				let elements_in_8 = 8 / T::Underlier::BITS;
				let shift = (i % elements_in_8) * T::Underlier::BITS;
				let mask = (1u8 << T::Underlier::BITS) - 1;

				T::Underlier::num_cast_from(as_array_ref::<_, u8, 16, _>(self, |a| {
					Self::from((a[i / elements_in_8] >> shift) & mask)
				}))
			}
			8 => T::Underlier::num_cast_from(as_array_ref::<_, u8, 16, _>(self, |a| {
				Self::from(a[i])
			})),
			16 => T::Underlier::num_cast_from(as_array_ref::<_, u16, 8, _>(self, |a| {
				Self::from(a[i])
			})),
			32 => T::Underlier::num_cast_from(as_array_ref::<_, u32, 4, _>(self, |a| {
				Self::from(a[i])
			})),
			64 => T::Underlier::num_cast_from(as_array_ref::<_, u64, 2, _>(self, |a| {
				Self::from(a[i])
			})),
			128 => T::Underlier::num_cast_from(*self),
			_ => panic!("unsupported bit count"),
		};

		T::from_underlier(result)
	}

	#[inline(always)]
	unsafe fn set_subvalue<T>(&mut self, i: usize, val: T)
	where
		T: UnderlierWithBitOps,
		Self: From<T>,
	{
		match T::BITS {
			1 | 2 | 4 => {
				let elements_in_8 = 8 / T::BITS;
				let mask = (1u8 << T::BITS) - 1;
				let shift = (i % elements_in_8) * T::BITS;
				let val = u8::num_cast_from(Self::from(val)) << shift;
				let mask = mask << shift;

				as_array_mut::<_, u8, 16>(self, |array| {
					let element = &mut array[i / elements_in_8];
					*element &= !mask;
					*element |= val;
				});
			}
			8 => as_array_mut::<_, u8, 16>(self, |array| {
				array[i] = u8::num_cast_from(Self::from(val));
			}),
			16 => as_array_mut::<_, u16, 8>(self, |array| {
				array[i] = u16::num_cast_from(Self::from(val));
			}),
			32 => as_array_mut::<_, u32, 4>(self, |array| {
				array[i] = u32::num_cast_from(Self::from(val));
			}),
			64 => as_array_mut::<_, u64, 2>(self, |array| {
				array[i] = u64::num_cast_from(Self::from(val));
			}),
			128 => {
				*self = Self::from(val);
			}
			_ => panic!("unsupported bit count"),
		}
	}

	#[inline(always)]
	fn shl_128b_lanes(self, rhs: usize) -> Self {
		Self(self.0 << rhs)
	}

	#[inline(always)]
	fn shr_128b_lanes(self, rhs: usize) -> Self {
		Self(self.0 >> rhs)
	}

	#[inline(always)]
	fn unpack_lo_128b_lanes(self, rhs: Self, log_block_len: usize) -> Self {
		match log_block_len {
			0..3 => unpack_lo_128b_fallback(self, rhs, log_block_len),
			3 => unsafe { vzip1q_u8(self.into(), rhs.into()).into() },
			4 => unsafe { vzip1q_u16(self.into(), rhs.into()).into() },
			5 => unsafe { vzip1q_u32(self.into(), rhs.into()).into() },
			6 => unsafe { vzip1q_u64(self.into(), rhs.into()).into() },
			_ => panic!("Unsupported block length"),
		}
	}

	#[inline(always)]
	fn unpack_hi_128b_lanes(self, rhs: Self, log_block_len: usize) -> Self {
		match log_block_len {
			0..3 => unpack_lo_128b_fallback(self, rhs, log_block_len),
			3 => unsafe { vzip2q_u8(self.into(), rhs.into()).into() },
			4 => unsafe { vzip2q_u16(self.into(), rhs.into()).into() },
			5 => unsafe { vzip2q_u32(self.into(), rhs.into()).into() },
			6 => unsafe { vzip2q_u64(self.into(), rhs.into()).into() },
			_ => panic!("Unsupported block length"),
		}
	}

	#[inline]
	fn transpose_bytes_from_byte_sliced<TL: TowerLevel>(values: &mut TL::Data<Self>)
	where
		u8: NumCast<Self>,
		Self: From<u8>,
	{
		transpose_128b_values::<Self, TL>(values, 0);
	}

	#[inline]
	fn transpose_bytes_to_byte_sliced<TL: TowerLevel>(values: &mut TL::Data<Self>)
	where
		u8: NumCast<Self>,
		Self: From<u8>,
	{
		if TL::LOG_WIDTH == 0 {
			return;
		}

		match TL::LOG_WIDTH {
			1 => {
				let shuffle = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15];
				for v in values.as_mut().iter_mut() {
					*v = v.shuffle_u8(shuffle);
				}
			}
			2 => {
				let shuffle = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
				for v in values.as_mut().iter_mut() {
					*v = v.shuffle_u8(shuffle);
				}
			}
			3 => {
				let shuffle = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];
				for v in values.as_mut().iter_mut() {
					*v = v.shuffle_u8(shuffle);
				}
			}
			4 => {}
			_ => unreachable!("Log width must be less than 5"),
		}

		transpose_128b_values::<_, TL>(values, 4 - TL::LOG_WIDTH);
	}
}

impl UnderlierWithBitConstants for M128 {
	const INTERLEAVE_EVEN_MASK: &'static [Self] = &[
		Self(interleave_mask_even!(u128, 0)),
		Self(interleave_mask_even!(u128, 1)),
		Self(interleave_mask_even!(u128, 2)),
		Self(interleave_mask_even!(u128, 3)),
		Self(interleave_mask_even!(u128, 4)),
		Self(interleave_mask_even!(u128, 5)),
		Self(interleave_mask_even!(u128, 6)),
	];
	const INTERLEAVE_ODD_MASK: &'static [Self] = &[
		Self(interleave_mask_odd!(u128, 0)),
		Self(interleave_mask_odd!(u128, 1)),
		Self(interleave_mask_odd!(u128, 2)),
		Self(interleave_mask_odd!(u128, 3)),
		Self(interleave_mask_odd!(u128, 4)),
		Self(interleave_mask_odd!(u128, 5)),
		Self(interleave_mask_odd!(u128, 6)),
	];

	#[inline]
	fn interleave(self, other: Self, log_block_len: usize) -> (Self, Self) {
		unsafe {
			seq!(LOG_BLOCK_LEN in 0..=2 {
				if log_block_len == LOG_BLOCK_LEN {
					let (a, b) = (self.into(), other.into());
					let mask = Self::INTERLEAVE_EVEN_MASK[LOG_BLOCK_LEN].into();
					let t = vandq_u64(veorq_u64(vshrq_n_u64(a, 1 << LOG_BLOCK_LEN), b), mask);
					let c = veorq_u64(a, vshlq_n_u64(t, 1 << LOG_BLOCK_LEN));
					let d = veorq_u64(b, t);
					return (c.into(), d.into());
				}
			});
			match log_block_len {
				3 => {
					let (a, b) = (self.into(), other.into());
					let c = vtrn1q_u8(a, b);
					let d = vtrn2q_u8(a, b);
					(c.into(), d.into())
				}
				4 => {
					let (a, b) = (self.into(), other.into());
					let c = vtrn1q_u16(a, b);
					let d = vtrn2q_u16(a, b);
					(c.into(), d.into())
				}
				5 => {
					let (a, b) = (self.into(), other.into());
					let c = vtrn1q_u32(a, b);
					let d = vtrn2q_u32(a, b);
					(c.into(), d.into())
				}
				6 => {
					let (a, b) = (self.into(), other.into());
					let c = vtrn1q_u64(a, b);
					let d = vtrn2q_u64(a, b);
					(c.into(), d.into())
				}
				_ => panic!("Unsupported block length"),
			}
		}
	}

	#[inline]
	fn transpose(self, other: Self, log_block_len: usize) -> (Self, Self) {
		unsafe {
			match log_block_len {
				0..=3 => {
					let (a, b) = (self.into(), other.into());
					let (mut a, mut b) = (Self::from(vuzp1q_u8(a, b)), Self::from(vuzp2q_u8(a, b)));

					for log_block_len in (log_block_len..3).rev() {
						(a, b) = a.interleave(b, log_block_len);
					}

					(a, b)
				}
				4 => {
					let (a, b) = (self.into(), other.into());
					(vuzp1q_u16(a, b).into(), vuzp2q_u16(a, b).into())
				}
				5 => {
					let (a, b) = (self.into(), other.into());
					(vuzp1q_u32(a, b).into(), vuzp2q_u32(a, b).into())
				}
				6 => {
					let (a, b) = (self.into(), other.into());
					(vuzp1q_u64(a, b).into(), vuzp2q_u64(a, b).into())
				}
				_ => panic!("Unsupported block length"),
			}
		}
	}
}

impl<Scalar: BinaryField> From<u128> for PackedPrimitiveType<M128, Scalar> {
	fn from(value: u128) -> Self {
		Self::from(M128::from(value))
	}
}

impl<Scalar: BinaryField> From<PackedPrimitiveType<M128, Scalar>> for u128 {
	fn from(value: PackedPrimitiveType<M128, Scalar>) -> Self {
		value.to_underlier().into()
	}
}

impl<U: NumCast<u128>> NumCast<M128> for U {
	fn num_cast_from(val: M128) -> Self {
		Self::num_cast_from(val.into())
	}
}

impl<Scalar: BinaryField> Broadcast<Scalar> for PackedPrimitiveType<M128, Scalar>
where
	u128: From<Scalar::Underlier>,
{
	#[inline]
	fn broadcast(scalar: Scalar) -> Self {
		let tower_level = Scalar::N_BITS.ilog2() as usize;
		let mut value = u128::from(scalar.to_underlier());
		for n in tower_level..3 {
			value |= value << (1 << n);
		}

		let value = match tower_level {
			0..=3 => unsafe { vreinterpretq_p128_u8(vdupq_n_u8(value as u8)) },
			4 => unsafe { vreinterpretq_p128_u16(vdupq_n_u16(value as u16)) },
			5 => unsafe { vreinterpretq_p128_u32(vdupq_n_u32(value as u32)) },
			6 => unsafe { vreinterpretq_p128_u64(vdupq_n_u64(value as u64)) },
			7 => value,
			_ => unreachable!(),
		};

		value.into()
	}
}

impl_iteration!(M128,
	@strategy BitIterationStrategy, U1,
	@strategy FallbackStrategy, U2, U4,
	@strategy DivisibleStrategy, u8, u16, u32, u64, u128, M128,
);

#[cfg(test)]
mod tests {
	use binius_utils::bytes::BytesMut;
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_serialize_and_deserialize_m128() {
		let mode = SerializationMode::Native;

		let mut rng = StdRng::from_seed([0; 32]);

		let original_value = M128::from(rng.random::<u128>());

		let mut buf = BytesMut::new();
		original_value.serialize(&mut buf, mode).unwrap();

		let deserialized_value = M128::deserialize(buf.freeze(), mode).unwrap();

		assert_eq!(original_value, deserialized_value);
	}
}

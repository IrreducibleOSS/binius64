use std::{
	fmt,
	ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Word(pub u64);

impl Word {
	pub const ZERO: Word = Word(0);
	pub const ONE: Word = Word(1);
	pub const ALL_ONE: Word = Word(u64::MAX);
	pub const MASK_32: Word = Word(0x00000000_FFFFFFFF);
}

impl fmt::Debug for Word {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Word({:#018x})", self.0)
	}
}

impl BitAnd for Word {
	type Output = Self;

	fn bitand(self, rhs: Self) -> Self::Output {
		Word(self.0 & rhs.0)
	}
}

impl BitOr for Word {
	type Output = Self;

	fn bitor(self, rhs: Self) -> Self::Output {
		Word(self.0 | rhs.0)
	}
}

impl BitXor for Word {
	type Output = Self;

	fn bitxor(self, rhs: Self) -> Self::Output {
		Word(self.0 ^ rhs.0)
	}
}

impl Shl<u32> for Word {
	type Output = Self;

	fn shl(self, rhs: u32) -> Self::Output {
		Word(self.0 << rhs)
	}
}

impl Shr<u32> for Word {
	type Output = Self;

	fn shr(self, rhs: u32) -> Self::Output {
		Word(self.0 >> rhs)
	}
}

impl Not for Word {
	type Output = Self;

	fn not(self) -> Self::Output {
		Word(!self.0)
	}
}

impl Word {
	/// Performs 32-bit addition.
	///
	/// Returns (sum, carry_out) where ith carry_out bit is set to one if there is a carry out at
	/// that bit position.
	pub fn iadd_cout_32(self, rhs: Word) -> (Word, Word) {
		let Word(lhs) = self;
		let Word(rhs) = rhs;
		let full_sum = lhs.wrapping_add(rhs);
		let sum = full_sum & 0x00000000_FFFFFFFF;
		let cout = (lhs & rhs) | ((lhs ^ rhs) & !full_sum);
		(Word(sum), Word(cout))
	}

	/// Performs 64-bit addition with carry input bit.
	///
	/// cin is a carry-in from the previous addition. Since it can only affect the LSB only, the cin
	/// could be 1 if there is carry over, or 0 otherwise.
	///
	/// Returns (sum, carry_out) where ith carry_out bit is set to one if there is a carry out at
	/// that bit position.
	pub fn iadd_cin_cout(self, rhs: Word, cin: Word) -> (Word, Word) {
		debug_assert!(cin == Word::ZERO || cin == Word::ONE, "cin must be 0 or 1");
		let Word(lhs) = self;
		let Word(rhs) = rhs;
		let Word(cin) = cin;
		let sum = lhs.wrapping_add(rhs).wrapping_add(cin);
		let cout = (lhs & rhs) | ((lhs ^ rhs) & !sum);
		(Word(sum), Word(cout))
	}

	/// Performs 64-bit subtraction with borrow input bit.
	///
	/// bin is a borrow-in from the previous subtraction. Since it can only affect the LSB only, the
	/// bin could be 1 if there is borrow over, or 0 otherwise.
	///
	/// Returns (diff, borrow_out) where ith borrow_out bit is set to one if there is a borrow out
	/// at that bit position.
	pub fn isub_bin_bout(self, rhs: Word, bin: Word) -> (Word, Word) {
		debug_assert!(bin == Word::ZERO || bin == Word::ONE, "bin must be 0 or 1");
		let Word(lhs) = self;
		let Word(rhs) = rhs;
		let Word(bin) = bin;
		let diff = lhs.wrapping_sub(rhs).wrapping_sub(bin);
		let bout = (!lhs & rhs) | (!(lhs ^ rhs) & diff);
		(Word(diff), Word(bout))
	}

	pub fn shr_32(self, n: u32) -> Word {
		let Word(value) = self;
		// Shift right logically by n bits and mask with 32-bit mask
		let result = (value >> n) & 0x00000000_FFFFFFFF;
		Word(result)
	}

	/// Shift Arithmetic Right by a given number of bits.
	pub fn sar(&self, n: u32) -> Word {
		let Word(value) = self;
		let value = *value as i64;
		let result = value >> n;
		Word(result as u64)
	}

	pub fn rotr_32(self, n: u32) -> Word {
		let Word(value) = self;
		let n = n % 32; // Ensure n is within 0-31 range
		// Extract lower 32 bits for rotation
		let value_32 = value & 0x00000000_FFFFFFFF;
		if n == 0 {
			return Word(value_32); // Avoid full-width shift
		}
		// Rotate right: (value >> n) | (value << (32 - n))
		let result = ((value_32 >> n) | (value_32 << (32 - n))) & 0x00000000_FFFFFFFF;
		Word(result)
	}

	pub fn rotl_64(self, n: u32) -> Word {
		let Word(value) = self;
		let n = n % 64; // Ensure n is within 0-63 range
		if n == 0 {
			return self; // Avoid full-width shift
		}
		let result = (value << n) | (value >> (64 - n));
		Word(result)
	}

	pub fn imul(self, rhs: Word) -> (Word, Word) {
		let Word(lhs) = self;
		let Word(rhs) = rhs;
		let result = (lhs as u128) * (rhs as u128);

		let hi = (result >> 64) as u64;
		let lo = (result & 0x0000000000000000_FFFFFFFFFFFFFFFF) as u64;
		(Word(hi), Word(lo))
	}

	pub fn smul(self, rhs: Word) -> (Word, Word) {
		let Word(lhs) = self;
		let Word(rhs) = rhs;
		// Interpret as signed 64-bit integers
		let a = lhs as i64;
		let b = rhs as i64;
		// Perform signed multiplication as 128-bit
		let result = (a as i128) * (b as i128);
		// Extract high and low 64-bit words
		let hi = (result >> 64) as u64;
		let lo = result as u64;
		(Word(hi), Word(lo))
	}

	pub fn wrapping_sub(self, rhs: Word) -> Word {
		Word(self.0.wrapping_sub(rhs.0))
	}

	pub fn as_u64(self) -> u64 {
		self.0
	}

	pub fn from_u64(value: u64) -> Word {
		Word(value)
	}
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;

	use super::*;

	#[test]
	fn test_constants() {
		assert_eq!(Word::ZERO, Word(0));
		assert_eq!(Word::ONE, Word(1));
		assert_eq!(Word::ALL_ONE, Word(0xFFFFFFFFFFFFFFFF));
		assert_eq!(Word::MASK_32, Word(0x00000000FFFFFFFF));
	}

	proptest! {
		#[test]
		fn prop_bitwise_and(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);

			// Basic AND properties
			assert_eq!((wa & wb).0, a & b);
			assert_eq!(wa & Word::ALL_ONE, wa);
			assert_eq!(wa & Word::ZERO, Word::ZERO);
			assert_eq!(wa & wa, wa); // Idempotent

			// Commutative
			assert_eq!(wa & wb, wb & wa);
		}

		#[test]
		fn prop_bitwise_or(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);

			// Basic OR properties
			assert_eq!((wa | wb).0, a | b);
			assert_eq!(wa | Word::ZERO, wa);
			assert_eq!(wa | Word::ALL_ONE, Word::ALL_ONE);
			assert_eq!(wa | wa, wa); // Idempotent

			// Commutative
			assert_eq!(wa | wb, wb | wa);
		}

		#[test]
		fn prop_bitwise_xor(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);

			// Basic XOR properties
			assert_eq!((wa ^ wb).0, a ^ b);
			assert_eq!(wa ^ Word::ZERO, wa);
			assert_eq!(wa ^ wa, Word::ZERO);
			assert_eq!(wa ^ Word::ALL_ONE, !wa);

			// Commutative
			assert_eq!(wa ^ wb, wb ^ wa);

			// Double XOR cancels
			assert_eq!(wa ^ wb ^ wb, wa);
		}

		#[test]
		fn prop_bitwise_not(a in any::<u64>()) {
			let wa = Word(a);

			// Basic NOT properties
			assert_eq!((!wa).0, !a);
			assert_eq!(!(!wa), wa); // Double negation
			assert_eq!(!Word::ZERO, Word::ALL_ONE);
			assert_eq!(!Word::ALL_ONE, Word::ZERO);

			// De Morgan's laws
			let wb = Word(a.wrapping_add(1));
			assert_eq!(!(wa & wb), !wa | !wb);
			assert_eq!(!(wa | wb), !wa & !wb);
		}

		#[test]
		fn prop_shift_left(val in any::<u64>(), shift in 0u32..64) {
			let w = Word(val);
			assert_eq!((w << shift).0, val << shift);

			// Shifting by 0 is identity
			assert_eq!(w << 0, w);

			// Shifting by 64 or more gives 0
			if shift >= 64 {
				assert_eq!((w << shift).0, 0);
			}
		}

		#[test]
		fn prop_shift_right(val in any::<u64>(), shift in 0u32..64) {
			let w = Word(val);
			assert_eq!((w >> shift).0, val >> shift);

			// Shifting by 0 is identity
			assert_eq!(w >> 0, w);

			// Shifting by 64 or more gives 0
			if shift >= 64 {
				assert_eq!((w >> shift).0, 0);
			}
		}

		#[test]
		fn prop_shift_inverse(val in any::<u64>(), shift in 1u32..64) {
			let w = Word(val);
			// Left then right shift loses high bits
			let mask = (1u64 << (64 - shift)) - 1;
			assert_eq!(((w << shift) >> shift).0, val & mask);

			// Right then left shift loses low bits
			let high_mask = !((1u64 << shift) - 1);
			assert_eq!(((w >> shift) << shift).0, val & high_mask);
		}

		#[test]
		fn prop_sar(val in any::<u64>(), shift in 0u32..64) {
			let w = Word(val);
			let expected = ((val as i64) >> shift) as u64;
			assert_eq!(w.sar(shift).0, expected);

			// SAR by 0 is identity
			assert_eq!(w.sar(0), w);

			// SAR by 63 gives all 0s or all 1s depending on sign
			let sign_extended = if (val as i64) < 0 {
				Word(0xFFFFFFFFFFFFFFFF)
			} else {
				Word(0)
			};
			assert_eq!(w.sar(63), sign_extended);
		}

		#[test]
		fn prop_sar_sign_extension(val in any::<u64>(), shift in 1u32..64) {
			let w = Word(val);
			let result = w.sar(shift);

			// Check sign bit is extended
			let is_negative = (val as i64) < 0;
			if is_negative {
				// High bits should all be 1
				let mask = !((1u64 << (64 - shift)) - 1);
				assert_eq!(result.0 & mask, mask);
			} else {
				// High bits should all be 0
				let mask = !((1u64 << (64 - shift)) - 1);
				assert_eq!(result.0 & mask, 0);
			}
		}

		#[test]
		fn prop_iadd_cout_32(a in any::<u32>(), b in any::<u32>()) {
			let wa = Word(a as u64);
			let wb = Word(b as u64);
			let (sum, cout) = wa.iadd_cout_32(wb);

			// Sum should be masked to 32 bits
			assert_eq!(sum.0, (a as u64 + b as u64) & 0xFFFFFFFF);

			// Carry computation: cout = (a & b) | ((a ^ b) & !sum)
			let expected_cout = (a as u64 & b as u64) | ((a as u64 ^ b as u64) & !sum.0);
			assert_eq!(cout.0, expected_cout);

			// Identity: adding 0 produces no carries
			let (sum0, cout0) = wa.iadd_cout_32(Word::ZERO);
			assert_eq!(sum0.0, a as u64);
			assert_eq!(cout0, Word::ZERO);
		}

		#[test]
		fn prop_iadd_cin_cout(a in any::<u64>(), b in any::<u64>(), cin in 0u64..=1) {
			let wa = Word(a);
			let wb = Word(b);
			let wcin = Word(cin);
			let (sum, cout) = wa.iadd_cin_cout(wb, wcin);

			// Basic addition with carry
			let expected_sum = a.wrapping_add(b).wrapping_add(cin);
			assert_eq!(sum.0, expected_sum);

			// Carry computation: cout at each bit position
			let expected_cout = (a & b) | ((a ^ b) & !expected_sum);
			assert_eq!(cout.0, expected_cout);

			// Without carry in, same as regular addition
			let (sum0, cout0) = wa.iadd_cin_cout(wb, Word::ZERO);
			let full_sum = a.wrapping_add(b);
			assert_eq!(sum0.0, full_sum);
			assert_eq!(cout0.0, (a & b) | ((a ^ b) & !full_sum));
		}

		#[test]
		fn prop_isub_bin_bout(a in any::<u64>(), b in any::<u64>(), bin in 0u64..=1) {
			let wa = Word(a);
			let wb = Word(b);
			let wbin = Word(bin);
			let (diff, bout) = wa.isub_bin_bout(wb, wbin);

			// Basic subtraction with borrow
			let expected_diff = a.wrapping_sub(b).wrapping_sub(bin);
			assert_eq!(diff.0, expected_diff);

			// Borrow computation: bout = (!a & b) | (!(a ^ b) & diff)
			let expected_bout = (!a & b) | (!(a ^ b) & expected_diff);
			assert_eq!(bout.0, expected_bout);

			// Without borrow in
			let (diff0, bout0) = wa.isub_bin_bout(wb, Word::ZERO);
			let expected = a.wrapping_sub(b);
			assert_eq!(diff0.0, expected);
			assert_eq!(bout0.0, (!a & b) | (!(a ^ b) & expected));
		}

		#[test]
		fn prop_shr_32(val in any::<u64>(), shift in 0u32..64) {
			let w = Word(val);
			let result = w.shr_32(shift);

			// Result should be the full value shifted right, then masked to 32 bits
			let expected = (val >> shift) & 0xFFFFFFFF;
			assert_eq!(result.0, expected);

			// Shifting by 0 gives lower 32 bits
			assert_eq!(w.shr_32(0).0, val & 0xFFFFFFFF);

			// Shifting by 32 or more gives upper bits or zeros
			if shift >= 32 {
				assert_eq!(result.0, (val >> shift) & 0xFFFFFFFF);
			}
		}

		#[test]
		fn prop_rotr_32(val in any::<u32>(), rotate in 0u32..64) {
			let w = Word(val as u64);
			let result = w.rotr_32(rotate);

			// Only lower 32 bits are rotated
			let rotate_mod = rotate % 32;
			let val32 = val as u64;
			let expected = if rotate_mod == 0 {
				val32
			} else {
				((val32 >> rotate_mod) | (val32 << (32 - rotate_mod))) & 0xFFFFFFFF
			};
			assert_eq!(result.0, expected);

			// Rotation by 0 or 32 is identity
			assert_eq!(w.rotr_32(0).0, val32);
			assert_eq!(w.rotr_32(32).0, val32);
		}

		#[test]
		fn prop_rotl_64(val in any::<u64>(), rotate in 0u32..128) {
			let w = Word(val);
			let result = w.rotl_64(rotate);

			// Rotation is modulo 64
			let rotate_mod = rotate % 64;
			let expected = if rotate_mod == 0 {
				val
			} else {
				(val << rotate_mod) | (val >> (64 - rotate_mod))
			};
			assert_eq!(result.0, expected);

			// Rotation by 0 or 64 is identity
			assert_eq!(w.rotl_64(0), w);
			assert_eq!(w.rotl_64(64), w);

			// Double rotation
			let r1 = rotate % 64;
			let r2 = (64 - r1) % 64;
			if r1 != 0 {
				assert_eq!(w.rotl_64(r1).rotl_64(r2), w);
			}
		}

		#[test]
		fn prop_imul(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);
			let (hi, lo) = wa.imul(wb);

			// Check against native 128-bit multiplication
			let result = (a as u128) * (b as u128);
			assert_eq!(hi.0, (result >> 64) as u64);
			assert_eq!(lo.0, result as u64);

			// Multiplication by 0 gives 0
			let (hi0, lo0) = wa.imul(Word::ZERO);
			assert_eq!(hi0, Word::ZERO);
			assert_eq!(lo0, Word::ZERO);

			// Multiplication by 1 is identity
			let (hi1, lo1) = wa.imul(Word::ONE);
			assert_eq!(hi1, Word::ZERO);
			assert_eq!(lo1, wa);

			// Commutative
			let (hi_ab, lo_ab) = wa.imul(wb);
			let (hi_reversed, lo_reversed) = wb.imul(wa);
			assert_eq!(hi_ab, hi_reversed);
			assert_eq!(lo_ab, lo_reversed);
		}

		#[test]
		fn prop_smul(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);
			let (hi, lo) = wa.smul(wb);

			// Check against native 128-bit signed multiplication
			let result = (a as i64 as i128) * (b as i64 as i128);
			assert_eq!(hi.0, (result >> 64) as u64);
			assert_eq!(lo.0, result as u64);

			// Multiplication by 0 gives 0
			let (hi0, lo0) = wa.smul(Word::ZERO);
			assert_eq!(hi0, Word::ZERO);
			assert_eq!(lo0, Word::ZERO);

			// Multiplication by 1 is identity
			let (hi1, lo1) = wa.smul(Word::ONE);
			let expected_hi = if (a as i64) < 0 { Word(0xFFFFFFFFFFFFFFFF) } else { Word::ZERO };
			assert_eq!(hi1, expected_hi);
			assert_eq!(lo1, wa);

			// Multiplication by -1 negates
			let (hi_neg, lo_neg) = wa.smul(Word(0xFFFFFFFFFFFFFFFF));
			let neg_result = -(a as i64 as i128);
			assert_eq!(hi_neg.0, (neg_result >> 64) as u64);
			assert_eq!(lo_neg.0, neg_result as u64);

			// Commutative
			let (hi_ab, lo_ab) = wa.smul(wb);
			let (hi_reversed, lo_reversed) = wb.smul(wa);
			assert_eq!(hi_ab, hi_reversed);
			assert_eq!(lo_ab, lo_reversed);
		}

		#[test]
		fn prop_wrapping_sub(a in any::<u64>(), b in any::<u64>()) {
			let wa = Word(a);
			let wb = Word(b);
			let result = wa.wrapping_sub(wb);

			assert_eq!(result.0, a.wrapping_sub(b));

			// Subtracting 0 is identity
			assert_eq!(wa.wrapping_sub(Word::ZERO), wa);

			// Subtracting itself gives 0
			assert_eq!(wa.wrapping_sub(wa), Word::ZERO);

			// Adding then subtracting cancels
			let sum = Word(a.wrapping_add(b));
			assert_eq!(sum.wrapping_sub(wb), wa);
		}

		#[test]
		fn prop_conversions(val in any::<u64>()) {
			let word = Word::from_u64(val);
			assert_eq!(word.as_u64(), val);
			assert_eq!(word, Word(val));

			// Round trip
			assert_eq!(Word::from_u64(word.as_u64()), word);
		}

		#[test]
		fn prop_debug_format(val in any::<u64>()) {
			let word = Word(val);
			let debug_str = format!("{:?}", word);
			assert!(debug_str.starts_with("Word(0x"));
			assert!(debug_str.ends_with(")"));
			// Check the hex value is correct (lowercase)
			let expected = format!("Word({:#018x})", val);
			assert_eq!(debug_str, expected);
		}
	}
}

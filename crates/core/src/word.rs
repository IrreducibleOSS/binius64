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
	/// Performs n-ary XOR operation over a slice of words.
	///
	/// Returns the XOR of all the words in the slice.
	pub fn n_ary_xor(words: &[Word]) -> Word {
		let mut result = Word::ZERO;
		for word in words {
			result = result ^ *word;
		}
		result
	}
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
		// Rotate right: (value >> n) | (value << (32 - n))
		let result = ((value_32 >> n) | (value_32 << (32 - n))) & 0x00000000_FFFFFFFF;
		Word(result)
	}

	pub fn rotl_64(self, n: u32) -> Word {
		let Word(value) = self;
		let n = n % 64; // Ensure n is within 0-63 range
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

use std::{
    fmt,
    ops::{BitAnd, BitOr, BitXor},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

impl Word {
    pub fn iadd_32(self, rhs: Word) -> (Word, Word) {
        let Word(lhs) = self;
        let Word(rhs) = rhs;
        let sum = lhs.wrapping_add(rhs) & 0x00000000_FFFFFFFF;
        let cout = (lhs & rhs) | ((lhs ^ rhs) & !sum);
        (Word(sum), Word(cout))
    }

    pub fn shr_32(self, n: u32) -> Word {
        let Word(value) = self;
        // Shift right logically by n bits and mask with 32-bit mask
        let result = (value >> n) & 0x00000000_FFFFFFFF;
        Word(result)
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
}

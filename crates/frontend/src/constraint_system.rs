use std::ops::{Index, IndexMut};

use crate::word::Word;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ValueIndex(pub u32);

/// A different variants of shifting a value.
///
/// Note that there is no shift left arithmetic because it is redundant.
#[derive(Copy, Clone, Debug)]
pub enum ShiftVariant {
	/// Shift logical left.
	Sll,
	/// Shift logical right.
	Slr,
	/// Shift arithmetic right.
	Sar,
}

#[derive(Copy, Clone, Debug)]
pub struct ShiftedValueIndex {
	/// The index of this value in the input values vector `z`.
	pub value_index: ValueIndex,
	/// The flavour of the shift that the value must be shifted by.
	pub shift_variant: ShiftVariant,
	/// The number of bits by which the value must be shifted by.
	pub amount: usize,
}

impl ShiftedValueIndex {
	/// Create a value index that just uses the specified value.
	pub fn plain(value_index: ValueIndex) -> Self {
		Self {
			value_index,
			shift_variant: ShiftVariant::Sll,
			amount: 0,
		}
	}

	/// Shift Left Logical by the given number of bits.
	pub fn sll(value_index: ValueIndex, amount: usize) -> Self {
		Self {
			value_index,
			shift_variant: ShiftVariant::Sll,
			amount,
		}
	}

	pub fn srl(value_index: ValueIndex, amount: usize) -> Self {
		Self {
			value_index,
			shift_variant: ShiftVariant::Slr,
			amount,
		}
	}

	pub fn sar(value_index: ValueIndex, amount: usize) -> Self {
		Self {
			value_index,
			shift_variant: ShiftVariant::Sar,
			amount,
		}
	}
}

pub type Operand = Vec<ShiftedValueIndex>;

pub struct AndConstraint {
	pub a: Operand,
	pub b: Operand,
	pub c: Operand,
}

impl AndConstraint {
	pub fn plain_abc(
		a: impl IntoIterator<Item = ValueIndex>,
		b: impl IntoIterator<Item = ValueIndex>,
		c: impl IntoIterator<Item = ValueIndex>,
	) -> AndConstraint {
		AndConstraint {
			a: a.into_iter().map(ShiftedValueIndex::plain).collect(),
			b: b.into_iter().map(ShiftedValueIndex::plain).collect(),
			c: c.into_iter().map(ShiftedValueIndex::plain).collect(),
		}
	}

	pub fn abc(
		a: impl IntoIterator<Item = ShiftedValueIndex>,
		b: impl IntoIterator<Item = ShiftedValueIndex>,
		c: impl IntoIterator<Item = ShiftedValueIndex>,
	) -> AndConstraint {
		AndConstraint {
			a: a.into_iter().collect(),
			b: b.into_iter().collect(),
			c: c.into_iter().collect(),
		}
	}
}

pub struct MulConstraint {
	pub a: Operand,
	pub b: Operand,
	pub hi: Operand,
	pub lo: Operand,
}

pub struct ConstraintSystem {
	pub constants: Vec<Word>,
	pub n_inout: usize,
	pub n_witness: usize,
	pub and_constraints: Vec<AndConstraint>,
	pub mul_constraints: Vec<MulConstraint>,
}

impl ConstraintSystem {
	pub fn new(constants: Vec<Word>, n_inout: usize, n_witness: usize) -> Self {
		ConstraintSystem {
			constants,
			n_inout,
			n_witness,
			and_constraints: Vec::new(),
			mul_constraints: Vec::new(),
		}
	}

	pub fn add_and_constraint(&mut self, and_constraint: AndConstraint) {
		self.and_constraints.push(and_constraint);
	}

	pub fn add_mul_constraint(&mut self, mul_constraint: MulConstraint) {
		self.mul_constraints.push(mul_constraint);
	}

	pub fn n_and_constraints(&self) -> usize {
		self.and_constraints.len()
	}

	pub fn n_mul_constraints(&self) -> usize {
		self.mul_constraints.len()
	}

	/// The total length of the [`ValueVec`] expected by this constraint system.
	pub fn value_vec_len(&self) -> usize {
		value_vec_len(self.constants.len(), self.n_inout, self.n_witness)
	}

	/// Create a new [`ValueVec`] with the size expected by this constraint system.
	pub fn new_value_vec(&self) -> ValueVec {
		ValueVec::new(self.constants.len(), self.n_inout, self.n_witness)
	}
}

pub fn value_vec_len(n_const: usize, n_inout: usize, n_witness: usize) -> usize {
	(n_const + n_inout + n_witness).next_power_of_two()
}

/// The vector of values.
///
/// This is a prover-only structure.
///
/// The size of the value vec is always a power-of-two.
#[derive(Clone, Debug)]
pub struct ValueVec {
	n_const: usize,
	n_inout: usize,
	n_witness: usize,
	data: Vec<Word>,
}

impl ValueVec {
	pub fn new(n_const: usize, n_inout: usize, n_witness: usize) -> ValueVec {
		let size = value_vec_len(n_const, n_inout, n_witness);
		ValueVec {
			n_const,
			n_inout,
			n_witness,
			data: vec![Word::ZERO; size],
		}
	}

	/// The total size of the vector.
	pub fn size(&self) -> usize {
		self.data.len()
	}

	pub fn get(&self, index: usize) -> Word {
		self.data[index]
	}

	pub fn set(&mut self, index: usize, value: Word) {
		self.data[index] = value;
	}

	/// Returns the inout portion of the values vector.
	pub fn inout(&self) -> &[Word] {
		let start = self.n_const;
		let end = start + self.n_inout;
		&self.data[start..end]
	}

	/// Returns the witness portion of the values vector.
	pub fn witness(&self) -> &[Word] {
		let start = self.n_const + self.n_inout;
		let end = start + self.n_witness;
		&self.data[start..end]
	}

	pub fn assert_filled(&self) {}
}

impl Index<ValueIndex> for ValueVec {
	type Output = Word;

	fn index(&self, index: ValueIndex) -> &Self::Output {
		&self.data[index.0 as usize]
	}
}

impl IndexMut<ValueIndex> for ValueVec {
	fn index_mut(&mut self, index: ValueIndex) -> &mut Self::Output {
		&mut self.data[index.0 as usize]
	}
}

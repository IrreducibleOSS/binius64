use crate::word::Word;

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
pub struct ValueIndex {
    /// The index of this value in the input values vector `z`.
    pub value_index: usize,
    /// The flavour of the shift that the value must be shifted by.
    pub shift_variant: ShiftVariant,
    /// The number of bits by which the value must be shifted by.
    pub amount: usize,
}

impl ValueIndex {
    /// Create a value index that just uses the specified value.
    pub fn plain(value_index: usize) -> Self {
        Self {
            value_index,
            shift_variant: ShiftVariant::Sll,
            amount: 0,
        }
    }

    /// Shift Left Logical by the given number of bits.
    pub fn sll(value_index: usize, amount: usize) -> Self {
        Self {
            value_index,
            shift_variant: ShiftVariant::Sll,
            amount,
        }
    }

    pub fn srl(value_index: usize, amount: usize) -> Self {
        Self {
            value_index,
            shift_variant: ShiftVariant::Slr,
            amount,
        }
    }
}

pub type Operand = Vec<ValueIndex>;

pub struct AndConstraint {
    pub a: Operand,
    pub b: Operand,
    pub c: Operand,
}

impl AndConstraint {
    pub fn plain_abc(
        a: impl IntoIterator<Item = usize>,
        b: impl IntoIterator<Item = usize>,
        c: impl IntoIterator<Item = usize>,
    ) -> AndConstraint {
        AndConstraint {
            a: a.into_iter().map(|i| ValueIndex::plain(i)).collect(),
            b: b.into_iter().map(|i| ValueIndex::plain(i)).collect(),
            c: c.into_iter().map(|i| ValueIndex::plain(i)).collect(),
        }
    }

    pub fn abc(
        a: impl IntoIterator<Item = ValueIndex>,
        b: impl IntoIterator<Item = ValueIndex>,
        c: impl IntoIterator<Item = ValueIndex>,
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
    pub n_public: usize,
    pub n_private: usize,
    pub and_constrants: Vec<AndConstraint>,
    pub mul_constraints: Vec<MulConstraint>,
}

impl ConstraintSystem {
    pub fn new(constants: Vec<Word>, n_public: usize, n_private: usize) -> Self {
        ConstraintSystem {
            constants,
            n_public,
            n_private,
            and_constrants: Vec::new(),
            mul_constraints: Vec::new(),
        }
    }

    pub fn add_and_constraint(&mut self, and_constraint: AndConstraint) {
        self.and_constrants.push(and_constraint);
    }

    pub fn n_and_constraints(&self) -> usize {
        self.and_constrants.len()
    }

    /// The total size of the [`ValueVec`] expected by this constraint system.
    pub fn value_vec_size(&self) -> usize {
        self.constants.len() + self.n_public + self.n_private
    }

    /// Create a new [`ValueVec`] with the size expected by this constraint system.
    pub fn new_value_vec(&self) -> ValueVec {
        ValueVec::new(self.value_vec_size())
    }
}

/// The vector of values.
pub struct ValueVec {
    data: Vec<Option<Word>>,
}

impl ValueVec {
    pub fn new(size: usize) -> ValueVec {
        ValueVec {
            data: vec![None; size],
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn get(&self, index: usize) -> Word {
        if self.data[index].is_none() {
            panic!("Witness::get: value at index {} is not set", index);
        }
        self.data[index].unwrap()
    }

    pub fn set(&mut self, index: usize, value: Word) {
        assert!(self.data[index].is_none());
        self.data[index] = Some(value);
    }

    pub fn assert_filled(&self) {
        assert!(self.data.iter().all(|v| v.is_some()))
    }
}

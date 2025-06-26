use crate::word::Word;

/// A different variants of shifting a value.
///
/// Note that there is no shift left arithmetic because it is redundant.
#[derive(Copy, Clone, Debug)]
pub enum ShiftVariant {
    /// Shift left logical
    Sll,
    /// Shift right logical.
    Srl,
    /// Shift right arithmetic.
    Sar,
}

#[derive(Copy, Clone, Debug)]
pub struct ShiftedValueIndex {
    pub value_index: usize,
    pub shift_variant: ShiftVariant,
    pub amount: usize,
}

impl ShiftedValueIndex {
    pub fn plain(value_index: usize) -> Self {
        Self {
            value_index,
            shift_variant: ShiftVariant::Sll,
            amount: 0,
        }
    }

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
            shift_variant: ShiftVariant::Srl,
            amount,
        }
    }
}

pub struct AndConstraint {
    pub a: Vec<ShiftedValueIndex>,
    pub b: Vec<ShiftedValueIndex>,
    pub c: Vec<ShiftedValueIndex>,
}

impl AndConstraint {
    pub fn plain_abc(
        a: impl IntoIterator<Item = usize>,
        b: impl IntoIterator<Item = usize>,
        c: impl IntoIterator<Item = usize>,
    ) -> AndConstraint {
        AndConstraint {
            a: a.into_iter().map(|i| ShiftedValueIndex::plain(i)).collect(),
            b: b.into_iter().map(|i| ShiftedValueIndex::plain(i)).collect(),
            c: c.into_iter().map(|i| ShiftedValueIndex::plain(i)).collect(),
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
    pub a: Vec<ShiftedValueIndex>,
    pub b: Vec<ShiftedValueIndex>,
    pub hi: Vec<ShiftedValueIndex>,
    pub lo: Vec<ShiftedValueIndex>,
}

pub struct ConstraintSystem {
    constants: Vec<Word>,
    n_public: usize,
    n_private: usize,
    and_constrants: Vec<AndConstraint>,
    mul_constraints: Vec<MulConstraint>,
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

    pub fn new_witness(&self) -> Witness {
        let size = self.constants.len() + self.n_public + self.n_private;
        Witness::new(size)
    }

    // pub fn validate_witness(&self, witness: &Witness) -> bool {
    //
    // }
}

pub struct Witness {
    data: Vec<Option<Word>>,
}

impl Witness {
    pub fn new(size: usize) -> Witness {
        Witness {
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

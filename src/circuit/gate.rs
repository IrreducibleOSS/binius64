use super::Wire;
use crate::constraint_system::AndConstraint;
use crate::constraint_system::ConstraintSystem;
use crate::constraint_system::ValueIndex;
use crate::constraint_system::Witness;

use super::Circuit;

pub trait Gate {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness);
    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem);
}

pub struct Band {
    pub a: Wire,
    pub b: Wire,
    pub c: Wire,
}

impl Band {
    pub fn new(a: Wire, b: Wire, c: Wire) -> Self {
        Self { a, b, c }
    }
}

impl Gate for Band {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        w.set(c, w.get(a) & w.get(b));
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        cs.add_and_constraint(AndConstraint::plain_abc([a], [b], [c]));
    }
}

pub struct Bxor {
    pub a: Wire,
    pub b: Wire,
    pub c: Wire,
}

impl Bxor {
    pub fn new(a: Wire, b: Wire, c: Wire) -> Self {
        Self { a, b, c }
    }
}

impl Gate for Bxor {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        w.set(c, w.get(a) ^ w.get(b));
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        cs.add_and_constraint(AndConstraint::plain_abc([a, b], [], [c]));
    }
}

pub struct Bor {
    pub a: Wire,
    pub b: Wire,
    pub c: Wire,
}

impl Bor {
    pub fn new(a: Wire, b: Wire, c: Wire) -> Self {
        Self { a, b, c }
    }
}

impl Gate for Bor {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        w.set(c, w.get(a) | w.get(b));
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        cs.add_and_constraint(AndConstraint::plain_abc([a], [b], [a, b, c]));
    }
}

pub struct Iadd32 {
    pub a: Wire,
    pub b: Wire,
    pub c: Wire,
    pub cout: Wire,
    pub mask32: Wire,
}

impl Iadd32 {
    pub fn new(a: Wire, b: Wire, c: Wire, cout: Wire, mask32: Wire) -> Self {
        Self {
            a,
            b,
            c,
            cout,
            mask32,
        }
    }
}

impl Gate for Iadd32 {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        let cout = circuit.witness_index(self.cout);

        let (sum, carry) = w.get(a).iadd_32(w.get(b));

        w.set(c, sum);
        w.set(cout, carry);
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let b = circuit.witness_index(self.b);
        let c = circuit.witness_index(self.c);
        let cout = circuit.witness_index(self.cout);
        let mask32 = circuit.witness_index(self.mask32);

        // (x XOR (cout << 1)) AND (y XOR (cout << 1)) = (cout << 1) XOR cout
        cs.add_and_constraint(AndConstraint::abc(
            [ValueIndex::plain(a), ValueIndex::sll(cout, 1)],
            [ValueIndex::plain(b), ValueIndex::sll(cout, 1)],
            [ValueIndex::plain(cout), ValueIndex::sll(cout, 1)],
        ));

        // (x XOR y XOR (cout « 1)) AND M32 = z
        cs.add_and_constraint(AndConstraint::abc(
            [
                ValueIndex::plain(a),
                ValueIndex::plain(b),
                ValueIndex::sll(cout, 1),
            ],
            [ValueIndex::plain(mask32)],
            [ValueIndex::plain(c)],
        ));
    }
}

pub struct Shr32 {
    pub a: Wire,
    pub c: Wire,
    pub mask32: Wire,
    pub n: u32,
}

impl Shr32 {
    pub fn new(a: Wire, c: Wire, mask32: Wire, n: u32) -> Self {
        Self { a, c, mask32, n }
    }
}

impl Gate for Shr32 {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let c = circuit.witness_index(self.c);

        let result = w.get(a).shr_32(self.n);
        w.set(c, result);
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let c = circuit.witness_index(self.c);
        let mask32 = circuit.witness_index(self.mask32);

        // SHR = AND(srl(x, n), M32)
        cs.add_and_constraint(AndConstraint::abc(
            [ValueIndex::srl(a, self.n as usize)],
            [ValueIndex::plain(mask32)],
            [ValueIndex::plain(c)],
        ));
    }
}

pub struct Rotr32 {
    pub a: Wire,
    pub c: Wire,
    pub mask32: Wire,
    pub n: u32,
}

impl Rotr32 {
    pub fn new(a: Wire, c: Wire, mask32: Wire, n: u32) -> Self {
        Self { a, c, mask32, n }
    }
}

impl Gate for Rotr32 {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let a = circuit.witness_index(self.a);
        let c = circuit.witness_index(self.c);

        let result = w.get(a).rotr_32(self.n);
        w.set(c, result);
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let a = circuit.witness_index(self.a);
        let c = circuit.witness_index(self.c);
        let mask32 = circuit.witness_index(self.mask32);

        // ROTR: t1 = srl(x, n), t2 = sll(x, 32-n), r = OR(t1, t2), return AND(r, M32)
        // This translates to: AND(OR(srl(x, n), sll(x, 32-n)), M32) = c
        cs.add_and_constraint(AndConstraint::abc(
            [
                ValueIndex::srl(a, self.n as usize),
                ValueIndex::sll(a, (32 - self.n) as usize),
            ],
            [ValueIndex::plain(mask32)],
            [ValueIndex::plain(c)],
        ));
    }
}

pub struct AssertEq {
    pub x: Wire,
    pub y: Wire,
}

impl AssertEq {
    pub fn new(x: Wire, y: Wire) -> Self {
        Self { x, y }
    }
}

impl Gate for AssertEq {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness) {
        let x = circuit.witness_index(self.x);
        let y = circuit.witness_index(self.y);

        assert_eq!(w.get(x), w.get(y));
    }

    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
        let x = circuit.witness_index(self.x);
        let y = circuit.witness_index(self.y);

        cs.add_and_constraint(AndConstraint::plain_abc([x], [], [y]));
    }
}

use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::{
    constraint_system::{
        AndConstraint, ConstraintSystem, ShiftVariant, ShiftedValueIndex, Witness,
    },
    word::Word,
};

pub struct ConstPool {
    pool: HashMap<Word, Wire>,
}

impl ConstPool {
    pub fn new() -> Self {
        ConstPool {
            pool: HashMap::new(),
        }
    }

    pub fn get(&self, value: Word) -> Option<Wire> {
        self.pool.get(&value).cloned()
    }

    pub fn insert(&mut self, word: Word, wire: Wire) {
        let prev = self.pool.insert(word, wire);
        assert!(prev.is_none());
    }
}

/// An ID of a wire.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Wire(pub usize);

#[derive(Copy, Clone)]
enum WireKind {
    Constant(Word),
    Public,
    Private,
}

#[derive(Copy, Clone)]
pub struct WireData {
    kind: WireKind,
    shift: Option<(ShiftVariant, usize)>,
}

struct Shared {
    cp: ConstPool,
    n_public: usize,
    n_private: usize,
    wires: Vec<WireData>,
    gates: Vec<Box<dyn Gate>>,
}

/// # Clone
///
/// This is a light-weight reference. Cloning is cheap.
#[derive(Clone)]
pub struct CircuitBuilder {
    name: String,
    shared: Rc<RefCell<Option<Shared>>>,
}

impl CircuitBuilder {
    pub fn new() -> Self {
        CircuitBuilder {
            name: String::new(),
            shared: Rc::new(RefCell::new(Some(Shared {
                cp: ConstPool::new(),
                n_private: 0,
                n_public: 0,
                wires: Vec::new(),
                gates: Vec::new(),
            }))),
        }
    }

    pub fn build(&self) -> Circuit {
        let shared = self.shared.borrow_mut().take().unwrap();
        Circuit { shared }
    }

    pub fn subcircuit(&self, name: impl Into<String>) -> CircuitBuilder {
        let name = name.into();
        CircuitBuilder {
            name: format!("{}.{name}", self.name),
            shared: self.shared.clone(),
        }
    }

    fn shared_mut(&self) -> RefMut<Shared> {
        RefMut::map(self.shared.borrow_mut(), |mut shared| {
            shared.as_mut().unwrap()
        })
    }

    fn emit(&self, gate: impl Gate + 'static) {
        self.shared_mut().gates.push(Box::new(gate))
    }

    fn add_wire(&self, wire_data: WireData) -> Wire {
        let mut shared = self.shared_mut();
        let id = shared.wires.len();
        shared.wires.push(wire_data);
        Wire(id)
    }

    pub fn add_constant(&self, word: Word) -> Wire {
        if let Some(wire) = self.shared_mut().cp.get(word) {
            return wire;
        }
        let wire = self.add_wire(WireData {
            kind: WireKind::Constant(word),
            shift: None,
        });
        self.shared_mut().cp.insert(word, wire);
        wire
    }

    pub fn add_public(&self) -> Wire {
        self.shared_mut().n_public += 1;
        self.add_wire(WireData {
            kind: WireKind::Public,
            shift: None,
        })
    }

    pub fn add_private(&self) -> Wire {
        self.shared_mut().n_private += 1;
        self.add_wire(WireData {
            kind: WireKind::Private,
            shift: None,
        })
    }

    pub fn band(&self, a: Wire, b: Wire) -> Wire {
        let c = self.add_private();
        self.emit(Band::new(a, b, c));
        c
    }

    pub fn bxor(&self, a: Wire, b: Wire) -> Wire {
        let c = self.add_private();
        self.emit(Bxor::new(a, b, c));
        c
    }

    /// Bitwise Not
    pub fn bnot(&self, a: Wire) -> Wire {
        let all_one = self.add_constant(Word::ALL_ONE);
        self.bxor(a, all_one)
    }

    pub fn bor(&self, a: Wire, b: Wire) -> Wire {
        let c = self.add_private();
        self.emit(Bor::new(a, b, c));
        c
    }

    pub fn iadd_32(&self, a: Wire, b: Wire) -> Wire {
        let c = self.add_private();
        let cout = self.add_private();
        let mask32 = self.add_constant(Word::MASK_32);
        self.emit(Iadd32::new(a, b, c, cout, mask32));
        c
    }

    pub fn rotr_32(&self, a: Wire, n: u32) -> Wire {
        let c = self.add_private();
        let mask32 = self.add_constant(Word::MASK_32);
        self.emit(Rotr32::new(a, c, mask32, n));
        c
    }

    pub fn shr_32(&self, a: Wire, n: u32) -> Wire {
        let c = self.add_private();
        let mask32 = self.add_constant(Word::MASK_32);
        self.emit(Shr32::new(a, c, mask32, n));
        c
    }

    pub fn assert_eq(&self, x: Wire, y: Wire) {
        self.emit(AssertEq::new(x, y))
    }

    pub fn assert_eq_v<const N: usize>(&self, x: [Wire; N], y: [Wire; N]) {
        for i in 0..N {
            self.assert_eq(x[i], y[i]);
        }
    }
}

pub struct Circuit {
    shared: Shared,
}

impl Circuit {
    /// For the given wire, returns its index in the witness vector.
    #[inline(always)]
    pub fn witness_index(&self, wire: Wire) -> usize {
        wire.0
    }

    pub fn fill_witness(&self, w: &mut Witness) {
        for (i, wire) in self.shared.wires.iter().enumerate() {
            if let WireKind::Constant(value) = wire.kind {
                w.set(self.witness_index(Wire(i)), value);
            }
        }

        use std::time::Instant;
        let start = Instant::now();

        for gate in self.shared.gates.iter() {
            gate.fill_witness(self, w);
        }

        let elapsed = start.elapsed();
        println!("fill_witness took {} microseconds", elapsed.as_micros());
    }

    pub fn constraint_system(&self) -> ConstraintSystem {
        let mut cs = ConstraintSystem::new(
            self.shared.cp.pool.keys().cloned().collect::<Vec<_>>(),
            self.shared.n_public,
            self.shared.n_private,
        );
        for gate in self.shared.gates.iter() {
            gate.constrain(self, &mut cs);
        }
        cs
    }

    pub fn n_gates(&self) -> usize {
        self.shared.gates.len()
    }
}

trait Gate {
    fn fill_witness(&self, circuit: &Circuit, w: &mut Witness);
    fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem);
}

struct Band {
    a: Wire,
    b: Wire,
    c: Wire,
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

struct Bxor {
    a: Wire,
    b: Wire,
    c: Wire,
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

struct Bor {
    a: Wire,
    b: Wire,
    c: Wire,
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

struct Iadd32 {
    a: Wire,
    b: Wire,
    c: Wire,
    cout: Wire,
    mask32: Wire,
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
            [ShiftedValueIndex::plain(a), ShiftedValueIndex::sll(cout, 1)],
            [ShiftedValueIndex::plain(b), ShiftedValueIndex::sll(cout, 1)],
            [
                ShiftedValueIndex::plain(cout),
                ShiftedValueIndex::sll(cout, 1),
            ],
        ));

        // (x XOR y XOR (cout « 1)) AND M32 = z
        cs.add_and_constraint(AndConstraint::abc(
            [
                ShiftedValueIndex::plain(a),
                ShiftedValueIndex::plain(b),
                ShiftedValueIndex::sll(cout, 1),
            ],
            [ShiftedValueIndex::plain(mask32)],
            [ShiftedValueIndex::plain(c)],
        ));
    }
}

struct Shr32 {
    a: Wire,
    c: Wire,
    mask32: Wire,
    n: u32,
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
            [ShiftedValueIndex::srl(a, self.n as usize)],
            [ShiftedValueIndex::plain(mask32)],
            [ShiftedValueIndex::plain(c)],
        ));
    }
}

struct Rotr32 {
    a: Wire,
    c: Wire,
    mask32: Wire,
    n: u32,
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
                ShiftedValueIndex::srl(a, self.n as usize),
                ShiftedValueIndex::sll(a, (32 - self.n) as usize),
            ],
            [ShiftedValueIndex::plain(mask32)],
            [ShiftedValueIndex::plain(c)],
        ));
    }
}

pub struct AssertEq {
    x: Wire,
    y: Wire,
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

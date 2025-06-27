use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    rc::Rc,
};

use gate::{AssertEq, Band, Bor, Bxor, Gate, Iadd32, Rotr32, Shr32};

use crate::{
    constraint_system::{ConstraintSystem, ShiftVariant, ValueVec},
    word::Word,
};

mod gate;

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
    Inout,
    Private,
}

#[derive(Copy, Clone)]
pub struct WireData {
    kind: WireKind,
    shift: Option<(ShiftVariant, usize)>,
}

struct Shared {
    cp: ConstPool,
    n_inout: usize,
    n_witness: usize,
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
                n_witness: 0,
                n_inout: 0,
                wires: Vec::new(),
                gates: Vec::new(),
            }))),
        }
    }

    /// # Preconditions
    ///
    /// Must be called only once.
    pub fn build(&self) -> Circuit {
        let shared = self.shared.borrow_mut().take();
        let Some(shared) = shared else {
            panic!("CircuitBuilder::build called twice");
        };

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

    pub fn add_inout(&self) -> Wire {
        self.shared_mut().n_inout += 1;
        self.add_wire(WireData {
            kind: WireKind::Inout,
            shift: None,
        })
    }

    pub fn add_witness(&self) -> Wire {
        self.shared_mut().n_witness += 1;
        self.add_wire(WireData {
            kind: WireKind::Private,
            shift: None,
        })
    }

    pub fn band(&self, a: Wire, b: Wire) -> Wire {
        let gate = Band::new(self, a, b);
        let out = gate.c;
        self.emit(gate);
        out
    }

    pub fn bxor(&self, a: Wire, b: Wire) -> Wire {
        let gate = Bxor::new(self, a, b);
        let out = gate.c;
        self.emit(gate);
        out
    }

    /// Bitwise Not
    pub fn bnot(&self, a: Wire) -> Wire {
        let all_one = self.add_constant(Word::ALL_ONE);
        self.bxor(a, all_one)
    }

    pub fn bor(&self, a: Wire, b: Wire) -> Wire {
        let gate = Bor::new(self, a, b);
        let out = gate.c;
        self.emit(gate);
        out
    }

    pub fn iadd_32(&self, a: Wire, b: Wire) -> Wire {
        let gate = Iadd32::new(self, a, b);
        let out = gate.c;
        self.emit(gate);
        out
    }

    pub fn rotr_32(&self, a: Wire, n: u32) -> Wire {
        let gate = Rotr32::new(self, a, n);
        let out = gate.c;
        self.emit(gate);
        out
    }

    pub fn shr_32(&self, a: Wire, n: u32) -> Wire {
        let gate = Shr32::new(self, a, n);
        let out = gate.c;
        self.emit(gate);
        out
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

pub struct WitnessFiller<'a> {
    circuit: &'a Circuit,
    value_vec: &'a mut ValueVec,
}

impl<'a> std::ops::Index<Wire> for WitnessFiller<'a> {
    type Output = Word;

    fn index(&self, wire: Wire) -> &Self::Output {
        &self.value_vec[self.circuit.witness_index(wire)]
    }
}

impl<'a> std::ops::IndexMut<Wire> for WitnessFiller<'a> {
    fn index_mut(&mut self, wire: Wire) -> &mut Self::Output {
        &mut self.value_vec[self.circuit.witness_index(wire)]
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

    pub fn populate_wire_witness(&self, w: &mut ValueVec) {
        for (i, wire) in self.shared.wires.iter().enumerate() {
            if let WireKind::Constant(value) = wire.kind {
                w.set(self.witness_index(Wire(i)), value);
            }
        }

        use std::time::Instant;
        let start = Instant::now();

        let mut filler = WitnessFiller {
            circuit: self,
            value_vec: w,
        };

        for gate in self.shared.gates.iter() {
            gate.populate_wire_witness(&mut filler);
        }

        let elapsed = start.elapsed();
        println!("fill_witness took {} microseconds", elapsed.as_micros());
    }

    /// Builds a constraint system from this circuit.
    pub fn constraint_system(&self) -> ConstraintSystem {
        let mut cs = ConstraintSystem::new(
            self.shared.cp.pool.keys().cloned().collect::<Vec<_>>(),
            self.shared.n_inout,
            self.shared.n_witness,
        );
        for gate in self.shared.gates.iter() {
            gate.constrain(self, &mut cs);
        }
        cs
    }

    /// Returns the number of gates in this circuit.
    ///
    /// Depending on what type of gates this circuit uses, the number of constraints might be
    /// significantly larger.
    pub fn n_gates(&self) -> usize {
        self.shared.gates.len()
    }
}

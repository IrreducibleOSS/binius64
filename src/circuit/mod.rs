use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    rc::Rc,
};

use gate::{AssertEq, Band, Bor, Bxor, Gate, Iadd32, Rotr32, Shr32};

use crate::{
    constraint_system::{ConstraintSystem, ShiftVariant, Witness},
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

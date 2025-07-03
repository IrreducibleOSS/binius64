use std::{
	cell::{RefCell, RefMut},
	collections::HashMap,
	rc::Rc,
};

use gate::{Assert0, AssertEq, Band, Bor, Bxor, Gate, Iadd32, Imul, Rotr32, Shr32};

use crate::{
	constraint_system::{ConstraintSystem, ValueIndex, ValueVec},
	word::Word,
};

mod gate;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct ConstPool {
	pool: HashMap<Word, Wire>,
}

impl ConstPool {
	pub fn new() -> Self {
		ConstPool::default()
	}

	pub fn get(&self, value: Word) -> Option<Wire> {
		self.pool.get(&value).cloned()
	}

	pub fn insert(&mut self, word: Word, wire: Wire) {
		let prev = self.pool.insert(word, wire);
		assert!(prev.is_none());
	}
}

/// A wire through which a value flows in and out of gates.
///
/// The difference from `ValueIndex` is that a wire is abstract. Some wires could be moved during
/// compilation and some wires might be pruned altogether.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Wire(u32);

#[derive(Copy, Clone)]
enum WireKind {
	Constant(Word),
	Inout,
	Private,
}

#[derive(Copy, Clone)]
pub struct WireData {
	kind: WireKind,
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

impl Default for CircuitBuilder {
	fn default() -> Self {
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
}

impl CircuitBuilder {
	pub fn new() -> Self {
		CircuitBuilder::default()
	}

	/// # Preconditions
	///
	/// Must be called only once.
	pub fn build(&self) -> Circuit {
		let shared = self.shared.borrow_mut().take();
		let Some(shared) = shared else {
			panic!("CircuitBuilder::build called twice");
		};

		// `ValueVec` expects the wires to be in a certain order. Specifically:
		//
		// 1. const
		// 2. inout
		// 3. witness
		//
		// So we create a mapping between a `Wire` to the final `ValueIndex`.

		// Create a vector of (original_index, priority) pairs and sort by priority.
		let mut indexed_wires: Vec<(usize, u8)> = shared
			.wires
			.iter()
			.enumerate()
			.map(|(i, wire_data)| {
				let priority = match wire_data.kind {
					WireKind::Constant(_) => 0,
					WireKind::Inout => 1,
					WireKind::Private => 2,
				};
				(i, priority)
			})
			.collect();

		indexed_wires.sort_by_key(|(_, priority)| *priority);

		// Create the mapping from original wire index to sorted ValueIndex.
		let mut wire_mapping = vec![ValueIndex(0); shared.wires.len()];
		for (sorted_index, (original_index, _)) in indexed_wires.iter().enumerate() {
			wire_mapping[*original_index] = ValueIndex(sorted_index as u32);
		}

		Circuit {
			shared,
			wire_mapping,
		}
	}

	pub fn subcircuit(&self, name: impl Into<String>) -> CircuitBuilder {
		let name = name.into();
		CircuitBuilder {
			name: format!("{}.{name}", self.name),
			shared: self.shared.clone(),
		}
	}

	fn shared_mut(&self) -> RefMut<'_, Shared> {
		RefMut::map(self.shared.borrow_mut(), |shared| shared.as_mut().unwrap())
	}

	fn emit(&self, gate: impl Gate + 'static) {
		self.shared_mut().gates.push(Box::new(gate))
	}

	fn add_wire(&self, wire_data: WireData) -> Wire {
		let mut shared = self.shared_mut();
		let id = shared.wires.len();
		shared.wires.push(wire_data);
		Wire(id as u32)
	}

	pub fn add_constant(&self, word: Word) -> Wire {
		if let Some(wire) = self.shared_mut().cp.get(word) {
			return wire;
		}
		let wire = self.add_wire(WireData {
			kind: WireKind::Constant(word),
		});
		self.shared_mut().cp.insert(word, wire);
		wire
	}

	pub fn add_inout(&self) -> Wire {
		self.shared_mut().n_inout += 1;
		self.add_wire(WireData {
			kind: WireKind::Inout,
		})
	}

	pub fn add_witness(&self) -> Wire {
		self.shared_mut().n_witness += 1;
		self.add_wire(WireData {
			kind: WireKind::Private,
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

	/// Asserts that the given wire equals zero using a single AND constraint.
	/// This is more efficient than using assert_eq with a zero constant.
	pub fn assert_0(&self, a: Wire) {
		self.emit(Assert0::new(self, a))
	}

	/// 64-bit × 64-bit → 128-bit unsigned multiplication.
	/// Returns (hi, lo) where result = (hi << 64) | lo
	pub fn imul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let gate = Imul::new(self, a, b);
		let hi = gate.hi;
		let lo = gate.lo;
		self.emit(gate);
		(hi, lo)
	}
}

pub struct WitnessFiller<'a> {
	circuit: &'a Circuit,
	value_vec: ValueVec,
	assertion_failed: bool,
}

impl<'a> WitnessFiller<'a> {
	pub fn flag_assertion_failed(&mut self) {
		self.assertion_failed = true;
	}

	pub fn into_value_vec(self) -> ValueVec {
		self.value_vec
	}
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
	wire_mapping: Vec<ValueIndex>,
}

impl Circuit {
	/// For the given wire, returns its index in the witness vector.
	#[inline(always)]
	pub fn witness_index(&self, wire: Wire) -> ValueIndex {
		self.wire_mapping[wire.0 as usize]
	}

	pub fn new_witness_filler(&self) -> WitnessFiller<'_> {
		WitnessFiller {
			circuit: self,
			value_vec: ValueVec::new(
				self.shared.cp.pool.len(),
				self.shared.n_inout,
				self.shared.n_witness,
			),
			assertion_failed: false,
		}
	}

	pub fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		for (i, wire) in self.shared.wires.iter().enumerate() {
			if let WireKind::Constant(value) = wire.kind {
				// TODO: don't conjure up a wire.
				w[Wire(i as u32)] = value;
			}
		}

		use std::time::Instant;
		let start = Instant::now();

		for gate in self.shared.gates.iter() {
			gate.populate_wire_witness(w);
		}

		if w.assertion_failed {
			panic!("assertion failed");
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

use std::collections::HashMap;

use cranelift_entity::{PrimaryMap, SecondaryMap, entity_impl};

use crate::{compiler::gate::opcode::Opcode, word::Word};

#[derive(Default)]
pub struct ConstPool {
	pub pool: HashMap<Word, Wire>,
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
entity_impl!(Wire);

#[derive(Copy, Clone)]
pub enum WireKind {
	Constant(Word),
	Inout,
	Witness,
}

#[derive(Copy, Clone)]
pub struct WireData {
	pub kind: WireKind,
}

/// Gate ID - identifies a gate in the graph
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Gate(u32);

entity_impl!(Gate);

/// Describes a particular gate in the gate graph, it's type, input and output wires and
/// immediate parameters.
pub struct GateData {
	/// The code of operation of this gate.
	pub opcode: Opcode,

	/// The input and output wires of this gate.
	///
	/// They are laid out in the following order:
	/// - Inputs
	/// - Outputs
	///
	/// The number of input and output wires is specified by the opcode's shape.
	pub wires: Vec<Wire>,

	/// The immediate parameters of this gate.
	///
	/// The immediates contain compile-time parameters of the circuits, such as shift amounts,
	/// byte indices, etc.
	///
	/// The length of the immediates is specified by the opcode's shape.
	pub immediates: Vec<u32>,
}

impl GateData {
	pub fn inputs(&self) -> &[Wire] {
		let shape = self.opcode.shape();
		&self.wires[..shape.n_in]
	}

	pub fn outputs(&self) -> &[Wire] {
		let shape = self.opcode.shape();
		&self.wires[shape.n_in..]
	}

	/// Ensures the gate has the right shape.
	pub fn validate_shape(&self) {
		assert_eq!(self.inputs().len(), self.opcode.shape().n_in);
		assert_eq!(self.outputs().len(), self.opcode.shape().n_out);
		assert_eq!(self.immediates.len(), self.opcode.shape().n_imm);
	}
}

/// Gate graph replaces the current Shared struct
pub struct GateGraph {
	// Primary maps
	pub gates: PrimaryMap<Gate, GateData>,
	pub wires: PrimaryMap<Wire, WireData>,

	// Secondary maps for optional data
	pub assertion_names: SecondaryMap<Gate, String>,

	// Other circuit data
	pub const_pool: ConstPool,
	pub n_witness: usize,
	pub n_inout: usize,
}

impl GateGraph {
	/// Runs a validation pass ensuring all the invariants hold.
	pub fn validate(&self) {
		// Every gate holds shape.
		for gate in self.gates.values() {
			gate.validate_shape();
		}
	}

	/// Return the number of constants this graph defines.
	pub fn n_const(&self) -> usize {
		self.const_pool.pool.len()
	}
}

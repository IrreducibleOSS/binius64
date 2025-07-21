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
	/// An internal wire is a wire created inside a gate.
	Internal,
}

#[derive(Copy, Clone)]
pub struct WireData {
	pub kind: WireKind,
}

/// Gate ID - identifies a gate in the graph
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Gate(u32);

entity_impl!(Gate);

/// A handy struct that allows a more type safe destructure.
pub struct GateParam<'a> {
	pub constants: &'a [Wire],
	pub inputs: &'a [Wire],
	pub outputs: &'a [Wire],
	pub internal: &'a [Wire],
	pub imm: &'a [u32],
}

/// Describes a particular gate in the gate graph, it's type, input and output wires and
/// immediate parameters.
pub struct GateData {
	/// The code of operation of this gate.
	pub opcode: Opcode,

	/// The input and output wires of this gate.
	///
	/// They are laid out in the following order:
	///
	/// - Constants
	/// - Inputs
	/// - Outputs
	/// - Internal
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
	pub fn gate_param(&self) -> GateParam<'_> {
		let shape = self.opcode.shape();
		let start_const = 0;
		let end_const = shape.const_in.len();
		let start_input = end_const;
		let end_input = start_input + shape.n_in;
		let start_output = end_input;
		let end_output = start_output + shape.n_out;
		let start_internal = end_output;
		let end_internal = start_internal + shape.n_internal;
		GateParam {
			constants: &self.wires[start_const..end_const],
			inputs: &self.wires[start_input..end_input],
			outputs: &self.wires[start_output..end_output],
			internal: &self.wires[start_internal..end_internal],
			imm: &self.immediates,
		}
	}

	/// Ensures the gate has the right shape.
	pub fn validate_shape(&self) {
		let gate_param = self.gate_param();
		assert_eq!(gate_param.inputs.len(), self.opcode.shape().n_in);
		assert_eq!(gate_param.outputs.len(), self.opcode.shape().n_out);
		assert_eq!(gate_param.internal.len(), self.opcode.shape().n_internal);
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

	pub fn add_inout(&mut self) -> Wire {
		self.n_inout += 1;
		self.wires.push(WireData {
			kind: WireKind::Inout,
		})
	}

	pub fn add_witness(&mut self) -> Wire {
		self.n_witness += 1;
		self.wires.push(WireData {
			kind: WireKind::Witness,
		})
	}

	pub fn add_internal(&mut self) -> Wire {
		// Internal wires are treated as witnesses for allocation purposes
		self.n_witness += 1;
		self.wires.push(WireData {
			kind: WireKind::Internal,
		})
	}

	pub fn add_constant(&mut self, word: Word) -> Wire {
		if let Some(wire) = self.const_pool.get(word) {
			return wire;
		}
		let wire = self.wires.push(WireData {
			kind: WireKind::Constant(word),
		});
		self.const_pool.insert(word, wire);
		wire
	}

	/// Emits a gate with the given opcode, inputs and outputs.
	pub fn emit_gate(
		&mut self,
		opcode: Opcode,
		inputs: impl IntoIterator<Item = Wire>,
		outputs: impl IntoIterator<Item = Wire>,
	) -> Gate {
		self.emit_gate_internal(opcode, inputs, outputs, &[])
	}

	/// Emits a gate with the given opcode, inputs, outputs and a single immediate argument.
	pub fn emit_gate_imm(
		&mut self,
		opcode: Opcode,
		inputs: impl IntoIterator<Item = Wire>,
		outputs: impl IntoIterator<Item = Wire>,
		imm32: u32,
	) -> Gate {
		self.emit_gate_internal(opcode, inputs, outputs, &[imm32])
	}

	/// Creates a gate inline with the given opcode's shape parametrized with the inputs, outputs
	/// and immediates.
	///
	/// Panics if the resulting opcode shape is not valid.
	fn emit_gate_internal(
		&mut self,
		opcode: Opcode,
		inputs: impl IntoIterator<Item = Wire>,
		outputs: impl IntoIterator<Item = Wire>,
		immediates: &[u32],
	) -> Gate {
		let shape = opcode.shape();
		let mut wires: Vec<Wire> =
			Vec::with_capacity(shape.const_in.len() + shape.n_in + shape.n_out + shape.n_internal);
		for c in shape.const_in {
			wires.push(self.add_constant(*c));
		}
		wires.extend(inputs);
		wires.extend(outputs);
		for _ in 0..shape.n_internal {
			wires.push(self.add_internal());
		}
		let data = GateData {
			opcode,
			wires,
			immediates: immediates.to_vec(),
		};
		data.validate_shape();

		// Push and return the newly created gate.
		self.gates.push(data)
	}

	/// Return the number of constants this graph defines.
	pub fn n_const(&self) -> usize {
		self.const_pool.pool.len()
	}
}

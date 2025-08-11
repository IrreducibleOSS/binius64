use std::{
	cell::{RefCell, RefMut},
	rc::Rc,
};

use binius_core::{
	constraint_system::{ConstraintSystem, ValueIndex, ValueVecLayout},
	consts::MIN_WORDS_PER_SEGMENT,
	word::Word,
};
use cranelift_entity::{PrimaryMap, SecondaryMap};

use crate::compiler::{
	circuit::Circuit,
	constraint_builder::ConstraintBuilder,
	gate_graph::{ConstPool, GateGraph, WireKind},
	pathspec::{PathSpec, PathSpecTree},
};

mod gate;
use gate::Opcode;

pub mod circuit;
pub mod constraint_builder;
mod dump;
mod gate_graph;
mod pathspec;
#[cfg(test)]
mod tests;

pub use gate_graph::Wire;

pub(crate) struct Shared {
	pub(crate) graph: GateGraph,
}

/// # Clone
///
/// This is a light-weight reference. Cloning is cheap.
#[derive(Clone)]
pub struct CircuitBuilder {
	/// Current path at which this circuit builder is positioned.
	current_path: PathSpec,
	shared: Rc<RefCell<Option<Shared>>>,
}

impl Default for CircuitBuilder {
	fn default() -> Self {
		let path_spec_tree = PathSpecTree::new();
		let root = path_spec_tree.root();
		CircuitBuilder {
			current_path: root,
			shared: Rc::new(RefCell::new(Some(Shared {
				graph: GateGraph {
					gates: PrimaryMap::new(),
					wires: PrimaryMap::new(),
					assertion_names: SecondaryMap::with_default(root),
					gate_origin: SecondaryMap::with_default(root),
					const_pool: ConstPool::new(),
					path_spec_tree,
					n_witness: 0,
					n_inout: 0,
				},
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
		let graph = shared.graph;

		graph.validate();

		// `ValueVec` expects the wires to be in a certain order. Specifically:
		//
		// 1. const
		// 2. inout
		// 3. witness
		// 4. internal
		//
		// So we create a mapping between a `Wire` to the final `ValueIndex`.
		let mut wire_mapping = SecondaryMap::new();
		let total_wires = graph.wires.len();
		let mut w_const: Vec<(Wire, Word)> = Vec::with_capacity(total_wires);
		let mut w_inout: Vec<Wire> = Vec::with_capacity(total_wires);
		let mut w_witness: Vec<Wire> = Vec::with_capacity(total_wires);
		let mut w_internal: Vec<Wire> = Vec::with_capacity(total_wires);
		for (wire, wire_data) in graph.wires.iter() {
			match wire_data.kind {
				WireKind::Constant(ref value) => {
					w_const.push((wire, *value));
				}
				WireKind::Inout => w_inout.push(wire),
				WireKind::Witness => w_witness.push(wire),
				WireKind::Internal => w_internal.push(wire),
			}
		}

		let n_const = w_const.len();
		let n_inout = w_inout.len();
		let n_witness = w_witness.len();
		let n_internal = w_internal.len();

		// Sort the wires pointing to the constant section of the input value vector ascending
		// to their values.
		w_const.sort_by_key(|&(_, value)| value);

		// First, allocate the indices for the public section of the value vec. The public section
		// consists of constant wires followed by inout wires.
		//
		// Next, we align the current index to the next power of 2.
		//
		// Finally, allocate wires for witness values and internal wires.
		let mut cur_index: u32 = 0;
		let mut constants = Vec::with_capacity(n_const);
		for (wire, value) in w_const {
			wire_mapping[wire] = ValueIndex(cur_index);
			constants.push(value);
			cur_index += 1;
		}
		let offset_inout = cur_index as usize;
		for wire in w_inout {
			wire_mapping[wire] = ValueIndex(cur_index);
			cur_index += 1;
		}
		// Ensure the public section meets the minimum size requirement
		cur_index = cur_index.max(MIN_WORDS_PER_SEGMENT as u32);
		cur_index = cur_index.next_power_of_two();
		let offset_witness = cur_index as usize;
		for wire in w_witness.into_iter().chain(w_internal.into_iter()) {
			wire_mapping[wire] = ValueIndex(cur_index);
			cur_index += 1;
		}
		let total_len = (cur_index as usize).next_power_of_two();
		let value_vec_layout = ValueVecLayout {
			n_const,
			n_inout,
			n_witness,
			n_internal,
			offset_inout,
			offset_witness,
			total_len,
		};

		let mut builder = ConstraintBuilder::new();
		for (gate_id, _) in graph.gates.iter() {
			gate::constrain(gate_id, &graph, &mut builder);
		}
		let (and_constraints, mul_constraints) = builder.build(&wire_mapping);
		let cs =
			ConstraintSystem::new(constants, value_vec_layout, and_constraints, mul_constraints);

		Circuit::new(graph, cs, wire_mapping)
	}

	pub fn subcircuit(&self, name: impl Into<String>) -> CircuitBuilder {
		let nested_path = self
			.graph_mut()
			.path_spec_tree
			.extend(self.current_path, name);
		CircuitBuilder {
			current_path: nested_path,
			shared: self.shared.clone(),
		}
	}

	fn graph_mut(&self) -> RefMut<'_, GateGraph> {
		RefMut::map(self.shared.borrow_mut(), |shared| &mut shared.as_mut().unwrap().graph)
	}

	/// Creates a wire from a 64-bit word.
	///
	/// # Arguments
	///
	/// * `word` -  The word to add to the circuit.
	///
	/// # Returns
	///
	/// A `Wire` representing the constant value. The wire might be aliased because the constants
	/// are deduplicated.
	///
	/// # Cost
	///
	/// Constants have no constraint cost - they are "free" in the circuit.
	pub fn add_constant(&self, word: Word) -> Wire {
		self.graph_mut().add_constant(word)
	}

	/// Creates a constant wire from a 64-bit unsigned integer.
	///
	/// This method adds a 64-bit constant value to the circuit. The constant is stored
	/// as a `Word` and can be used in constraints and operations.
	///
	/// Constants are automatically deduplicated - multiple calls with the same value
	/// will return the same wire.
	///
	/// # Arguments
	/// * `c` - The 64-bit constant value to add to the circuit
	///
	/// # Returns
	/// A `Wire` representing the constant value that can be used in circuit operations
	pub fn add_constant_64(&self, c: u64) -> Wire {
		self.add_constant(Word(c))
	}

	/// Creates a constant wire from an 8-bit value, zero-extended to 64 bits.
	///
	/// This method takes an 8-bit unsigned integer (byte) and zero-extends it to
	/// a 64-bit value before adding it as a constant to the circuit. The resulting
	/// wire contains the byte value in the lower 8 bits and zeros in the upper 56 bits.
	/// This is commonly used for byte constants in circuits that process byte data.
	///
	/// # Arguments
	/// * `c` - The 8-bit constant value (0-255) to add to the circuit
	pub fn add_constant_zx_8(&self, c: u8) -> Wire {
		self.add_constant(Word(c as u64))
	}

	pub fn add_inout(&self) -> Wire {
		self.graph_mut().add_inout()
	}

	pub fn add_witness(&self) -> Wire {
		self.graph_mut().add_witness()
	}

	/// Adds a wire similar to `add_witness`. Internal wires are meant to designate wires that
	/// are prunable.
	fn add_internal(&self) -> Wire {
		self.graph_mut().add_internal()
	}

	pub fn band(&self, x: Wire, y: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Band, [x, y], [z]);
		z
	}

	pub fn bxor(&self, a: Wire, b: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Bxor, [a, b], [z]);
		z
	}

	/// Bitwise Not
	pub fn bnot(&self, a: Wire) -> Wire {
		let all_one = self.add_constant(Word::ALL_ONE);
		self.bxor(a, all_one)
	}

	pub fn bor(&self, a: Wire, b: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Bor, [a, b], [z]);
		z
	}

	pub fn iadd_32(&self, a: Wire, b: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Iadd32, [a, b], [z]);
		z
	}

	/// 64-bit addition with carry input and output.
	///
	/// Performs full 64-bit unsigned addition of two wires plus a carry input.
	///
	/// Returns (sum, carry_out) where sum is the 64-bit result and carry_out
	/// indicates overflow.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn iadd_cin_cout(&self, a: Wire, b: Wire, cin: Wire) -> (Wire, Wire) {
		let sum = self.add_internal();
		let cout = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IaddCinCout, [a, b, cin], [sum, cout]);
		(sum, cout)
	}

	/// 64-bit subtraction with borrow input and output.
	///
	/// Performs full 64-bit unsigned subtraction of two wires plus a borrow input.
	///
	/// Returns (diff, borrow_out) where diff is the 64-bit result and borrow_out
	/// indicates underflow.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn isub_bin_bout(&self, a: Wire, b: Wire, bin: Wire) -> (Wire, Wire) {
		let diff = self.add_internal();
		let bout = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IsubBinBout, [a, b, bin], [diff, bout]);
		(diff, bout)
	}

	pub fn rotr_32(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 32, "rotate amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotr32, [x], [z], n);
		z
	}

	pub fn rotl_64(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 64, "rotate amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotl64, [x], [z], n);
		z
	}

	pub fn shr_32(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 32, "shift amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Shr32, [x], [z], n);
		z
	}

	/// Logical left shift.
	///
	/// Shifts a 64-bit wire left by n bits, filling with zeros from the right.
	///
	/// Returns a << n
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn shl(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 64, "shift amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Shl, [a], [z], n);
		z
	}

	/// Logical right shift.
	///
	/// Shifts a 64-bit wire right by n bits, filling with zeros from the left.
	///
	/// Returns a >> n
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn shr(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 64, "shift amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Shr, [a], [z], n);
		z
	}

	/// Equality assertion.
	///
	/// Asserts that two 64-bit wires are equal.
	///
	/// Takes wires x and y and enforces x == y.
	/// If the assertion fails, the circuit will report an error with the given name.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_eq(&self, name: impl Into<String>, x: Wire, y: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertEq, [x, y], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Vector equality assertion.
	///
	/// Asserts that two arrays of 64-bit wires are equal element-wise.
	///
	/// Takes wire arrays x and y and enforces `x[i] == y[i]` for all `i`.
	/// Each element assertion is named with the base name and index.
	///
	/// # Cost
	///
	/// N AND constraints (one per element).
	pub fn assert_eq_v<const N: usize>(&self, name: impl Into<String>, x: [Wire; N], y: [Wire; N]) {
		let base_name = name.into();
		for i in 0..N {
			self.assert_eq(format!("{base_name}[{i}]"), x[i], y[i]);
		}
	}

	/// Asserts that the given wire equals zero using a single AND constraint.
	/// This is more efficient than using assert_eq with a zero constant.
	pub fn assert_0(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::Assert0, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Bitwise AND assertion with constant equals zero.
	///
	/// Asserts that the bitwise AND of a wire with a constant equals zero.
	/// This is useful for checking that specific bits are unset.
	///
	/// Takes wire a and constant c and enforces a & c = 0.
	/// If the assertion fails, the circuit will report an error with the given name.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_band_0(&self, name: impl Into<String>, x: Wire, c: Word) {
		let c = self.add_constant(c);
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertBand0, [x, c], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// 64-bit × 64-bit → 128-bit unsigned multiplication.
	/// Returns (hi, lo) where result = (hi << 64) | lo
	pub fn imul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let hi = self.add_internal();
		let lo = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Imul, [a, b], [hi, lo]);
		(hi, lo)
	}

	/// Conditional equality assertion.
	///
	/// Asserts that two 64-bit wires are equal, but only when the mask is all-1.
	/// When mask is all-0, the assertion is a no-op.
	///
	/// Takes wires a, b, and mask and enforces:
	/// - If mask is all-1: a must equal b
	/// - If mask is all-0: no constraint (assertion is ignored)
	///
	/// Pattern: AND((a ^ b), mask, 0)
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_eq_cond(&self, name: impl Into<String>, x: Wire, y: Wire, mask: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertEqCond, [x, y, mask], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Unsigned less-than comparison.
	///
	/// Compares two 64-bit wires as unsigned integers.
	///
	/// Returns:
	/// - all-1 if a < b
	/// - all-0 if a >= b
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn icmp_ult(&self, x: Wire, y: Wire) -> Wire {
		let out_mask = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IcmpUlt, [x, y], [out_mask]);
		out_mask
	}

	/// Equality comparison.
	///
	/// Compares two 64-bit wires for equality.
	///
	/// Returns:
	/// - all-1 if a == b
	/// - all-0 if a != b
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn icmp_eq(&self, x: Wire, y: Wire) -> Wire {
		let out_mask = self.add_witness();
		let all_1 = self.add_constant(Word::ALL_ONE);
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IcmpEq, [x, y, all_1], [out_mask]);
		out_mask
	}

	/// Byte extraction.
	///
	/// Extracts byte j from a 64-bit word (j=0 is least significant byte).
	///
	/// Returns the extracted byte (0-255) in the low 8 bits, with high 56 bits zero.
	///
	/// # Panics
	///
	/// Panics if j is greater than or equal to 8.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn extract_byte(&self, word: Wire, j: u32) -> Wire {
		assert!(j < 8, "byte index j={j} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::ExtractByte, [word], [z], j);
		z
	}

	/// Modular reduction.
	///
	/// Computes the remainder of the division of `dividend` by `modulus`. Returns zero if `modulus`
	/// is zero.
	///
	/// This is a hint - a deterministic computation that happens only on the prover side.
	/// The result should be additionally constrained by using bignum circuits to check that
	/// `remainder + modulus * quotient == dividend`.
	pub fn mod_reduce_hint(&self, dividend: &[Wire], modulus: &[Wire]) -> Vec<Wire> {
		let outputs = (0..modulus.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::ModReduceHint,
			dividend.iter().chain(modulus).copied(),
			outputs.iter().copied(),
			&[dividend.len(), modulus.len()],
			&[],
		);
		outputs
	}
}

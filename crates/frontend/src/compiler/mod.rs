use std::{
	array,
	cell::{RefCell, RefMut},
	rc::Rc,
};

use binius_core::{
	constraint_system::{ConstraintSystem, ValueIndex, ValueVecLayout},
	consts::MIN_WORDS_PER_SEGMENT,
	word::Word,
};
use cranelift_entity::SecondaryMap;

use crate::compiler::{
	circuit::Circuit,
	constraint_builder::ConstraintBuilder,
	gate_graph::{GateGraph, WireKind},
	pathspec::PathSpec,
};

mod gate;
use gate::Opcode;

pub mod circuit;
pub mod const_prop;
pub mod constraint_builder;
mod dump;
pub mod eval_form;
mod gate_fusion;
mod gate_graph;
pub mod hints;
mod pathspec;
#[cfg(test)]
mod tests;

pub use gate_graph::Wire;

/// Options for the compiler.
pub(crate) struct Options {
	enable_gate_fusion: bool,
	enable_constant_propagation: bool,
}

// Shut up clippy since this is just so happens to be derivable for now.
#[allow(clippy::derivable_impls)]
impl Default for Options {
	fn default() -> Self {
		Self {
			enable_gate_fusion: false,
			enable_constant_propagation: false,
		}
	}
}

impl Options {
	fn from_env() -> Self {
		// This is a very temporary solution for now.
		//
		// We do not expect those feature sets to soak here for too long neither we expect that
		// the features are going to be detected using the environment variables.
		let mut opts = Self::default();
		if std::env::var("MONBIJOU_FUSION").is_ok() {
			opts.enable_gate_fusion = true;
		}
		if std::env::var("MONBIJOU_CONSTPROP").is_ok() {
			opts.enable_constant_propagation = true;
		}
		opts
	}
}

pub(crate) struct Shared {
	pub(crate) graph: GateGraph,
	pub(crate) opts: Options,
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
		CircuitBuilder::new()
	}
}

impl CircuitBuilder {
	pub fn new() -> Self {
		let opts = Options::from_env();
		Self::with_opts(opts)
	}

	pub(crate) fn with_opts(opts: Options) -> Self {
		let graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		CircuitBuilder {
			current_path: root,
			shared: Rc::new(RefCell::new(Some(Shared { graph, opts }))),
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
		let mut graph = shared.graph;

		graph.validate();

		// Run constant propagation optimization
		if shared.opts.enable_constant_propagation {
			let replaced = const_prop::constant_propagation(&mut graph);
			if replaced > 0 {
				eprintln!("Constant propagation: replaced {} wires with constants", replaced);
			}
		}

		// `ValueVec` expects the wires to be in a certain order. Specifically:
		//
		// 1. const
		// 2. inout
		// 3. witness
		// 4. internal
		// Note: Scratch wires are NOT in ValueVec, they're handled separately
		//
		// So we create a mapping between a `Wire` to the final `ValueIndex`.
		let mut wire_mapping = SecondaryMap::new();
		let mut scratch_mapping = SecondaryMap::new();
		let total_wires = graph.wires.len();
		let mut w_const: Vec<(Wire, Word)> = Vec::with_capacity(total_wires);
		let mut w_inout: Vec<Wire> = Vec::with_capacity(total_wires);
		let mut w_witness: Vec<Wire> = Vec::with_capacity(total_wires);
		let mut w_internal: Vec<Wire> = Vec::with_capacity(total_wires);
		let mut w_scratch: Vec<Wire> = Vec::with_capacity(total_wires);
		for (wire, wire_data) in graph.wires.iter() {
			match wire_data.kind {
				WireKind::Constant(ref value) => {
					w_const.push((wire, *value));
				}
				WireKind::Inout => w_inout.push(wire),
				WireKind::Witness => w_witness.push(wire),
				WireKind::Internal => w_internal.push(wire),
				WireKind::Scratch => w_scratch.push(wire),
			}
		}

		let n_const = w_const.len();
		let n_inout = w_inout.len();
		let n_witness = w_witness.len();
		let n_internal = w_internal.len();
		let n_scratch = w_scratch.len();

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

		// Map scratch wires to scratch indices (with high bit set)
		for (scratch_index, wire) in (0_u32..).zip(w_scratch.into_iter()) {
			scratch_mapping[wire] = scratch_index | 0x8000_0000;
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
		let (mut and_constraints, mut mul_constraints) = builder.build(&wire_mapping);

		// Perform fusion if the corresponding feature flag is turned on.
		if shared.opts.enable_gate_fusion {
			let fusion =
				gate_fusion::Fusion::new(&mut and_constraints, &mut mul_constraints, &constants);
			if let Some(mut fusion) = fusion {
				let stats = fusion.run();
				eprintln!("{}", stats);
			}
		}

		let cs =
			ConstraintSystem::new(constants, value_vec_layout, and_constraints, mul_constraints);

		// Build evaluation form
		let eval_form =
			eval_form::EvalForm::build(&graph, &wire_mapping, &scratch_mapping, n_scratch);

		Circuit::new(graph, cs, wire_mapping, eval_form)
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

	/// Multi-way bitwise XOR operation.
	///
	/// Takes a variable-length slice of wires and XORs them all together.
	///
	/// # Cost
	///
	/// Potentially 1 AND constraint, though this may be optimized through gate fusion.
	pub fn bxor_multi(&self, wires: &[Wire]) -> Wire {
		assert!(!wires.is_empty(), "bxor_multi requires at least one input");

		if wires.len() == 1 {
			return wires[0];
		}

		if wires.len() == 2 {
			return self.bxor(wires[0], wires[1]);
		}

		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::BxorMulti,
			wires.iter().copied(),
			[z],
			&[wires.len()],
			&[],
		);
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

	// emulate rotl_32 using rotr_32. return right away if n == 0.
	pub fn rotl_32(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 32, "rotate amount n={n} out of range");
		if n == 0 {
			return x;
		}
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotr32, [x], [z], 32 - n);
		z
	}

	pub fn rotr_32(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 32, "rotate amount n={n} out of range");
		if n == 0 {
			return x;
		}

		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotr32, [x], [z], n);
		z
	}

	// emulate rotl using rotr. return right away if n == 0.
	pub fn rotl(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 64, "rotate amount n={n} out of range");
		if n == 0 {
			return x;
		}
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotr, [x], [z], 64 - n);
		z
	}

	pub fn rotr(&self, x: Wire, n: u32) -> Wire {
		assert!(n < 64, "rotate amount n={n} out of range");
		if n == 0 {
			return x;
		}

		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Rotr, [x], [z], n);
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

	/// Arithmetic right shift.
	///
	/// Shifts a 64-bit wire right by n bits, filling with the MSB from the left.
	///
	/// Returns a SAR n
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn sar(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 64, "shift amount n={n} out of range");
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate_imm(self.current_path, Opcode::Sar, [a], [z], n);
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
	pub fn assert_zero(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertZero, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	pub fn assert_non_zero(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertNonZero, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// asserts that the given wire, interpreted as a MSB-bool, is false.
	/// this is equivalent to asserting that x & 0x8000000000000000 == 0.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_false(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertFalse, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// asserts that the given wire, interpreted as a MSB-bool, is true.
	/// this is equivalent to asserting that x & 0x8000000000000000 == 0x8000000000000000.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_true(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertTrue, [x], []);
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

	/// Signed multiplication: 64-bit × 64-bit → 128-bit.
	/// Returns (hi, lo) where result = (hi << 64) | lo
	pub fn smul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let hi = self.add_internal();
		let lo = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Smul, [a, b], [hi, lo]);
		(hi, lo)
	}

	/// Conditional equality assertion.
	///
	/// Asserts that two 64-bit wires are equal, but only when the MSB-bool value of `cond` is true.
	/// When `cond` is MSB-bool-false, the assertion is a no-op.
	/// the non-most-significant bits of `cond` are ignored / have no impact.
	///
	/// Takes wires a, b, and cond and enforces:
	/// - If cond is MSB-bool-true: a must equal b
	/// - If cond is MSB-bool-false: no constraint (assertion is ignored)
	///
	/// Pattern: AND((a ^ b), (cond ~>> 63), 0)
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_eq_cond(&self, name: impl Into<String>, x: Wire, y: Wire, cond: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertEqCond, [x, y, cond], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Unsigned less-than comparison.
	///
	/// Compares two 64-bit wires as unsigned integers.
	///
	/// Returns:
	/// - a wire whose MSB-bool value is true if a < b
	/// - a wire whose MSB-bool value is false if a ≥ b
	///
	/// the non-most-significant bits of the output wire are undefined.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn icmp_ult(&self, x: Wire, y: Wire) -> Wire {
		let out_wire = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IcmpUlt, [x, y], [out_wire]);
		out_wire
	}

	/// Equality comparison.
	///
	/// Compares two 64-bit wires for equality.
	///
	/// Returns:
	/// - a wire whose MSB-bool value is true if a == b
	/// - a wire whose MSB-bool value is false if a != b
	///
	/// the non-most-significant bits of the output wire are undefined.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn icmp_eq(&self, x: Wire, y: Wire) -> Wire {
		let out_wire = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IcmpEq, [x, y], [out_wire]);
		out_wire
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

	/// Select operation.
	///
	/// Returns `t` if MSB(cond) is 1, otherwise returns `f`.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn select(&self, cond: Wire, t: Wire, f: Wire) -> Wire {
		let out = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Select, [cond, t, f], [out]);
		out
	}

	/// BigUint division.
	///
	/// Returns `(quotient, remainder)` of the division of `dividend` by `divisor`.
	///
	/// This is a hint - a deterministic computation that happens only on the prover side.
	/// The result should be additionally constrained by using bignum circuits to check that
	/// `remainder + divisor * quotient == dividend`.
	pub fn biguint_divide_hint(
		&self,
		dividend: &[Wire],
		divisor: &[Wire],
	) -> (Vec<Wire>, Vec<Wire>) {
		let quotient = (0..dividend.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let remainder = (0..divisor.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::BigUintDivideHint,
			dividend.iter().chain(divisor).copied(),
			quotient.iter().chain(&remainder).copied(),
			&[dividend.len(), divisor.len()],
			&[],
		);

		(quotient, remainder)
	}

	/// Modular exponentiation.
	///
	/// Computes `(base^exp) % modulus`.
	/// This is a hint - a deterministic computation that happens only on the prover side.
	/// The result should be additionally constrained using bignum circuits.
	pub fn biguint_mod_pow_hint(&self, base: &[Wire], exp: &[Wire], modulus: &[Wire]) -> Vec<Wire> {
		let modpow = (0..modulus.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::BigUintModPowHint,
			base.iter().chain(exp).chain(modulus).copied(),
			modpow.iter().copied(),
			&[base.len(), exp.len(), modulus.len()],
			&[],
		);

		modpow
	}

	/// Modular inverse.
	///
	/// Computes the modular inverse of `base` modulo `modulus`.
	/// Returns a pair `(quotient, inverse)` where both numbers are Bézout coefficients when
	/// `base` and `modulus` are coprime. Both numbers are set to zero if `gcd(base, modulus) > 1`.
	///
	/// This is a hint - a deterministic computation that happens only on the prover side.
	/// The result should be additionally constrained by using bignum circuits to check that
	/// `base * inverse = 1 + quotient * modulus`.
	pub fn mod_inverse_hint(&self, base: &[Wire], modulus: &[Wire]) -> (Vec<Wire>, Vec<Wire>) {
		let quotient = (0..modulus.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let inverse = (0..modulus.len())
			.map(|_| self.add_internal())
			.collect::<Vec<_>>();

		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::ModInverseHint,
			base.iter().chain(modulus).copied(),
			quotient.iter().chain(&inverse).copied(),
			&[base.len(), modulus.len()],
			&[],
		);

		(quotient, inverse)
	}

	/// Secp256k1 endomorphism split
	///
	/// The curve has an endomorphism `λ (x, y) = (βx, y)` where `λ³=1 (mod n)`
	/// and `β³=1 (mod p)` (`n` being the scalar field modulus and `p` coordinate field one).
	///
	/// For a 256-bit scalar `k` it is possible to split it into `k1` and `k2` such that
	/// `k1 + λ k2 = k (mod n)` and both `k1` and `k2` are no farther than `2^128` from zero.
	///
	/// The `k` scalar is represented by four 64-bit limbs in little endian order. The return value
	/// is quadruple of `(k1_neg, k2_neg, k1_abs, k2_abs)` where `k1_neg` and `k2_neg` are
	/// MSB-bools indicating whether `k1_abs` or `k2_abs`, respectively, should be negated.
	/// `k1_abs` and `k2_abs` are at most 128 bits and are represented with two 64-bit limbs.
	/// When `k` cannot be represented in this way (any valid scalar can, so it has to be modulus
	/// or above), both `k1_abs` and `k2_abs` are assigned zero values.
	///
	/// This is a hint - a deterministic computation that happens only on the prover side.
	/// The result should be additionally constrained by using bignum circuits to check that
	/// `k1 + λ k2 = k (mod n)`.
	pub fn secp256k1_endomorphism_split_hint(
		&self,
		k: &[Wire],
	) -> (Wire, Wire, [Wire; 2], [Wire; 2]) {
		assert_eq!(k.len(), 4);

		let k1_neg = self.add_internal();
		let k2_neg = self.add_internal();

		let k1_abs = array::from_fn(|_| self.add_internal());
		let k2_abs = array::from_fn(|_| self.add_internal());

		let mut graph = self.graph_mut();
		graph.emit_gate_generic(
			self.current_path,
			Opcode::Secp256k1EndosplitHint,
			k.iter().copied(),
			[k1_neg, k2_neg]
				.iter()
				.chain(&k1_abs)
				.chain(&k2_abs)
				.copied(),
			&[],
			&[],
		);

		(k1_neg, k2_neg, k1_abs, k2_abs)
	}
}

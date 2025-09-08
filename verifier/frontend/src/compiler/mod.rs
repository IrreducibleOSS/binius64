// Copyright 2025 Irreducible Inc.
use std::{
	array,
	cell::{RefCell, RefMut},
	rc::Rc,
};

use binius_core::{constraint_system::ConstraintSystem, word::Word};

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
mod value_vec_alloc;

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
			enable_gate_fusion: true,
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

/// Circuit builder for constructing zero-knowledge proof circuits.
///
/// `CircuitBuilder` is your primary interface for constructing circuits in the Binius64
/// proof system. Think of it as a specialized compiler that lets you express computations
/// in a way that can be efficiently proven in zero-knowledge.
///
/// # The Circuit Abstraction
///
/// A circuit in Binius64 represents a computation as a directed graph where data flows
/// through gates via "wires". Each wire carries a 64-bit word, and gates transform their
/// input wires to produce output wires. When you call methods like [`band`] or
/// [`iadd_32`], you're adding gates to this graph and getting back handles
/// to the output wires.
///
/// The beauty of this abstraction is that you write imperative-looking code, but behind
/// the scenes, the builder is constructing a declarative constraint system. When you
/// finally call [`build`], this graph is compiled into the AND and MUL constraints that
/// the proof system actually operates on.
///
/// # Wires and Values
///
/// Wires are abstract handles to 64-bit values that will exist during proof generation.
/// They don't contain actual values during circuit construction — they're more like
/// promises of values to come. There are several types of wires, each serving a
/// different role in the proof system:
///
/// **Constants** are values known at compile time. These are "free" in terms of
/// constraints because both prover and verifier know them. When you call
/// [`add_constant`], you're embedding that value directly into the
/// circuit.
///
/// **Public inputs/outputs** (created with [`add_inout`](Self::add_inout)) are values that will be
/// visible to both the prover and verifier. These form part of the statement being
/// proven—for example, the hash output in a hash preimage proof.
///
/// **Private witnesses** (created with [`add_witness`](Self::add_witness)) are the secret values
/// known only to the prover. These are the values you're proving knowledge of without
/// revealing them—like the preimage in a hash proof or a private key in a signature
/// verification.
///
/// Internal wires are created automatically when gates produce outputs. You don't
/// create these directly; they emerge from operations like [`iadd_32`].
///
/// # The MSB-Boolean Convention
///
/// Throughout this API, you'll encounter operations that produce or consume boolean
/// values. Rather than using a separate boolean type, Binius64 adopts an unusual
/// convention: booleans are encoded in the most significant bit (bit 63) of a 64-bit
/// word. When the MSB is 1, the value is considered "true"; when it's 0, it's "false".
/// The remaining 63 bits are ignored — they're "don't care" values.
///
/// This convention allows compiler to exploit a more efficient arithmitization for Binius64.
///
/// # Understanding Costs
///
/// Not all operations are created equal in terms of proof complexity. Here's the
/// hierarchy of costs you should keep in mind when optimizing circuits:
///
/// **AND constraints** form the baseline unit of cost. Operations like bitwise AND
/// and comparisons generate one or two AND constraints. These are your primary
/// optimization target.
///
/// **MUL constraints** (64-bit multiplication) are the heavyweight operations, costing
/// roughly 3-4 times more than AND constraints. Use them judiciously.
///
/// **Committing values** also has a cost—each committed word (public inputs/outputs
/// and witnesses) adds to the proof size, though less than a full AND constraint.
///
/// **Linear operations** ([`bxor`](Self::bxor) and shifts) are the interesting case. They generate
/// what we call "virtual" linear constraints — constraints that our underlying proof
/// system doesn't directly support. During compilation, these must either be:
/// - Absorbed into nearby non-linear gates through gate fusion (making them nearly free), or
/// - Materialized as actual AND constraints
///
/// The gate fusion optimization intelligently inlines XOR expressions and compatible
/// shifts into gates that already require AND constraints. However, it can't inline
/// everything — incompatible operations (like a right shift into a left shift) and
/// heuristic limits mean some linear operations will still materialize as constraints.
/// In practice, XORs are very cheap (think of them as a small fraction of an AND),
/// while shifts are slightly more expensive but still economical.
///
/// The individual method documentation specifies exact costs, but this hierarchy helps
/// you reason about circuit efficiency: minimize ANDs and MULs, use XORs liberally,
/// and be mindful of committed values.
///
/// # Building and Compilation
///
/// The builder uses a reference-counted pointer internally, making it cheap to clone.
/// When you call [`subcircuit`], you get a new builder that adds gates
/// to the same underlying graph but with hierarchical naming for better debugging.
///
/// The compilation process (triggered by [`build`]) is where the magic happens. It
/// validates your circuit, runs optimization passes like constant propagation and gate
/// fusion, and produces the final constraint system. Note that [`build`] consumes the
/// builder's internal state—you can only call it once per builder instance.
///
/// [`add_constant`]: Self::add_constant
/// [`add_inout`]: Self::add_inout
/// [`add_witness`]: Self::add_witness
/// [`band`]: Self::band
/// [`build`]: Self::build
/// [`iadd_32`]: Self::iadd_32
/// [`subcircuit`]: Self::subcircuit
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

#[warn(missing_docs)]
impl CircuitBuilder {
	/// Create a new circuit builder with default options.
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

	/// Returns the circuit built by this builder.
	///
	/// Note that cloning the circuit builder only clones the reference and as such is treated
	/// as a shallow copy.
	///
	/// # Preconditions
	///
	/// Must be called only once.
	pub fn build(&self) -> Circuit {
		let all_one = self.add_constant(Word::ALL_ONE);
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

		let mut builder = ConstraintBuilder::new();
		for (gate_id, _) in graph.gates.iter() {
			gate::constrain(gate_id, &graph, &mut builder);
		}

		// Perform fusion if the corresponding feature flag is turned on.
		if shared.opts.enable_gate_fusion {
			gate_fusion::run_pass(&mut builder, all_one);
		}

		let constrained_wires = builder.mark_used_wires();

		// Allocate a place for each wire in the value vec layout.
		//
		// This gives us mappings from wires into the value indices, as well as the constant
		// portion of the value vec.
		let value_vec_alloc::Assignment {
			wire_mapping,
			value_vec_layout,
			constants,
		} = {
			let mut value_vec_alloc = value_vec_alloc::Alloc::new();
			for (wire, wire_data) in graph.wires.iter() {
				match wire_data.kind {
					WireKind::Constant(ref value) => {
						value_vec_alloc.add_constant(wire, *value);
					}
					WireKind::Inout => value_vec_alloc.add_inout(wire),
					WireKind::Witness => value_vec_alloc.add_witness(wire),
					WireKind::Internal | WireKind::Scratch => {
						// Unlike inout and witness those two are not declared by the user and thus
						// are not required to appear in the value vec.
						//
						// Therefore, we ignore the initial designation internal <=> scratch and
						// instead we look whether a wire is referenced in the constraint system
						// or not. If it is referenced then we declare it as internal and put into
						// the private section (witness). If it's not referenced we declare it as
						// a scratch value.
						//
						// Note that the concept of wire kind outlived it's lifetime and should be
						// reworked. This is left for the future.
						if constrained_wires.contains(wire) {
							value_vec_alloc.add_internal(wire);
						} else {
							value_vec_alloc.add_scratch(wire);
						}
					}
				}
			}
			value_vec_alloc.into_assignment()
		};
		let (and_constraints, mul_constraints) = builder.build(&wire_mapping, all_one);

		let cs =
			ConstraintSystem::new(constants, value_vec_layout, and_constraints, mul_constraints);
		if cfg!(debug_assertions) {
			// Validate that the resulting constraint system has a good shape.
			cs.validate().unwrap();
		}

		// Build evaluation form
		let eval_form = eval_form::EvalForm::build(&graph, &wire_mapping);

		Circuit::new(graph, cs, wire_mapping, eval_form)
	}

	/// Creates a reference to the same underlying circuit builder that is namespaced to the
	/// given name.
	///
	/// This is useful for creating subcircuits within a larger circuit.
	///
	/// Note that this is the same builder instance, but with a different namespace, and that means
	/// calling [`Self::build`] on the returned builder is going to build the whole circuit.
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
	/// * `word` -  The word to add to the circuit.
	///
	/// # Returns
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

	/// Creates a public input/output wire.
	///
	/// Public wires form part of the proof statement and are visible to both prover and verifier.
	/// They are committed in the public section of the value vector alongside constants.
	///
	/// The wire must be manually assigned a value using [`WitnessFiller`] before circuit
	/// evaluation.
	///
	/// [`WitnessFiller`]: crate::compiler::circuit::WitnessFiller
	pub fn add_inout(&self) -> Wire {
		self.graph_mut().add_inout()
	}

	/// Creates a private input wire.
	///
	/// Private wires contain secret values known only to the prover. They are placed in the
	/// private section of the value vector and are not revealed to the verifier.
	///
	/// The wire must be manually assigned a value using [`WitnessFiller`] before circuit
	/// evaluation.
	///
	/// [`WitnessFiller`]: crate::compiler::circuit::WitnessFiller
	pub fn add_witness(&self) -> Wire {
		self.graph_mut().add_witness()
	}

	/// Adds a wire similar to [`Self::add_witness`]. Internal wires are meant to designate wires
	/// that are prunable.
	fn add_internal(&self) -> Wire {
		self.graph_mut().add_internal()
	}

	/// Bitwise AND.
	///
	/// Returns z = x & y
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn band(&self, x: Wire, y: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Band, [x, y], [z]);
		z
	}

	/// Bitwise XOR.
	///
	/// Returns z = x ^ y
	///
	/// # Cost
	///
	/// 1 linear constraint.
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
	/// Returns z = i ^ j ^ k ^ ...
	///
	/// # Cost
	///
	/// 1 linear constraint.
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
	///
	/// Returns z = ~x
	///
	/// # Cost
	///
	/// 1 linear constraint.
	pub fn bnot(&self, a: Wire) -> Wire {
		let all_one = self.add_constant(Word::ALL_ONE);
		self.bxor(a, all_one)
	}

	/// Bitwise OR.
	///
	/// Returns z = x | y
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn bor(&self, a: Wire, b: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Bor, [a, b], [z]);
		z
	}

	/// Fused AND-XOR operation.
	///
	/// Computes (x & y) ^ w in a single gate.
	///
	/// Returns z = (x & y) ^ w
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn fax(&self, x: Wire, y: Wire, w: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Fax, [x, y, w], [z]);
		z
	}

	/// 32-bit integer addition.
	///
	/// Performs a 32-bit integer addition of two wires. The high bits of the result are discarded.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn iadd_32(&self, a: Wire, b: Wire) -> Wire {
		let z = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Iadd32, [a, b], [z]);
		z
	}

	/// 64-bit integer addition with carry input and output.
	///
	/// Performs full 64-bit unsigned addition of two wires plus a carry input.
	///
	/// Returns `(sum, carry_out)` where:
	///
	/// - `sum` is the 64-bit result and
	/// - `carry_out` is a 64-bit word where every bit position with a carry is set to 1.
	///
	/// # Cost
	///
	/// - 1 AND constraint,
	/// - 1 linear constraint.
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
	/// Returns `(diff, borrow_out)` where:
	///
	/// - `diff` is the 64-bit result and
	/// - `borrow_out` is a 64-bit word where every bit position with a borrow is set to 1.
	///
	/// # Cost
	///
	/// - 1 AND constraint,
	/// - 1 linear constraint.
	pub fn isub_bin_bout(&self, a: Wire, b: Wire, bin: Wire) -> (Wire, Wire) {
		let diff = self.add_internal();
		let bout = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::IsubBinBout, [a, b, bin], [diff, bout]);
		(diff, bout)
	}

	/// 32-bit rotate left.
	///
	/// Rotates the lower 32 bits left by n positions. Bits shifted out on the left
	/// wrap around to the right. The upper 32 bits are zeroed.
	///
	/// Returns `(x & 0xFFFFFFFF) rotated left by n`
	///
	/// # Panics
	///
	/// Panics if n ≥ 32.
	///
	/// # Cost
	///
	/// 1 AND constraint (0 if n = 0).
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

	/// 32-bit rotate right.
	///
	/// Rotates the lower 32 bits right by n positions. Bits shifted out on the right
	/// wrap around to the left. The upper 32 bits are zeroed.
	///
	/// Returns `(x & 0xFFFFFFFF) rotated right by n`
	///
	/// # Panics
	///
	/// Panics if n ≥ 32.
	///
	/// # Cost
	///
	/// 1 AND constraint (0 if n = 0).
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

	/// 64-bit rotate left.
	///
	/// Rotates a 64-bit value left by n positions. Bits shifted out on the left
	/// wrap around to the right.
	///
	/// Returns `x rotated left by n`
	///
	/// # Panics
	///
	/// Panics if n ≥ 64.
	///
	/// # Cost
	///
	/// 1 AND constraint (0 if n = 0).
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

	/// 64-bit rotate right.
	///
	/// Rotates a 64-bit value right by n positions. Bits shifted out on the right
	/// wrap around to the left.
	///
	/// Returns `x rotated right by n`
	///
	/// # Panics
	///
	/// Panics if n ≥ 64.
	///
	/// # Cost
	///
	/// 1 AND constraint (0 if n = 0).
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

	/// 32-bit logical right shift.
	///
	/// Shifts the lower 32 bits right by n positions, filling with zeros from the left.
	/// The upper 32 bits are zeroed.
	///
	/// Returns `(x & 0xFFFFFFFF) >> n`
	///
	/// # Panics
	///
	/// Panics if n ≥ 32.
	///
	/// # Cost
	///
	/// 1 AND constraint.
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

	/// Asserts that the given wire equals zero.
	///
	/// Enforces that `x = 0` exactly. Every bit of the 64-bit value must be zero.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_zero(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertZero, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Asserts that the given wire is not zero.
	///
	/// Enforces that `x ≠ 0`. At least one bit must be non-zero.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_non_zero(&self, name: impl Into<String>, x: Wire) {
		let mut graph = self.graph_mut();
		let gate = graph.emit_gate(self.current_path, Opcode::AssertNonZero, [x], []);
		let path_spec = graph.path_spec_tree.extend(self.current_path, name);
		graph.assertion_names[gate] = path_spec;
	}

	/// Asserts that the given wire's MSB (Most Significant Bit) is 0.
	///
	/// This treats the wire as an MSB-boolean where:
	/// - MSB = 0 → false (assertion passes)
	/// - MSB = 1 → true (assertion fails)
	///
	/// All bits except the MSB are ignored. This is commonly used with comparison
	/// results which return MSB-boolean values.
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

	/// Asserts that the given wire's MSB (Most Significant Bit) is 1.
	///
	/// This treats the wire as an MSB-boolean where:
	/// - MSB = 1 → true (assertion passes)
	/// - MSB = 0 → false (assertion fails)
	///
	/// All bits except the MSB are ignored. This is commonly used with comparison
	/// results which return MSB-boolean values.
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
	///
	/// Performs unsigned integer multiplication of two 64-bit values, producing
	/// a 128-bit result split into high and low 64-bit words.
	///
	/// Returns `(hi, lo)` where `a * b = (hi << 64) | lo`
	///
	/// # Cost
	///
	/// - 1 MUL constraint,
	/// - 1 AND constraint (for security check).
	pub fn imul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let hi = self.add_internal();
		let lo = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Imul, [a, b], [hi, lo]);
		(hi, lo)
	}

	/// 64-bit × 64-bit → 128-bit signed multiplication.
	///
	/// Performs signed integer multiplication of two 64-bit values, producing
	/// a 128-bit result split into high and low 64-bit words. Correctly handles
	/// two's complement signed integers including overflow cases.
	///
	/// Returns `(hi, lo)` where the signed multiplication result equals `(hi << 64) | lo`.
	/// The high word is sign-extended based on the product's sign.
	///
	/// # Cost
	///
	/// - 1 MUL constraint
	/// - 7 AND constraints (2 for sign corrections, 4 for modular additions, 1 for low word
	///   equality).
	pub fn smul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let hi = self.add_internal();
		let lo = self.add_internal();
		let mut graph = self.graph_mut();
		graph.emit_gate(self.current_path, Opcode::Smul, [a, b], [hi, lo]);
		(hi, lo)
	}

	/// Conditional equality assertion.
	///
	/// Asserts that two 64-bit wires are equal only when a condition is true (MSB = 1).
	/// When the condition is false (MSB = 0), no constraint is enforced.
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
	/// - 1 AND constraint,
	/// - 1 linear constraint.
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
	/// - 1 AND constraint,
	/// - 1 linear constraint.
	pub fn extract_byte(&self, word: Wire, j: u32) -> Wire {
		assert!(j < 8, "byte index j={j} out of range");

		// To extract the byte j out of 8 we want to generate a mask that will zero out all bits
		// except the ones in the j-th byte and then shift it to the rightmost position. We used
		// to have a gate for this but it's not necessary.
		let shift = j * 8;
		let mask = self.add_constant_64(0xff << shift);
		let masked = self.band(word, mask);
		self.shr(masked, shift)
	}

	/// Select operation.
	///
	/// Returns `t` if `cond` is true (MSB-bit set), otherwise returns `f`.
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

//! Circuit representation in the evaluation form.
//!
//! The main purpose of the evaluation form is to evaluate and assign the intermediate witness
//! values. Those are also referred as internal wires.

mod builder;
mod interpreter;

use binius_core::{ValueIndex, ValueVec, Word};
pub use builder::BytecodeBuilder;
use cranelift_entity::SecondaryMap;
pub use interpreter::{AssertionFailure, ExecutionContext};

use crate::compiler::{
	circuit::PopulateError,
	gate,
	gate_graph::{GateGraph, Wire},
	hints::HintRegistry,
	RawConstraint,
};

/// Compiled evaluation form for circuit witness computation
pub struct EvalForm {
	/// Compiled bytecode instructions
	bytecode: Vec<u8>,
	/// Number of scratch registers needed
	n_scratch: usize,
	/// Number of evaluation instructions
	n_eval_insn: usize,
	/// Registered hint handlers
	hint_registry: HintRegistry,
}

impl EvalForm {
	/// Build the evaluation form from the gate graph
	pub(crate) fn build(
		gate_graph: &GateGraph,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
		scratch_mapping: &SecondaryMap<Wire, u32>,
		n_scratch: usize,
		raw_constraints: &[RawConstraint],
	) -> Self {
		let mut builder = BytecodeBuilder::new();
		let mut hint_registry = HintRegistry::new();

		// Combined wire to register mapping
		let wire_to_reg = |wire: Wire| -> u32 {
			// IMPORTANT: SecondaryMap returns default value (0) for non-existent keys!
			// We need to check if the value has the high bit set to know if it's a real scratch
			// register
			let scratch_reg = scratch_mapping[wire];
			if scratch_reg & 0x8000_0000 != 0 {
				// This is a real scratch register (high bit is set)
				scratch_reg // Already has high bit set
			} else if let Some(&ValueIndex(idx)) = wire_mapping.get(wire) {
				idx // ValueVec index
			} else {
				panic!("Wire {wire:?} not mapped");
			}
		};

		// Build bytecode for each gate
		for (gate_id, data) in gate_graph.gates.iter() {
			gate::emit_gate_bytecode(
				gate_id,
				data,
				gate_graph,
				&mut builder,
				wire_to_reg,
				&mut hint_registry,
			);
		}
		
		// Process raw constraints - register their witness computations as hints
		// Note: We can't clone the witness_fn from Box<dyn Fn>, so we need a different approach
		// For now, we'll skip witness computation for raw constraints and rely on gates
		// TODO: Implement proper witness computation for raw constraints
		// This would require refactoring how witness functions are stored (e.g., using Arc<dyn Fn>)
		let _ = raw_constraints; // Suppress unused warning

		let (bytecode, n_eval_insn) = builder.finalize();

		EvalForm {
			bytecode,
			n_scratch,
			n_eval_insn,
			hint_registry,
		}
	}

	/// Execute the evaluation form to populate witness values
	pub fn evaluate(&self, value_vec: &mut ValueVec) -> Result<(), PopulateError> {
		let scratch = vec![Word::ZERO; self.n_scratch];

		let mut interpreter = interpreter::Interpreter::new(&self.bytecode, &self.hint_registry);
		interpreter.run_with_value_vec(value_vec, scratch)?;

		Ok(())
	}

	/// Get the number of evaluation instructions
	pub fn n_eval_insn(&self) -> usize {
		self.n_eval_insn
	}
}

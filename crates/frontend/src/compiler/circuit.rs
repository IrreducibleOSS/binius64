use std::{error, fmt};

use binius_core::{
	constraint_system::{ConstraintSystem, ValueIndex, ValueVec},
	word::Word,
};
use cranelift_entity::SecondaryMap;

use crate::compiler::{
	eval_form::EvalForm,
	gate_graph::{GateGraph, Wire},
	pathspec::PathSpec,
};

const MAX_ASSERTION_MESSAGES: usize = 100;

/// Error returned when populating wire witness fails due to assertion failures.
#[derive(Debug)]
pub struct PopulateError {
	/// List of assertion failure messages (limited to MAX_ASSERTION_MESSAGES).
	pub messages: Vec<String>,
	/// Total count of assertion failures (may exceed messages.len()).
	pub total_count: usize,
}

impl fmt::Display for PopulateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		writeln!(f, "assertions failed:")?;
		for message in &self.messages {
			writeln!(f, "{message}")?;
		}
		if self.total_count > self.messages.len() {
			writeln!(f, "(Some assertions are omitted. Total: {})", self.total_count)?;
		}
		Ok(())
	}
}

impl error::Error for PopulateError {}

pub struct WitnessFiller<'a> {
	pub(crate) circuit: &'a Circuit,
	pub(crate) value_vec: ValueVec,
	pub(crate) ignore_assertions: bool,
	pub(crate) assertion_failed_message_vec: Vec<(PathSpec, String)>,
	pub(crate) assertion_failed_count: usize,
}

impl<'a> WitnessFiller<'a> {
	pub fn flag_assertion_failed(
		&mut self,
		path_spec: PathSpec,
		condition: impl FnOnce(&mut Self) -> String,
	) {
		if self.ignore_assertions {
			return;
		}
		self.assertion_failed_count += 1;
		if self.assertion_failed_message_vec.len() < MAX_ASSERTION_MESSAGES {
			let assertion_message = condition(self);
			self.assertion_failed_message_vec
				.push((path_spec, assertion_message));
		}
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
	gate_graph: GateGraph,
	constraint_system: ConstraintSystem,
	wire_mapping: SecondaryMap<Wire, ValueIndex>,
	eval_form: EvalForm,
}

impl Circuit {
	/// Creates a new circuit with the given shared data and wire mapping. Only used during building
	/// by the circuit builder.
	pub(super) fn new(
		gate_graph: GateGraph,
		constraint_system: ConstraintSystem,
		wire_mapping: SecondaryMap<Wire, ValueIndex>,
		eval_form: EvalForm,
	) -> Self {
		assert!(constraint_system.value_vec_layout.validate().is_ok());
		Self {
			gate_graph,
			constraint_system,
			wire_mapping,
			eval_form,
		}
	}

	/// For the given wire, returns its index in the witness vector.
	#[inline(always)]
	pub fn witness_index(&self, wire: Wire) -> ValueIndex {
		self.wire_mapping[wire]
	}

	pub fn new_witness_filler(&self) -> WitnessFiller<'_> {
		WitnessFiller {
			circuit: self,
			value_vec: ValueVec::new(self.constraint_system.value_vec_layout.clone()),
			assertion_failed_message_vec: Vec::new(),
			assertion_failed_count: 0,
			ignore_assertions: false,
		}
	}

	/// Populates non-input values (wires) in the witness.
	///
	/// Specifically, this will evaluate the circuit gate-by-gate and save the results in the
	/// witness vector.
	///
	/// This function expects that the input wires are already filled. The input wires are
	///
	/// - [`super::CircuitBuilder::add_inout`],
	/// - [`super::CircuitBuilder::add_witness`] that were not created by the gates,
	///
	/// The wires created by [`super::CircuitBuilder::add_constant`] (and its convenience methods)
	/// are automatically populated by this function as well.
	///
	/// # Errors
	///
	/// In case the circuit is not satisfiable (any assertion fails), this function will return
	/// an error with a list of assertion failure messages.
	pub fn populate_wire_witness(&self, w: &mut WitnessFiller) -> Result<(), PopulateError> {
		// Fill the constant part from the witness.
		for (index, constant) in self.constraint_system.constants.iter().enumerate() {
			w.value_vec.set(index, *constant);
		}

		// Execute the evaluation form - it modifies the ValueVec in place
		self.eval_form.evaluate(&mut w.value_vec)?;

		Ok(())
	}

	/// Returns the constraint system for this circuit.
	pub fn constraint_system(&self) -> &ConstraintSystem {
		&self.constraint_system
	}

	/// Returns the number of gates in this circuit.
	///
	/// Depending on what type of gates this circuit uses, the number of constraints might be
	/// significantly larger.
	pub fn n_gates(&self) -> usize {
		self.gate_graph.gates.len()
	}

	/// Returns the number of evaluation instructions in this circuit.
	pub fn n_eval_insn(&self) -> usize {
		self.eval_form.n_eval_insn()
	}

	/// Returns a string with a JSON dump that is useful to profile the circuit.
	pub fn simple_json_dump(&self) -> String {
		crate::compiler::dump::dump_composition(&self.gate_graph)
	}
}

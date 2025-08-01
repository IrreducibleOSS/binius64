use std::{error, fmt};

use cranelift_entity::SecondaryMap;

use super::{Shared, gate};
use crate::{
	compiler::{
		gate_graph::{Wire, WireKind},
		pathspec::PathSpec,
	},
	constraint_system::{
		AndConstraint, ConstraintSystem, MulConstraint, ShiftVariant, ShiftedValueIndex,
		ValueIndex, ValueVec, ValueVecLayout,
	},
	word::Word,
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
	shared: Shared,
	value_vec_layout: ValueVecLayout,
	wire_mapping: SecondaryMap<Wire, ValueIndex>,
}

impl Circuit {
	/// Creates a new circuit with the given shared data and wire mapping. Only used during building
	/// by the circuit builder.
	pub(super) fn new(
		shared: Shared,
		value_vec_layout: ValueVecLayout,
		wire_mapping: SecondaryMap<Wire, ValueIndex>,
	) -> Self {
		value_vec_layout.validate();
		Self {
			shared,
			value_vec_layout,
			wire_mapping,
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
			value_vec: ValueVec::new(self.value_vec_layout.clone()),
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
		// Fill constants
		for (wire, wire_data) in self.shared.graph.wires.iter() {
			if let WireKind::Constant(value) = wire_data.kind {
				w[wire] = value;
			}
		}

		// Evaluate all gates
		for (gate_id, _) in self.shared.graph.gates.iter() {
			gate::evaluate(gate_id, &self.shared.graph, w);
		}

		if !w.ignore_assertions && w.assertion_failed_count > 0 {
			// There were some assertions, we should resolve the assertion locations.
			return Err(PopulateError {
				messages: w
					.assertion_failed_message_vec
					.iter()
					.map(|(path_spec, message)| {
						let mut full_assertion_msg = String::with_capacity(message.len() + 128);
						self.shared
							.graph
							.path_spec_tree
							.stringify(*path_spec, &mut full_assertion_msg);
						full_assertion_msg.push_str(" failed: ");
						full_assertion_msg.push_str(message);
						full_assertion_msg
					})
					.collect(),
				total_count: w.assertion_failed_count,
			});
		}

		Ok(())
	}

	/// Builds a constraint system from this circuit.
	pub fn constraint_system(&self) -> ConstraintSystem {
		let mut cs = ConstraintSystem::new(
			self.shared
				.graph
				.const_pool
				.pool
				.keys()
				.cloned()
				.collect::<Vec<_>>(),
			self.value_vec_layout.clone(),
		);
		for (gate_id, _) in self.shared.graph.gates.iter() {
			gate::constrain(gate_id, &self.shared.graph, self, &mut cs);
		}

		let zero_wire = self
			.shared
			.graph
			.const_pool
			.get(Word::ZERO)
			.expect("every circuit has the zero constant... i think");
		let zero_value_index = self.wire_mapping[zero_wire];

		// Helper to pad constraint vectors to next power of 2 with zero dummy constraints
		let zero_operand = vec![ShiftedValueIndex {
			value_index: zero_value_index,
			shift_variant: ShiftVariant::Sll,
			amount: 0,
		}];

		// Pad AND constraints: 0 & 0 = 0
		let and_target_len = cs.and_constraints.len().next_power_of_two();
		cs.and_constraints
			.resize_with(and_target_len, || AndConstraint {
				a: zero_operand.clone(),
				b: zero_operand.clone(),
				c: zero_operand.clone(),
			});

		// Pad MUL constraints: 0 * 0 = 0 with hi=0, lo=0
		let mul_target_len = cs.mul_constraints.len().next_power_of_two();
		cs.mul_constraints
			.resize_with(mul_target_len, || MulConstraint {
				a: zero_operand.clone(),
				b: zero_operand.clone(),
				hi: zero_operand.clone(),
				lo: zero_operand.clone(),
			});

		cs
	}

	/// Returns the number of gates in this circuit.
	///
	/// Depending on what type of gates this circuit uses, the number of constraints might be
	/// significantly larger.
	pub fn n_gates(&self) -> usize {
		self.shared.graph.gates.len()
	}

	/// Returns a string with a JSON dump that is useful to profile the circuit.
	pub fn simple_json_dump(&self) -> String {
		crate::compiler::dump::dump_composition(&self.shared.graph)
	}
}

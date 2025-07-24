//! Uniqueness Constraint Propagation
//!
//! This module implements uniqueness propagation techniques inspired by the
//! Picus paper <https://eprint.iacr.org/2023/512.pdf>.

use std::collections::{HashMap, VecDeque};

use crate::{
	compiler::{Wire, circuit::Circuit},
	constraint_system::{ConstraintSystem, ShiftVariant, ShiftedValueIndex, ValueIndex},
	word::Word,
};

/// Represents the uniqueness status of a value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniquenessStatus {
	/// Value is uniquely determined by constraints
	Unique,
	/// Uniqueness status is unknown
	Unknown,
}

/// Information about how a value's uniqueness was determined
#[derive(Debug, Clone)]
pub enum UniquenessReason {
	/// Value is a constant
	Constant(Word),
	/// Value is uniquely determined by an AND constraint
	AndConstraint { constraint_idx: usize },
	/// Value is uniquely determined by a MUL constraint
	MulConstraint { constraint_idx: usize },
	/// Value is propagated from other unique values
	Propagated { from_values: Vec<ValueIndex> },
}

/// Uniqueness propagator that analyzes constraint systems
#[derive(Debug)]
pub struct UniquenessPropagator {
	/// Map from value index to its uniqueness status
	uniqueness: HashMap<ValueIndex, UniquenessStatus>,
	/// Map from value index to the reason for its uniqueness
	reasons: HashMap<ValueIndex, UniquenessReason>,
	/// Queue of values whose uniqueness changed (for propagation)
	propagation_queue: VecDeque<ValueIndex>,
}

impl Default for UniquenessPropagator {
	fn default() -> Self {
		Self::new()
	}
}

impl UniquenessPropagator {
	pub fn new() -> Self {
		Self {
			uniqueness: HashMap::new(),
			reasons: HashMap::new(),
			propagation_queue: VecDeque::new(),
		}
	}

	/// Analyze a constraint system and propagate uniqueness information
	pub fn analyze(&mut self, cs: &ConstraintSystem) {
		self.mark_constants_unique(cs);
		self.initial_constraint_analysis(cs);
		self.propagate_uniqueness(cs);
	}

	/// Mark all constant values as unique
	fn mark_constants_unique(&mut self, cs: &ConstraintSystem) {
		for (idx, &value) in cs.constants.iter().enumerate() {
			let value_idx = ValueIndex(idx as u32);
			self.uniqueness.insert(value_idx, UniquenessStatus::Unique);
			self.reasons
				.insert(value_idx, UniquenessReason::Constant(value));
			self.propagation_queue.push_back(value_idx);
		}
	}

	/// Initial analysis of constraints to find unique values
	fn initial_constraint_analysis(&mut self, cs: &ConstraintSystem) {
		// Analyze AND constraints
		for (idx, constraint) in cs.and_constraints.iter().enumerate() {
			self.analyze_and_constraint(constraint, idx);
		}

		// Analyze MUL constraints
		for (idx, constraint) in cs.mul_constraints.iter().enumerate() {
			self.analyze_mul_constraint(constraint, idx);
		}
	}

	/// Analyze an AND constraint for uniqueness
	fn analyze_and_constraint(
		&mut self,
		constraint: &crate::constraint_system::AndConstraint,
		idx: usize,
	) {
		// AND constraint: A & B ^ C = 0
		// If two of {A, B, C} are unique, the third is unique

		let a_unique = self.is_operand_unique(&constraint.a);
		let b_unique = self.is_operand_unique(&constraint.b);
		let c_unique = self.is_operand_unique(&constraint.c);

		// Count unique operands
		let unique_count = [a_unique, b_unique, c_unique]
			.iter()
			.filter(|&&x| x)
			.count();

		if unique_count >= 2 {
			if !a_unique {
				self.mark_operand_unique(
					&constraint.a,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			}
			if !b_unique {
				self.mark_operand_unique(
					&constraint.b,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			}
			if !c_unique {
				self.mark_operand_unique(
					&constraint.c,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			}
		}

		// Special cases for uniqueness
		self.check_and_special_cases(constraint, idx);
	}

	/// Check special cases for AND constraints
	fn check_and_special_cases(
		&mut self,
		constraint: &crate::constraint_system::AndConstraint,
		idx: usize,
	) {
		// Case 1: If A or B is 0, then C must be 0 (unique)
		if self.is_operand_zero(&constraint.a) || self.is_operand_zero(&constraint.b) {
			self.mark_operand_unique(
				&constraint.c,
				UniquenessReason::AndConstraint {
					constraint_idx: idx,
				},
			);
		}

		// Case 2: If A is all 1s, then B = C (propagate uniqueness)
		if self.is_operand_all_ones(&constraint.a) {
			if self.is_operand_unique(&constraint.b) && !self.is_operand_unique(&constraint.c) {
				self.mark_operand_unique(
					&constraint.c,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			} else if self.is_operand_unique(&constraint.c)
				&& !self.is_operand_unique(&constraint.b)
			{
				self.mark_operand_unique(
					&constraint.b,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			}
		}

		// Case 3: If B is all 1s, then A = C (propagate uniqueness)
		if self.is_operand_all_ones(&constraint.b) {
			if self.is_operand_unique(&constraint.a) && !self.is_operand_unique(&constraint.c) {
				self.mark_operand_unique(
					&constraint.c,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			} else if self.is_operand_unique(&constraint.c)
				&& !self.is_operand_unique(&constraint.a)
			{
				self.mark_operand_unique(
					&constraint.a,
					UniquenessReason::AndConstraint {
						constraint_idx: idx,
					},
				);
			}
		}
	}

	/// Analyze a MUL constraint for uniqueness
	fn analyze_mul_constraint(
		&mut self,
		constraint: &crate::constraint_system::MulConstraint,
		idx: usize,
	) {
		// MUL constraint: A * B = (HI << 64) | LO
		// If A and B are unique, then HI and LO are unique
		if self.is_operand_unique(&constraint.a) && self.is_operand_unique(&constraint.b) {
			self.mark_operand_unique(
				&constraint.hi,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
			self.mark_operand_unique(
				&constraint.lo,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
		}

		// Special cases
		self.check_mul_special_cases(constraint, idx);
	}

	/// Check special cases for MUL constraints
	fn check_mul_special_cases(
		&mut self,
		constraint: &crate::constraint_system::MulConstraint,
		idx: usize,
	) {
		// Case 1: If A or B is 0, then HI and LO must be 0 (unique)
		if self.is_operand_zero(&constraint.a) || self.is_operand_zero(&constraint.b) {
			self.mark_operand_unique(
				&constraint.hi,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
			self.mark_operand_unique(
				&constraint.lo,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
		}

		// Case 2: If A is 1, then B = LO and HI = 0
		if self.is_operand_one(&constraint.a) {
			if self.is_operand_unique(&constraint.b) {
				self.mark_operand_unique(
					&constraint.lo,
					UniquenessReason::MulConstraint {
						constraint_idx: idx,
					},
				);
			} else if self.is_operand_unique(&constraint.lo) {
				self.mark_operand_unique(
					&constraint.b,
					UniquenessReason::MulConstraint {
						constraint_idx: idx,
					},
				);
			}
			self.mark_operand_unique(
				&constraint.hi,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
		}

		// Case 3: If B is 1, then A = LO and HI = 0
		if self.is_operand_one(&constraint.b) {
			if self.is_operand_unique(&constraint.a) {
				self.mark_operand_unique(
					&constraint.lo,
					UniquenessReason::MulConstraint {
						constraint_idx: idx,
					},
				);
			} else if self.is_operand_unique(&constraint.lo) {
				self.mark_operand_unique(
					&constraint.a,
					UniquenessReason::MulConstraint {
						constraint_idx: idx,
					},
				);
			}
			self.mark_operand_unique(
				&constraint.hi,
				UniquenessReason::MulConstraint {
					constraint_idx: idx,
				},
			);
		}
	}

	/// Propagate uniqueness information through the constraint system
	fn propagate_uniqueness(&mut self, cs: &ConstraintSystem) {
		while let Some(changed_value) = self.propagation_queue.pop_front() {
			self.repropagate_through_constraints(cs, changed_value);
		}
	}

	/// Re-propagate through constraints when a value's uniqueness changes
	fn repropagate_through_constraints(&mut self, cs: &ConstraintSystem, value: ValueIndex) {
		// Check all AND constraints
		for (idx, constraint) in cs.and_constraints.iter().enumerate() {
			if self.operand_contains_value(&constraint.a, value)
				|| self.operand_contains_value(&constraint.b, value)
				|| self.operand_contains_value(&constraint.c, value)
			{
				self.analyze_and_constraint(constraint, idx);
			}
		}

		// Check all MUL constraints
		for (idx, constraint) in cs.mul_constraints.iter().enumerate() {
			if self.operand_contains_value(&constraint.a, value)
				|| self.operand_contains_value(&constraint.b, value)
				|| self.operand_contains_value(&constraint.hi, value)
				|| self.operand_contains_value(&constraint.lo, value)
			{
				self.analyze_mul_constraint(constraint, idx);
			}
		}
	}

	/// Check if an operand is unique (all values in it are unique)
	fn is_operand_unique(&self, operand: &[ShiftedValueIndex]) -> bool {
		operand
			.iter()
			.all(|svi| self.uniqueness.get(&svi.value_index) == Some(&UniquenessStatus::Unique))
	}

	/// Check if an operand is known to be zero
	fn is_operand_zero(&self, operand: &[ShiftedValueIndex]) -> bool {
		operand.len() == 1
			&& operand[0].shift_variant == ShiftVariant::Sll
			&& operand[0].amount == 0
			&& matches!(
				self.reasons.get(&operand[0].value_index),
				Some(UniquenessReason::Constant(w)) if *w == Word::ZERO
			)
	}

	/// Check if an operand is known to be one
	fn is_operand_one(&self, operand: &[ShiftedValueIndex]) -> bool {
		operand.len() == 1
			&& operand[0].shift_variant == ShiftVariant::Sll
			&& operand[0].amount == 0
			&& matches!(
				self.reasons.get(&operand[0].value_index),
				Some(UniquenessReason::Constant(w)) if *w == Word::ONE
			)
	}

	/// Check if an operand is known to be all ones
	fn is_operand_all_ones(&self, operand: &[ShiftedValueIndex]) -> bool {
		operand.len() == 1
			&& operand[0].shift_variant == ShiftVariant::Sll
			&& operand[0].amount == 0
			&& matches!(
				self.reasons.get(&operand[0].value_index),
				Some(UniquenessReason::Constant(w)) if *w == Word::ALL_ONE
			)
	}

	/// Check if an operand contains a specific value
	fn operand_contains_value(&self, operand: &[ShiftedValueIndex], value: ValueIndex) -> bool {
		operand.iter().any(|svi| svi.value_index == value)
	}

	/// Mark an operand as unique
	fn mark_operand_unique(&mut self, operand: &[ShiftedValueIndex], reason: UniquenessReason) {
		for svi in operand {
			if self.uniqueness.get(&svi.value_index) != Some(&UniquenessStatus::Unique) {
				self.uniqueness
					.insert(svi.value_index, UniquenessStatus::Unique);
				self.reasons.insert(svi.value_index, reason.clone());
				self.propagation_queue.push_back(svi.value_index);
			}
		}
	}

	/// Get the uniqueness status of a value
	pub fn get_uniqueness(&self, value: ValueIndex) -> UniquenessStatus {
		self.uniqueness
			.get(&value)
			.copied()
			.unwrap_or(UniquenessStatus::Unknown)
	}

	/// Get the uniqueness status of a wire (requires Circuit for wire mapping)
	pub fn get_wire_uniqueness(&self, circuit: &Circuit, wire: Wire) -> UniquenessStatus {
		let value_idx = circuit.witness_index(wire);
		self.get_uniqueness(value_idx)
	}

	/// Get all unique values
	pub fn get_unique_values(&self) -> Vec<ValueIndex> {
		self.uniqueness
			.iter()
			.filter(|&(_, &status)| status == UniquenessStatus::Unique)
			.map(|(&idx, _)| idx)
			.collect()
	}
}

/// Check if a constraint system has unique witness assignment
pub fn check_witness_uniqueness(cs: &ConstraintSystem) -> UniquenessCheckResult<'_> {
	let mut propagator = UniquenessPropagator::new();
	propagator.analyze(cs);

	// Count unique witnesses (excluding constants and public inputs)
	let const_count = cs.constants.len();
	let inout_count = cs.value_vec_layout.n_inout;
	let witness_start = const_count + inout_count;
	let witness_end = witness_start + cs.value_vec_layout.n_witness;

	let mut unique_witnesses = 0;

	for idx in witness_start..witness_end {
		let value_idx = ValueIndex(idx as u32);
		match propagator.get_uniqueness(value_idx) {
			UniquenessStatus::Unique => unique_witnesses += 1,
			UniquenessStatus::Unknown => {}
		}
	}

	UniquenessCheckResult {
		total_witnesses: cs.value_vec_layout.n_witness,
		unique_witnesses,
		uniqueness_ratio: unique_witnesses as f64 / cs.value_vec_layout.n_witness as f64,
		propagator,
		circuit: None,
	}
}

/// Check if a circuit has unique witness assignment (allows wire lookups)
pub fn process_circuit_uniqueness(circuit: &Circuit) -> UniquenessCheckResult<'_> {
	let cs = circuit.constraint_system();
	let mut propagator = UniquenessPropagator::new();
	propagator.analyze(&cs);

	// Count unique witnesses (excluding constants and public inputs)
	let const_count = cs.constants.len();
	let inout_count = cs.value_vec_layout.n_inout;
	let witness_start = const_count + inout_count;
	let witness_end = witness_start + cs.value_vec_layout.n_witness;

	let mut unique_witnesses = 0;

	for idx in witness_start..witness_end {
		let value_idx = ValueIndex(idx as u32);
		match propagator.get_uniqueness(value_idx) {
			UniquenessStatus::Unique => unique_witnesses += 1,
			UniquenessStatus::Unknown => {}
		}
	}

	UniquenessCheckResult {
		total_witnesses: cs.value_vec_layout.n_witness,
		unique_witnesses,
		uniqueness_ratio: unique_witnesses as f64 / cs.value_vec_layout.n_witness as f64,
		propagator,
		circuit: Some(circuit),
	}
}

pub struct UniquenessCheckResult<'a> {
	pub total_witnesses: usize,
	pub unique_witnesses: usize,
	pub uniqueness_ratio: f64,
	pub propagator: UniquenessPropagator,
	/// Reference to the circuit (if analysis was done via check_circuit_uniqueness)
	pub circuit: Option<&'a Circuit>,
}

impl<'a> UniquenessCheckResult<'a> {
	/// Check if a wire is unique (only available if circuit reference is present)
	pub fn is_wire_unique(&self, wire: Wire) -> Option<UniquenessStatus> {
		self.circuit
			.map(|c| self.propagator.get_wire_uniqueness(c, wire))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::compiler::CircuitBuilder;

	#[test]
	fn test_constant_uniqueness() {
		let builder = CircuitBuilder::new();

		let zero = builder.add_constant(Word::ZERO);
		let one = builder.add_constant(Word::ONE);
		let all_one = builder.add_constant(Word::ALL_ONE);

		let w1 = builder.add_witness();
		let w2 = builder.add_witness();

		// Add constraints that should propagate uniqueness
		// AND constraint: w1 & all_one = w2, and w2 = zero
		let w1_and_all_one = builder.band(w1, all_one);
		builder.assert_eq("w1_and_all_one_eq_w2", w1_and_all_one, w2);
		builder.assert_eq("w2_eq_zero", w2, zero);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		assert_eq!(
			result.is_wire_unique(zero),
			Some(UniquenessStatus::Unique),
			"zero constant should be unique"
		);
		assert_eq!(
			result.is_wire_unique(one),
			Some(UniquenessStatus::Unique),
			"one constant should be unique"
		);
		assert_eq!(
			result.is_wire_unique(all_one),
			Some(UniquenessStatus::Unique),
			"all_one constant should be unique"
		);

		// Check witness uniqueness
		assert_eq!(
			result.is_wire_unique(w2),
			Some(UniquenessStatus::Unique),
			"w2 should be unique (constrained to zero)"
		);
	}

	#[test]
	fn test_and_constraint_propagation() {
		let builder = CircuitBuilder::new();

		let zero = builder.add_constant(Word::ZERO);
		let all_one = builder.add_constant(Word::ALL_ONE);

		let a = builder.add_witness();
		let b = builder.add_witness();
		let c = builder.add_witness();

		// AND constraint: all_one & b ^ c = 0
		// Since all_one & b = b, this means b ^ c = 0, so b = c
		// If c is unique, b should be unique too
		let b_and_all_one = builder.band(all_one, b);
		let b_xor_c = builder.bxor(b_and_all_one, c);
		builder.assert_0("b_xor_c_eq_0", b_xor_c);

		// Make c equal to zero (unique)
		builder.assert_eq("c_eq_zero", c, zero);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		assert_eq!(
			result.is_wire_unique(c),
			Some(UniquenessStatus::Unique),
			"c should be unique (constrained to zero)"
		);

		assert_eq!(
			result.is_wire_unique(b),
			Some(UniquenessStatus::Unique),
			"b should be unique (propagated from c via AND constraint)"
		);

		// 'a' has no constraints, so should be unknown
		assert_eq!(
			result.is_wire_unique(a),
			Some(UniquenessStatus::Unknown),
			"a should have unknown uniqueness"
		);
	}

	#[test]
	fn test_mul_constraint_propagation() {
		let builder = CircuitBuilder::new();

		let one = builder.add_constant(Word::ONE);
		let two = builder.add_constant(Word(2));

		let a = builder.add_witness();
		let b = builder.add_witness();

		// MUL constraint: one * two = (0 << 64) | a
		// This should make a = 2 (unique)
		let (lo, hi) = builder.imul(one, two);
		builder.assert_eq("lo_eq_a", lo, a);
		builder.assert_0("hi_eq_0", hi);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		assert_eq!(
			result.is_wire_unique(a),
			Some(UniquenessStatus::Unique),
			"a should be unique (constrained to multiplication result)"
		);

		assert_eq!(
			result.is_wire_unique(lo),
			Some(UniquenessStatus::Unique),
			"lo should be unique (result of 1 * 2)"
		);

		assert_eq!(
			result.is_wire_unique(hi),
			Some(UniquenessStatus::Unique),
			"hi should be unique (constrained to zero)"
		);

		// 'b' has no constraints
		assert_eq!(
			result.is_wire_unique(b),
			Some(UniquenessStatus::Unknown),
			"b should have unknown uniqueness"
		);
	}

	#[test]
	fn test_wire_uniqueness_lookup() {
		let builder = CircuitBuilder::new();

		let _zero = builder.add_constant(Word::ZERO);
		let five = builder.add_constant(Word(5));

		let unique_wire = builder.add_witness();
		let unknown_wire = builder.add_witness();
		let derived_wire = builder.add_witness();

		builder.assert_eq("unique_wire_eq_5", unique_wire, five);

		builder.assert_eq("derived_eq_unique", derived_wire, unique_wire);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		assert_eq!(
			result.is_wire_unique(unique_wire),
			Some(UniquenessStatus::Unique),
			"unique_wire should be unique"
		);

		assert_eq!(
			result.is_wire_unique(derived_wire),
			Some(UniquenessStatus::Unique),
			"derived_wire should be unique (propagated)"
		);

		assert_eq!(
			result.is_wire_unique(unknown_wire),
			Some(UniquenessStatus::Unknown),
			"unknown_wire should have unknown uniqueness"
		);

		// Can also use the propagator directly with circuit
		assert_eq!(
			result.propagator.get_wire_uniqueness(&circuit, unique_wire),
			UniquenessStatus::Unique
		);

		println!("Wire uniqueness test passed!");
	}

	#[test]
	fn test_complex_circuit_analysis() {
		let builder = CircuitBuilder::new();

		let zero = builder.add_constant(Word::ZERO);
		let one = builder.add_constant(Word::ONE);
		let ten = builder.add_constant(Word(10));

		let input_a = builder.add_witness();
		let input_b = builder.add_witness();

		builder.assert_eq("input_a_eq_10", input_a, ten);

		let sum = builder.bxor(input_a, input_b);

		let (prod_lo, prod_hi) = builder.imul(input_a, input_b);

		let is_b_zero = builder.icmp_eq(input_b, zero);
		let conditional_result = builder.band(is_b_zero, one);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		assert_eq!(
			result.is_wire_unique(input_a),
			Some(UniquenessStatus::Unique),
			"input_a should be unique (constrained to 10)"
		);
		let wires_to_check = vec![
			(zero, "zero"),
			(one, "one"),
			(ten, "ten"),
			(input_a, "input_a"),
			(input_b, "input_b"),
			(sum, "sum"),
			(prod_lo, "prod_lo"),
			(prod_hi, "prod_hi"),
			(is_b_zero, "is_b_zero"),
			(conditional_result, "conditional_result"),
		];

		println!("\nWire uniqueness summary:");
		for (wire, name) in wires_to_check {
			let status = result.is_wire_unique(wire).unwrap();
			println!("  {name}: {status:?}");
		}
	}

	#[test]
	fn test_circuit_with_non_unique_witnesses() {
		let builder = CircuitBuilder::new();
		let zero = builder.add_constant(Word::ZERO);
		let one = builder.add_constant(Word::ONE);

		let free_witness = builder.add_witness(); // This has NO constraints
		let constrained_witness = builder.add_witness();

		builder.assert_eq("constrained_eq_one", constrained_witness, one);

		let derived = builder.bxor(free_witness, zero);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);

		let wires_to_check = vec![
			(zero, "zero (constant)"),
			(one, "one (constant)"),
			(free_witness, "free_witness (no constraints)"),
			(constrained_witness, "constrained_witness (equals one)"),
			(derived, "derived (free_witness ^ zero)"),
		];

		for (wire, name) in wires_to_check {
			let status = result.is_wire_unique(wire).unwrap();
			println!("  {name}: {status:?}");
		}
	}

	#[test]
	fn test_witness_with_multiple_valid_assignments() {
		let builder = CircuitBuilder::new();

		// A circuit where witnesses have multiple valid assignments
		// We'll use a quadratic constraint: x * x = 4
		// This has two solutions: x = 2 and x = -2 (in modular arithmetic)
		let four = builder.add_constant(Word(4));
		let zero = builder.add_constant(Word::ZERO);

		let x = builder.add_witness();
		let (x_squared_lo, x_squared_hi) = builder.imul(x, x);
		builder.assert_eq("x_squared_eq_4", x_squared_lo, four);
		builder.assert_eq("x_squared_hi_eq_0", x_squared_hi, zero);

		// Add another example: y | z = 15
		// This has many solutions: (y=1, z=15), (y=3, z=13), (y=5, z=11), etc.
		let fifteen = builder.add_constant(Word(15));
		let y = builder.add_witness();
		let z = builder.add_witness();

		let y_or_z = builder.bor(y, z);
		builder.assert_eq("y_or_z_eq_15", y_or_z, fifteen);

		let derived = builder.bxor(x, y);
		let circuit = builder.build();

		let result = process_circuit_uniqueness(&circuit);

		let wires_to_check = vec![
			(four, "four (constant)"),
			(zero, "zero (constant)"),
			(fifteen, "fifteen (constant)"),
			(x, "x (where x*x = 4)"),
			(x_squared_lo, "x_squared_lo"),
			(y, "y (where y|z = 15)"),
			(z, "z (where y|z = 15)"),
			(y_or_z, "y_or_z"),
			(derived, "derived (x ^ y)"),
		];

		println!("\nUnique wires:");
		for (wire, name) in wires_to_check {
			let status = result.is_wire_unique(wire).unwrap();
			println!("  {name}: {status:?}");
		}
	}

	#[test]
	fn test_minimal_quadratic_constraint() {
		let builder = CircuitBuilder::new();

		// Minimal test: just x * x = 4
		let four = builder.add_constant(Word(4));
		let zero = builder.add_constant(Word::ZERO);

		let x = builder.add_witness();

		// x * x = 4
		let (lo, hi) = builder.imul(x, x);
		builder.assert_eq("x_squared_lo_eq_4", lo, four);
		builder.assert_eq("x_squared_hi_eq_0", hi, zero);

		let circuit = builder.build();
		let result = process_circuit_uniqueness(&circuit);
		assert_eq!(
			result.is_wire_unique(x),
			Some(UniquenessStatus::Unknown),
			"x should be Unknown since x² = 4 has two solutions"
		);
	}
}

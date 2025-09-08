// Copyright 2025 Irreducible Inc.
use std::fmt;

use binius_core::{ConstraintSystem, Operand, ShiftedValueIndex};

use crate::compiler::circuit::Circuit;

/// Various stats of a circuit that affect the prover performance.
pub struct CircuitStat {
	/// Number of gates in the circuit.
	pub n_gates: usize,
	/// Number of instructions in the evaluation form of circuit.
	///
	/// Directly proportional to performance of witness filling.
	pub n_eval_insn: usize,
	/// Number of AND constraints in the circuit.
	///
	/// Affects performance of AND reduction.
	pub n_and_constraints: usize,
	/// Number of MUL constraints in the circuit.
	///
	/// Affects performance of intmul reduction phase.
	pub n_mul_constraints: usize,
	/// Number of distinct shifted value indices in the circuit.
	///
	/// A single use of any value is counted here. Additionally, every use of a value with a
	/// distinct shift type and amount is also counted here.
	///
	/// Affects performance of shift reduction phase.
	pub distinct_shifted_value_indices: usize,
	/// Length of the value vector.
	///
	/// Affects performance of committing.
	pub value_vec_len: usize,
	/// Number of constant values used by the circuit.
	pub n_const: usize,
	/// Number of public input values in the circuit.
	pub n_inout: usize,
	/// Number of private input values in the circuit.
	pub n_witness: usize,
	/// Number of internal values in the circuit.
	///
	/// Internal values are values produced by gates.
	pub n_internal: usize,
	/// Number of scratch values in the circuit.
	///
	/// Those values are not committed, those only exist during witness generation.
	pub n_scratch: usize,
}

impl CircuitStat {
	/// Creates a new `CircuitStat` instance by collecting statistics from the given circuit.
	pub fn collect(circuit: &Circuit) -> Self {
		let cs = circuit.constraint_system();
		Self {
			n_gates: circuit.n_gates(),
			n_eval_insn: circuit.n_eval_insn(),
			n_and_constraints: cs.n_and_constraints(),
			n_mul_constraints: cs.n_mul_constraints(),
			value_vec_len: cs.value_vec_layout.committed_total_len,
			distinct_shifted_value_indices: distinct_shifted_value_indices(cs),
			n_const: cs.value_vec_layout.n_const,
			n_inout: cs.value_vec_layout.n_inout,
			n_witness: cs.value_vec_layout.n_witness,
			n_internal: cs.value_vec_layout.n_internal,
			n_scratch: cs.value_vec_layout.n_scratch,
		}
	}
}

impl fmt::Display for CircuitStat {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "Number of gates: {}", self.n_gates)?;
		writeln!(f, "Number of evaluation instructions: {}", self.n_eval_insn)?;
		writeln!(f, "Number of AND constraints: {}", self.n_and_constraints)?;
		writeln!(f, "Number of MUL constraints: {}", self.n_mul_constraints)?;
		writeln!(
			f,
			"Number of distinct shifted value indices: {}",
			self.distinct_shifted_value_indices
		)?;
		writeln!(f, "Length of value vec: {}", self.value_vec_len)?;
		writeln!(f, "  Constants: {}", self.n_const)?;
		writeln!(f, "  Inout: {}", self.n_inout)?;
		writeln!(f, "  Witness: {}", self.n_witness)?;
		writeln!(f, "  Internal: {}", self.n_internal)?;
		writeln!(f, "  Scratch: {}", self.n_scratch)?;
		Ok(())
	}
}

fn distinct_shifted_value_indices(cs: &ConstraintSystem) -> usize {
	use std::collections::HashSet;
	let mut indices = HashSet::new();
	for and in &cs.and_constraints {
		visit_operand(&and.a, &mut indices);
		visit_operand(&and.b, &mut indices);
		visit_operand(&and.c, &mut indices);
	}
	for mul in &cs.mul_constraints {
		visit_operand(&mul.a, &mut indices);
		visit_operand(&mul.b, &mut indices);
		visit_operand(&mul.lo, &mut indices);
		visit_operand(&mul.hi, &mut indices);
	}
	return indices.len();

	fn visit_operand(operand: &Operand, indices: &mut HashSet<ShiftedValueIndex>) {
		for term in operand {
			indices.insert(*term);
		}
	}
}

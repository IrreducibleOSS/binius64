use std::fmt;

use crate::compiler::circuit::Circuit;

/// Various stats of a circuit that affect the prover performance.
pub struct CircuitStat {
	pub n_gates: usize,
	pub n_eval_insn: usize,
	pub n_and_constraints: usize,
	pub n_mul_constraints: usize,
	pub value_vec_len: usize,
	pub n_const: usize,
	pub n_inout: usize,
	pub n_witness: usize,
	pub n_internal: usize,
}

impl CircuitStat {
	pub fn collect(circuit: &Circuit) -> Self {
		let cs = circuit.constraint_system();
		Self {
			n_gates: circuit.n_gates(),
			n_eval_insn: circuit.n_eval_insn(),
			n_and_constraints: cs.n_and_constraints(),
			n_mul_constraints: cs.n_mul_constraints(),
			value_vec_len: cs.value_vec_layout.committed_total_len,
			n_const: cs.value_vec_layout.n_const,
			n_inout: cs.value_vec_layout.n_inout,
			n_witness: cs.value_vec_layout.n_witness,
			n_internal: cs.value_vec_layout.n_internal,
		}
	}
}

impl fmt::Display for CircuitStat {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "Number of gates: {}", self.n_gates)?;
		writeln!(f, "Number of evaluation instructions: {}", self.n_eval_insn)?;
		writeln!(f, "Number of AND constraints: {}", self.n_and_constraints)?;
		writeln!(f, "Number of MUL constraints: {}", self.n_mul_constraints)?;
		writeln!(f, "Length of value vec: {}", self.value_vec_len)?;
		writeln!(f, "  Constants: {}", self.n_const)?;
		writeln!(f, "  Inout: {}", self.n_inout)?;
		writeln!(f, "  Witness: {}", self.n_witness)?;
		writeln!(f, "  Internal: {}", self.n_internal)?;
		Ok(())
	}
}

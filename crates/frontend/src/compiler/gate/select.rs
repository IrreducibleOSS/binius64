//! Select operation.
//!
//! Returns `out = MSB(cond) ? b : a`.
//!
//! # Algorithm
//!
//! The gate inspects the MSB (Most Significant Bit) of the condition value to select between
//! two inputs. This is computed using a single AND constraint with the formula:
//! `out = a ⊕ ((cond >> 63) ∧ (b ⊕ a))`
//!
//! The arithmetic shift right by 63 broadcasts the MSB to all bit positions, creating
//! an all-ones mask if MSB=1 or all-zeros if MSB=0.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(cond >> 63) ∧ (b ⊕ a) = out ⊕ a`

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, sar, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 3,
		n_out: 1,
		n_internal: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [a, b, cond] = inputs else { unreachable!() };
	let [out] = outputs else { unreachable!() };

	// Constraint: Select operation
	//
	// (cond >> 63) ∧ (b ⊕ a) = out ⊕ a
	builder
		.and()
		.a(sar(*cond, 63))
		.b(xor2(*b, *a))
		.c(xor2(*out, *a))
		.build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [a, b, cond] = inputs else { unreachable!() };
	let [out] = outputs else { unreachable!() };

	builder.emit_select(wire_to_reg(*out), wire_to_reg(*a), wire_to_reg(*b), wire_to_reg(*cond));
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;
	use rand::{RngCore, SeedableRng, rngs::StdRng};

	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	#[test]
	fn test_select_basic() {
		// Build a circuit with Select gate
		let builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let cond = builder.add_inout();
		let actual = builder.select(a, b, cond);
		let expected = builder.add_inout();
		builder.assert_eq("select", actual, expected);
		let circuit = builder.build();

		// Test specific cases
		let test_cases = [
			// (a, b, cond, expected)
			(
				0x1234567890ABCDEF_u64,
				0xFEDCBA0987654321_u64,
				0x7FFFFFFFFFFFFFFF_u64,
				0x1234567890ABCDEF_u64,
			), // MSB=0, select a
			(
				0x1234567890ABCDEF_u64,
				0xFEDCBA0987654321_u64,
				0x8000000000000000_u64,
				0xFEDCBA0987654321_u64,
			), // MSB=1, select b
			(
				0x0000000000000000_u64,
				0xFFFFFFFFFFFFFFFF_u64,
				0xFFFFFFFFFFFFFFFF_u64,
				0xFFFFFFFFFFFFFFFF_u64,
			), // All ones cond, select b
			(
				0xAAAAAAAAAAAAAAAA_u64,
				0x5555555555555555_u64,
				0x0000000000000000_u64,
				0xAAAAAAAAAAAAAAAA_u64,
			), // Zero cond, select a
		];

		for (a_val, b_val, cond_val, expected_val) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[a] = Word(a_val);
			w[b] = Word(b_val);
			w[cond] = Word(cond_val);
			w[expected] = Word(expected_val);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_select_random() {
		// Build a circuit with Select gate
		let builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let cond = builder.add_inout();
		let actual = builder.select(a, b, cond);
		let expected = builder.add_inout();
		builder.assert_eq("select", actual, expected);
		let circuit = builder.build();

		// Test with random values
		let mut rng = StdRng::seed_from_u64(42);
		for _ in 0..1000 {
			let mut w = circuit.new_witness_filler();
			let a_val = rng.next_u64();
			let b_val = rng.next_u64();
			let cond_val = rng.next_u64();

			// Expected value based on MSB of condition
			let expected_val = if (cond_val as i64) < 0 { b_val } else { a_val };

			w[a] = Word(a_val);
			w[b] = Word(b_val);
			w[cond] = Word(cond_val);
			w[expected] = Word(expected_val);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}
}

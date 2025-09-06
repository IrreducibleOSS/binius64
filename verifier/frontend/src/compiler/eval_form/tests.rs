// Copyright 2025 Irreducible Inc.

use binius_core::{ValueIndex, ValueVec, ValueVecLayout, word::Word};

use crate::compiler::{
	circuit::PopulateError,
	eval_form::{
		BytecodeBuilder,
		interpreter::{ExecutionContext, Interpreter},
	},
	hints::HintRegistry,
};

/// Test harness for interpreter tests that makes them much more concise
struct InterpreterTest {
	builder: BytecodeBuilder,
	values: Vec<Word>,
}

impl InterpreterTest {
	fn new() -> Self {
		Self {
			builder: BytecodeBuilder::new(),
			values: Vec::new(),
		}
	}

	/// Set the witness values that will be used in the test
	fn with_values(mut self, values: Vec<Word>) -> Self {
		self.values = values;
		self
	}

	/// Emit an assert_eq_cond instruction
	fn assert_eq_cond(mut self, cond: u32, x: u32, y: u32) -> Self {
		self.builder.emit_assert_eq_cond(cond, x, y, 1);
		self
	}

	/// Run the test and expect success (no assertion failures)
	fn expect_success(self) {
		let (result, ctx) = self.execute();
		assert!(result.is_ok(), "Interpreter should execute successfully");
		assert!(ctx.check_assertions(None).is_ok(), "Should have no assertion failures");
	}

	/// Run the test and expect assertion failure
	fn expect_assertion_failure(self) {
		let (result, ctx) = self.execute();
		assert!(result.is_ok(), "Interpreter should execute successfully");
		assert!(ctx.check_assertions(None).is_err(), "Should have assertion failures");
	}

	/// Execute the bytecode and return the result and context
	fn execute(self) -> (Result<(), PopulateError>, ExecutionContext<'static>) {
		let (bytecode, _) = self.builder.finalize();

		// Create value vec with the right size
		let n_witness = self.values.len();
		let mut value_vec = ValueVec::new(ValueVecLayout {
			n_const: 0,
			n_inout: 0,
			n_witness,
			n_internal: 0,
			offset_inout: 0,
			offset_witness: 0,
			committed_total_len: n_witness,
			n_scratch: 0,
		});

		// Set the values
		for (i, value) in self.values.into_iter().enumerate() {
			value_vec[ValueIndex(i as u32)] = value;
		}

		let hint_registry = HintRegistry::new();
		let mut interpreter = Interpreter::new(&bytecode, &hint_registry);

		// Leak the value_vec to get 'static lifetime - this is ok in tests
		let value_vec = Box::leak(Box::new(value_vec));
		let mut ctx = ExecutionContext::new(value_vec);

		let result = interpreter.run(&mut ctx);
		(result, ctx)
	}
}

/// Helper to create MSB-true value (MSB set to 1)
fn msb_true(lower_bits: u64) -> Word {
	Word(0x8000000000000000 | lower_bits)
}

/// Helper to create MSB-false value (MSB set to 0)
fn msb_false(lower_bits: u64) -> Word {
	Word(0x7FFFFFFFFFFFFFFF & lower_bits)
}

#[test]
fn test_assert_eq_cond() {
	// MSB=0, values different - should NOT trigger assertion
	InterpreterTest::new()
		.with_values(vec![
			msb_false(0x7FFFFFFFFFFFFFFF), // cond: all bits except MSB
			Word(42),                      // x
			Word(99),                      // y (different)
		])
		.assert_eq_cond(0, 1, 2)
		.expect_success();

	// MSB=1, values equal - should succeed
	InterpreterTest::new()
		.with_values(vec![
			msb_true(0), // cond: only MSB set
			Word(100),   // x
			Word(100),   // y (same)
		])
		.assert_eq_cond(0, 1, 2)
		.expect_success();

	// MSB=1, values different - should FAIL
	InterpreterTest::new()
		.with_values(vec![
			msb_true(0x7FFFFFFFFFFFFFFF), // cond: all bits set
			Word(42),                     // x
			Word(99),                     // y (different)
		])
		.assert_eq_cond(0, 1, 2)
		.expect_assertion_failure();

	// Only MSB matters, not other bits (MSB=0 with other bits set)
	InterpreterTest::new()
		.with_values(vec![
			msb_false(0xFF), // cond: low byte set but MSB=0
			Word(1000),      // x
			Word(2000),      // y (different)
		])
		.assert_eq_cond(0, 1, 2)
		.expect_success();

	// Edge case: MSB=1 with only one other bit
	InterpreterTest::new()
		.with_values(vec![
			msb_true(1), // cond: MSB and LSB set
			Word(5),     // x
			Word(10),    // y (different)
		])
		.assert_eq_cond(0, 1, 2)
		.expect_assertion_failure();
}

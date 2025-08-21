//! 128-bit addition in the Spark paradigm
//!
//! This example shows 128-bit unsigned integer addition using the Spark witness-first approach.

use crate::{UIntValue, witness::WitnessContext};
use binius_core::Word;

/// Input for 128-bit addition
pub struct Add128Input {
	/// First number as [low, high] limbs
	pub a: [Word; 2],
	/// Second number as [low, high] limbs
	pub b: [Word; 2],
}

/// Output of 128-bit addition
pub struct Add128Output {
	/// Sum as [low, high] limbs
	pub sum: [Word; 2],
}

/// Reference implementation - pure wrapping 128-bit addition
pub fn reference_add128(input: &Add128Input) -> Add128Output {
	// Add low limbs with carry out
	let a_low = input.a[0].0;
	let b_low = input.b[0].0;
	let low_sum = a_low.wrapping_add(b_low);
	let low_carry = if low_sum < a_low { 1 } else { 0 };

	// Add high limbs with carry in (wrapping)
	let a_high = input.a[1].0;
	let b_high = input.b[1].0;
	let high_sum = a_high.wrapping_add(b_high).wrapping_add(low_carry);

	Add128Output {
		sum: [Word(low_sum), Word(high_sum)],
	}
}

/// Spark implementation - tracked wrapping 128-bit addition
pub fn spark_add128(ctx: &mut WitnessContext, input: &Add128Input) -> Add128Output {
	// TODO: even closer to rust impl: binary wrapping_add (if makes sense)
	// TODO: remove uint_... since this is now typed
	// TODO ability to inline ctx.uint(input.a[0]); (not possible now due to rust mut. )
	// Add low limbs with carry out
	let a_low = ctx.uint(input.a[0]);
	let b_low = ctx.uint(input.b[0]);
	let zero = ctx.zero_uint();
	let (sum_low, carry_low) = ctx.add_with_carry(a_low, b_low, zero);

	// Add high limbs with carry in (wrapping)
	let a_high = ctx.uint(input.a[1]);
	let b_high = ctx.uint(input.b[1]);
	let (sum_high, _carry_high) = ctx.add_with_carry(a_high, b_high, carry_low);

	Add128Output {
		sum: [sum_low.value, sum_high.value],
	}
}

/// Spark implementation with overflow detection (returns carry as separate value)
pub fn spark_add128_with_overflow(
	ctx: &mut WitnessContext,
	input: &Add128Input,
) -> ([UIntValue; 2], UIntValue) {
	// Add low limbs with carry out
	let a_low = ctx.uint(input.a[0]);
	let b_low = ctx.uint(input.b[0]);
	let zero = ctx.zero_uint();
	let (sum_low, carry_low) = ctx.add_with_carry(a_low, b_low, zero);

	// Add high limbs with carry in
	let a_high = ctx.uint(input.a[1]);
	let b_high = ctx.uint(input.b[1]);
	let (sum_high, carry_high) = ctx.add_with_carry(a_high, b_high, carry_low);

	// carry_high is the overflow indicator (0 or 0xFFFFFFFFFFFFFFFF)
	([sum_low, sum_high], carry_high)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::compiler::ConstraintCompiler;

	#[test]
	fn test_128bit_addition_simple() {
		// Test: 100 + 200 = 300
		let input = Add128Input {
			a: [Word(100), Word(0)],
			b: [Word(200), Word(0)],
		};

		// Test reference implementation
		let output = reference_add128(&input);
		assert_eq!(output.sum[0], Word(300));
		assert_eq!(output.sum[1], Word(0));

		// Test tracked computation - should match exactly
		let mut ctx = WitnessContext::new();
		let tracked_output = spark_add128(&mut ctx, &input);
		assert_eq!(tracked_output.sum[0], Word(300));
		assert_eq!(tracked_output.sum[1], Word(0));
	}

	#[test]
	fn test_128bit_addition_with_carry() {
		// Test: (2^64 - 1) + 1 = 2^64 (carry to high limb)
		let input = Add128Input {
			a: [Word(u64::MAX), Word(0)],
			b: [Word(1), Word(0)],
		};

		let output = reference_add128(&input);
		assert_eq!(output.sum[0], Word(0));
		assert_eq!(output.sum[1], Word(1));

		// Test tracked version too
		let mut ctx = WitnessContext::new();
		let tracked = spark_add128(&mut ctx, &input);
		assert_eq!(tracked.sum[0], Word(0));
		assert_eq!(tracked.sum[1], Word(1));
	}

	#[test]
	fn test_128bit_wrapping() {
		// Test: (2^128 - 1) + 1 = 0 (wraps around)
		let input = Add128Input {
			a: [Word(u64::MAX), Word(u64::MAX)], // 2^128 - 1
			b: [Word(1), Word(0)],
		};

		// Reference implementation should wrap
		let output = reference_add128(&input);
		assert_eq!(output.sum[0], Word(0));
		assert_eq!(output.sum[1], Word(0));

		// Tracked implementation should match
		let mut ctx = WitnessContext::new();
		let tracked = spark_add128(&mut ctx, &input);
		assert_eq!(tracked.sum[0], Word(0));
		assert_eq!(tracked.sum[1], Word(0));
	}

	#[test]
	fn test_constraint_generation() {
		let input = Add128Input {
			a: [Word(100), Word(200)],
			b: [Word(300), Word(400)],
		};

		let mut ctx = WitnessContext::new();
		let _ = spark_add128(&mut ctx, &input);

		// Compile to constraints
		let mut compiler = ConstraintCompiler::new();
		compiler.compile(ctx.operations());
		let (and_constraints, mul_constraints) = compiler.get_constraints();

		// Should generate AND constraints for carry propagation
		assert!(!and_constraints.is_empty());
		assert_eq!(mul_constraints.len(), 0, "Addition should not use MUL constraints");
	}
}

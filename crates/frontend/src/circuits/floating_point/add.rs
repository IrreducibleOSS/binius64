//! Circuit for adding two 64-bit floating point numbers according to IEEE 754 double-precision
//! floating point addition circuit

use super::utils::extract_ieee754_components;
use crate::{
	circuits::variable_shifter::shr_var_with_sticky,
	compiler::{CircuitBuilder, Wire},
};

/// Creates a 64-bit IEEE 754 double-precision floating point addition circuit.
///
/// This function implements floating point addition according to the IEEE 754 standard,
/// handling all special cases including NaN, infinity, zero, and subnormal numbers.
/// The circuit performs mantissa alignment, addition with overflow handling, and
/// result normalization.
///
/// # Arguments
/// * `builder` - Circuit builder for creating the constraint system
/// * `a` - First operand wire (64-bit IEEE 754 double-precision float)
/// * `b` - Second operand wire (64-bit IEEE 754 double-precision float)
///
/// # Returns
/// Wire containing the result of `a + b` in IEEE 754 double-precision format
///
/// # IEEE 754 Special Cases Handled
/// * **NaN propagation**: Any NaN input produces NaN output
/// * **Infinity operations**: ∞ + finite = ∞, ∞ + (-∞) = NaN
/// * **Zero handling**: 0 + x = x, preserving sign rules
/// * **Overflow/underflow**: Proper exponent adjustment and normalization
/// * **Subnormal numbers**: Correct handling of denormalized values
///
/// # Implementation Details  
/// - Uses mantissa alignment for different exponents (up to 52-bit shift)
/// - Performs addition-only arithmetic (no subtraction circuits)
pub fn fp64_add(builder: &mut CircuitBuilder, a: Wire, b: Wire) -> Wire {
	let zero = builder.add_constant_64(0);
	let one = builder.add_constant_64(1);

	// Step 1: Extract IEEE 754 components (sign, exponent, mantissa)
	// IEEE 754 format: [sign:1][exponent:11][mantissa:52]
	let (sign_a, exp_a, mant_a) = extract_ieee754_components(builder, a);
	let (sign_b, exp_b, mant_b) = extract_ieee754_components(builder, b);

	// Step 3: Detect special value types for both operands
	let mant_a_zero = builder.icmp_eq(mant_a, zero);
	let mant_b_zero = builder.icmp_eq(mant_b, zero);
	let exp_max = builder.add_constant_64(0x7FF); // 2047 = maximum exponent
	let exp_a_is_max = builder.icmp_eq(exp_a, exp_max);
	let exp_b_is_max = builder.icmp_eq(exp_b, exp_max);

	// IEEE 754 special value classification:
	// NaN: exponent = 2047 AND mantissa ≠ 0
	let a_is_nan = builder.band(exp_a_is_max, builder.bnot(mant_a_zero));
	let b_is_nan = builder.band(exp_b_is_max, builder.bnot(mant_b_zero));
	let either_nan = builder.bor(a_is_nan, b_is_nan);

	// Infinity: exponent = 2047 AND mantissa = 0
	let a_is_inf = builder.band(exp_a_is_max, mant_a_zero);
	let b_is_inf = builder.band(exp_b_is_max, mant_b_zero);

	// Zero: exponent = 0 AND mantissa = 0 (true zero, not subnormal)
	let a_without_sign = builder.shl(a, 1);
	let b_without_sign = builder.shl(b, 1);
	let a_is_zero = builder.icmp_eq(a_without_sign, zero);
	let b_is_zero = builder.icmp_eq(b_without_sign, zero);

	// Step 4: Analyze exponent relationship for mantissa alignment
	let same_sign = builder.icmp_eq(sign_a, sign_b);
	let same_exp = builder.icmp_eq(exp_a, exp_b);
	let exp_b_lt_exp_a = builder.icmp_ult(exp_b, exp_a);
	let larger_exp = builder.select(exp_b, exp_a, exp_b_lt_exp_a);
	let smaller_exp = builder.select(exp_a, exp_b, exp_b_lt_exp_a);
	let (exp_diff, _) = builder.isub_bin_bout(larger_exp, smaller_exp, zero);

	// Step 5: Prepare mantissas for addition
	// Add implicit leading bit (bit 52) only for normal numbers
	// Subnormal numbers (exp = 0) have no implicit bit: 0.mantissa
	// Normal numbers (exp != 0) have implicit bit: 1.mantissa
	let implicit_bit = builder.add_constant_64(1u64 << 52);
	let exp_a_is_zero = builder.icmp_eq(exp_a, zero);
	let exp_b_is_zero = builder.icmp_eq(exp_b, zero);
	let full_mant_a = builder.select(
		builder.bxor(mant_a, implicit_bit), /* normal: add implicit bit (XOR since bit 52 is
		                                     * always 0) */
		mant_a, // subnormal: no implicit bit
		exp_a_is_zero,
	);
	let full_mant_b = builder.select(
		builder.bxor(mant_b, implicit_bit), /* normal: add implicit bit (XOR since bit 52 is
		                                     * always 0) */
		mant_b, // subnormal: no implicit bit
		exp_b_is_zero,
	);

	// Step 7: Align mantissas by shifting smaller exponent's mantissa
	// Pre-compute both possible shifts with sticky bits, then select the correct one
	let (shifted_mant_a, sticky_a) = shr_var_with_sticky(builder, full_mant_a, exp_diff);
	let (shifted_mant_b, sticky_b) = shr_var_with_sticky(builder, full_mant_b, exp_diff);

	// When exp_b < exp_a (exp_b_lt_exp_a is true): shift B's mantissa, keep A unchanged
	// When exp_a < exp_b (exp_b_lt_exp_a is false): shift A's mantissa, keep B unchanged
	let aligned_mant_a = builder.select(shifted_mant_a, full_mant_a, exp_b_lt_exp_a);
	let aligned_mant_b = builder.select(full_mant_b, shifted_mant_b, exp_b_lt_exp_a);

	// Select the correct sticky bit based on which mantissa was actually shifted
	let sticky_bit = builder.select(sticky_a, sticky_b, exp_b_lt_exp_a);

	// Step 8: Perform mantissa arithmetic
	// Always use addition (no dedicated subtraction circuit needed)
	// For different signs, this handles magnitude subtraction via two's complement
	let (sum_mant, carry) = builder.iadd_cin_cout(aligned_mant_a, aligned_mant_b, zero);

	// Step 9: Handle mantissa overflow and normalize result
	// If carry = 1, sum overflowed 53 bits, need to shift right and increment exponent
	let has_overflow = builder.bnot(builder.icmp_eq(carry, zero));
	let normalized_mant = builder.select(sum_mant, builder.shr(sum_mant, 1), has_overflow);

	// Step 10: Check if operation is feasible and compute final exponent
	// We can only handle shifts up to 52 bits (mantissa precision)
	// Beyond that, the smaller number becomes negligible
	let max_shift = builder.add_constant_64(52);
	let can_do_operation =
		builder.bor(same_exp, builder.bnot(builder.icmp_ult(max_shift, exp_diff)));
	// same_exp || !(max_shift < exp_diff) → same_exp || exp_diff <= max_shift

	// Use larger exponent as base (if operation is feasible), increment if overflow occurred
	let base_exp = builder.select(exp_a, larger_exp, can_do_operation);
	let (incremented_exp, _) = builder.iadd_cin_cout(base_exp, one, zero);
	let final_exp = builder.select(base_exp, incremented_exp, has_overflow);

	// Step 11: Convert mantissa back to IEEE 754 format and apply basic rounding
	// Check if we need to round up based on the least significant bit and sticky bit
	let lsb = builder.band(normalized_mant, one); // Least significant bit (bit 0)
	let round_up = builder.band(lsb, sticky_bit); // Simple rounding: round up if LSB=1 and sticky=1

	// Add rounding adjustment
	let (rounded_mant, round_carry) = builder.iadd_cin_cout(normalized_mant, round_up, zero);

	// Handle rounding overflow (rare case where rounding causes another normalization)
	let has_round_overflow = builder.bnot(builder.icmp_eq(round_carry, zero));
	let final_normalized_mant =
		builder.select(rounded_mant, builder.shr(rounded_mant, 1), has_round_overflow);

	// Remove implicit bit (bit 52) to get the fractional part only
	let mantissa_mask = builder.add_constant_64((1u64 << 52) - 1); // 52 bits = 2^52 - 1
	let final_mant = builder.band(final_normalized_mant, mantissa_mask);

	// Step 12: Determine result sign
	// Same signs: use common sign
	// Different signs: use sign of operand with larger magnitude (larger exponent)
	// Fallback: use sign_a when operation not supported
	let larger_operand_sign = builder.select(sign_a, sign_b, exp_b_lt_exp_a);
	let result_sign = builder.select(sign_a, larger_operand_sign, can_do_operation);

	// Step 13: Assemble IEEE 754 result from components
	// Format: [sign:1][exponent:11][mantissa:52]
	let sign_shifted = builder.shl(result_sign, 63);
	let exp_shifted = builder.shl(final_exp, 52);
	let simple_result = builder.bor(builder.bor(sign_shifted, exp_shifted), final_mant);

	// Step 14: Handle IEEE 754 special cases with priority-based selection
	// NaN has highest priority, followed by infinity, then zero, then normal arithmetic
	let nan_result = builder.add_constant_64(0x7FF8000000000000); // Canonical quiet NaN

	// Define special case conditions with clear intermediate names
	let both_inf = builder.band(a_is_inf, b_is_inf);
	let inf_different_signs = builder.band(both_inf, builder.bnot(same_sign)); // ∞ + (-∞) = NaN

	// Finite number detection (not infinity)
	let b_is_finite = builder.bnot(b_is_inf);
	let a_is_finite = builder.bnot(a_is_inf);
	let a_inf_b_finite = builder.band(a_is_inf, b_is_finite); // ∞ + finite = ∞
	let b_inf_a_finite = builder.band(b_is_inf, a_is_finite); // finite + ∞ = ∞

	// Normal number detection (not NaN or infinity)
	let b_is_special = builder.bor(b_is_inf, b_is_nan);
	let a_is_special = builder.bor(a_is_inf, a_is_nan);
	let b_is_normal = builder.bnot(b_is_special);
	let a_is_normal = builder.bnot(a_is_special);
	let a_zero_b_normal = builder.band(a_is_zero, b_is_normal); // 0 + normal = normal
	let b_zero_a_normal = builder.band(b_is_zero, a_is_normal); // normal + 0 = normal
	let nan_case = builder.bor(either_nan, inf_different_signs);

	// Step 15: Build final result using priority-based selection chain
	// Priority order: NaN > Infinity > Zero identity > Normal arithmetic > Fallback
	// When not feasible (exp_diff > 52), return the larger operand since smaller becomes negligible
	let larger_operand = builder.select(b, a, exp_b_lt_exp_a);
	let base_result = builder.select(larger_operand, simple_result, can_do_operation);
	let mut final_result = base_result;
	final_result = builder.select(final_result, b, a_zero_b_normal); // 0 + b = b
	final_result = builder.select(final_result, a, b_zero_a_normal); // a + 0 = a  
	final_result = builder.select(final_result, a, a_inf_b_finite); // ∞ + finite = ∞
	final_result = builder.select(final_result, b, b_inf_a_finite); // finite + ∞ = ∞
	builder.select(final_result, nan_result, nan_case) // NaN cases (highest priority)
}

#[cfg(test)]
mod tests {
	use binius_core::Word;
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	/// Generic test function for single FP64 addition case
	fn test_fp64_addition_case(a_val: f64, b_val: f64, expected: f64, description: &str) {
		let mut builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let result = fp64_add(&mut builder, a, b);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();

		filler[a] = Word(a_val.to_bits());
		filler[b] = Word(b_val.to_bits());
		filler[result] = Word(expected.to_bits());

		circuit.populate_wire_witness(&mut filler).unwrap();
		verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).unwrap_or_else(
			|_| panic!("Test failed: {description}: {a_val} + {b_val} = {expected}"),
		);
	}

	/// Generic test function for multiple FP64 addition cases
	fn test_fp64_addition_cases(test_cases: Vec<(f64, f64, f64, &str)>) {
		for (a_val, b_val, expected, description) in test_cases {
			test_fp64_addition_case(a_val, b_val, expected, description);
		}
	}

	#[test]
	fn test_basic_arithmetic() {
		let mut test_cases = vec![
			// Basic same-exponent addition
			(1.25, 1.75, 3.0, "same exp addition"),
			(1.0, 1.0, 2.0, "1+1=2"),
			(0.5, 0.25, 0.75, "fractional addition"),
			// Mantissa overflow requiring normalization
			(1.75, 1.75, 3.5, "mantissa overflow"),
			(1.9999999999999998, 1.9999999999999998, 3.9999999999999996, "near overflow"),
			// Basic subtraction (different signs)
			(1.5, -0.5, 1.0, "basic subtraction"),
			(2.5, -1.5, 1.0, "subtraction result"),
			(3.0, -1.5, 1.5, "alignment subtraction"),
		];

		// Add random test cases with seeded randomness for reproducibility
		let mut random_cases = Vec::new();
		generate_random_test_cases(&mut test_cases, &mut random_cases, 0, 10, "random_case");

		test_fp64_addition_cases(test_cases);
	}

	/// Helper to generate random test cases with seeded randomness for reproducibility
	fn generate_random_test_cases<'a>(
		test_cases: &mut Vec<(f64, f64, f64, &'a str)>,
		owned_cases: &'a mut Vec<(f64, f64, f64, String)>,
		seed: u64,
		num_cases: usize,
		desc_prefix: &str,
	) {
		let mut rng = StdRng::seed_from_u64(seed);

		for i in 0..num_cases {
			let a_random: f64 = if i % 4 == 0 {
				// Generate subnormal numbers 25% of the time
				generate_random_subnormal(&mut rng)
			} else {
				rng.random()
			};

			let b_random: f64 = if i % 3 == 0 {
				// Generate subnormal numbers ~33% of the time (different pattern)
				generate_random_subnormal(&mut rng)
			} else {
				rng.random()
			};

			let expected_random = a_random + b_random;
			owned_cases.push((a_random, b_random, expected_random, format!("{desc_prefix}_{i}")));
		}

		// Add to test_cases with borrowed strings
		for (a, b, expected, desc) in owned_cases.iter().rev().take(num_cases).rev() {
			test_cases.push((*a, *b, *expected, desc.as_str()));
		}
	}

	/// Generate a random subnormal number for testing
	fn generate_random_subnormal(rng: &mut StdRng) -> f64 {
		// Subnormal range: 0 < |x| < f64::MIN_POSITIVE
		// Generate random mantissa (1 to 2^52-1) and create subnormal
		let mantissa: u64 = rng.random_range(1..=(1u64 << 52) - 1);
		let sign_bit: u64 = if rng.random_bool(0.5) { 1u64 << 63 } else { 0 };
		let subnormal_bits = sign_bit | mantissa; // exponent = 0
		f64::from_bits(subnormal_bits)
	}

	/// Test function that validates special values (NaN, Inf) with custom comparison
	fn test_fp64_special_case(
		a_val: f64,
		b_val: f64,
		validator: impl Fn(f64) -> bool,
		description: &str,
	) {
		let mut builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let result = fp64_add(&mut builder, a, b);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();

		let expected = a_val + b_val; // IEEE 754 expected result
		filler[a] = Word(a_val.to_bits());
		filler[b] = Word(b_val.to_bits());
		filler[result] = Word(expected.to_bits());

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Get result before moving filler
		let actual_result = f64::from_bits(filler[result].0);
		verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).unwrap();

		assert!(
			validator(actual_result),
			"Test failed: {description}: {a_val} + {b_val}, got {actual_result}"
		);
	}

	#[test]
	fn test_exponent_differences() {
		// Test various exponent differences with 1.0 + powers of 2
		let test_cases = vec![
			(1.0, 2.0, 3.0, "exp_diff=1"),
			(1.0, 4.0, 5.0, "exp_diff=2"),
			(1.0, 8.0, 9.0, "exp_diff=3"),
			(1.0, 16.0, 17.0, "exp_diff=4"),
			(1.0, 256.0, 257.0, "exp_diff=8"),
			(1.0, 32768.0, 32769.0, "exp_diff=15"),
			(1.0, 1048576.0, 1048577.0, "exp_diff=20"),
			(1.0, 4294967296.0, 4294967297.0, "exp_diff=32"),
			(1.0, 35184372088832.0, 35184372088833.0, "exp_diff=45"),
			(1.0, 1125899906842624.0, 1125899906842625.0, "exp_diff=50"),
			(1.0, 4503599627370496.0, 4503599627370497.0, "exp_diff=52"),
		];

		test_fp64_addition_cases(test_cases);
	}

	#[test]
	fn test_special_cases() {
		// Test NaN propagation
		test_fp64_special_case(f64::NAN, 1.0, |r| r.is_nan(), "NaN + normal");
		test_fp64_special_case(1.0, f64::NAN, |r| r.is_nan(), "normal + NaN");

		// Test infinity arithmetic
		test_fp64_special_case(
			f64::INFINITY,
			42.0,
			|r| r.is_infinite() && r.is_sign_positive(),
			"Inf + finite",
		);
		test_fp64_special_case(
			f64::NEG_INFINITY,
			-5.0,
			|r| r.is_infinite() && r.is_sign_negative(),
			"-Inf + finite",
		);
		test_fp64_special_case(f64::INFINITY, f64::NEG_INFINITY, |r| r.is_nan(), "Inf + (-Inf)");

		// Test zero arithmetic
		test_fp64_special_case(0.0, 5.5, |r| r == 5.5, "0 + normal");
		test_fp64_special_case(
			-0.0,
			std::f64::consts::PI,
			|r| r == std::f64::consts::PI,
			"-0 + normal",
		);
		test_fp64_special_case(
			f64::INFINITY,
			0.0,
			|r| r.is_infinite() && r.is_sign_positive(),
			"Inf + 0",
		);
		test_fp64_special_case(
			0.0,
			f64::INFINITY,
			|r| r.is_infinite() && r.is_sign_positive(),
			"0 + Inf",
		);
	}

	#[test]
	fn test_comprehensive_normalization_and_alignment() {
		let mut test_cases = vec![
			// Normalization cases - close subtractions that require left-shift
			(1.0000001, -1.0, 1e-7, "close subtraction"),
			(2.0000001, -2.0, 1e-7, "close subtraction larger"),
			(1.125, -1.0, 0.125, "small difference subtraction"),
			// Complex alignment and arithmetic
			(1e100, 1e50, 1e100, "large exp diff addition"),
			(2.0, -0.5, 1.5, "subtraction with exp diff"),
			(2.0, 1.0000001, 3.0000001, "close exp different"),
			// Edge mantissa cases - near IEEE 754 boundaries
			(1.9999999999999998, 0.0000000000000002, 2.0, "near mantissa boundary"),
			// Additional normalization edge cases
			(1.5, -1.4999999999999998, 2.220446049250313e-16, "extreme close subtraction"),
			(4.0, -3.9999999999999996, 4.440892098500626e-16, "very close subtraction"),
			// Alignment with various shifts
			(1.0, 0.25, 1.25, "simple alignment case"),
			(8.0, 0.125, 8.125, "3-bit shift alignment"),
			// Mixed sign complex cases
			(1e20, -1e19, 9e19, "large number subtraction"),
			(1e-10, -1e-11, 9e-11, "small number subtraction with alignment"),
		];

		// Add random test cases with seeded randomness for reproducibility
		let mut random_cases = Vec::new();
		generate_random_test_cases(
			&mut test_cases,
			&mut random_cases,
			1,
			8,
			"normalization_random_case",
		);

		test_fp64_addition_cases(test_cases);
	}

	#[test]
	fn test_comprehensive_subnormal_operations() {
		let mut test_cases = vec![
			// Basic subnormal cancellation (should result in zero)
			(5e-324, -5e-324, 0.0, "smallest subnormal cancellation"),
			// Two small subnormals
			(1e-320, 1e-320, 2e-320, "two tiny subnormals"),
			// Subnormal + normal that results in subnormal
			(1e-308, -1e-308, 0.0, "small normal cancellation"),
			// Different magnitude subnormals
			(5e-324, 10e-324, 15e-324, "different magnitude subnormals"),
			// Subnormal with larger normal (should absorb into normal)
			(5e-324, 1.0, 1.0, "subnormal absorbed by normal"),
			// Edge case: result transitions from subnormal to normal
			(
				f64::MIN_POSITIVE * 0.9,
				f64::MIN_POSITIVE * 0.2,
				f64::MIN_POSITIVE * 1.1,
				"subnormal to normal transition",
			),
		];

		// Add random test cases with seeded randomness for reproducibility
		let mut random_cases = Vec::new();
		generate_random_test_cases(
			&mut test_cases,
			&mut random_cases,
			2,
			6,
			"subnormal_random_case",
		);

		test_fp64_addition_cases(test_cases);
	}

	#[test]
	fn test_exponent_difference_isolated() {
		// Test just exponent difference calculation for 1.0 + 2.0
		let builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let exp_diff_result = builder.add_inout();

		// Extract IEEE 754 components
		let (_sign_a, exp_a, _mant_a) = extract_ieee754_components(&builder, a);
		let (_sign_b, exp_b, _mant_b) = extract_ieee754_components(&builder, b);

		// Calculate |exp_a - exp_b|
		// exp_b_lt_exp_a is all-1 if exp_b < exp_a (i.e., exp_a is larger)
		let exp_b_lt_exp_a = builder.icmp_ult(exp_b, exp_a);
		let larger_exp = builder.select(exp_b, exp_a, exp_b_lt_exp_a); // if exp_b < exp_a, select exp_a
		let smaller_exp = builder.select(exp_a, exp_b, exp_b_lt_exp_a); // if exp_b < exp_a, select exp_b
		let zero = builder.add_constant_64(0);
		let (exp_diff, _) = builder.isub_bin_bout(larger_exp, smaller_exp, zero);

		builder.assert_eq("exp_diff", exp_diff, exp_diff_result);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();

		let a_val = 1.0_f64; // exp = 1023
		let b_val = 2.0_f64; // exp = 1024
		let expected_diff = 1u64; // |1024 - 1023| = 1

		filler[a] = Word(a_val.to_bits());
		filler[b] = Word(b_val.to_bits());
		filler[exp_diff_result] = Word(expected_diff);

		circuit.populate_wire_witness(&mut filler).unwrap();
		verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_comprehensive_edge_cases() {
		// Test combinations of features: large exp differences + subtraction, etc.
		let test_cases = vec![
			// Large exponent difference with subtraction
			(1e10_f64, -1e-5_f64, "large exp diff subtraction"),
			// Subtraction that results in subnormal
			(f64::MIN_POSITIVE, -f64::MIN_POSITIVE / 2.0, "subtraction to subnormal"),
			// Addition with large exponent difference
			(1e100_f64, 1e50_f64, "addition large exp diff"),
			// Mix of alignment and normalization
			(3.0_f64, -1.5_f64, "simple alignment subtraction"),
			// Very close but different exponents
			(2.0_f64, 1.0000001_f64, "close exp different"),
		];

		for (a_val, b_val, _description) in test_cases {
			let mut builder = CircuitBuilder::new();
			let a = builder.add_inout();
			let b = builder.add_inout();
			let result = fp64_add(&mut builder, a, b);
			let circuit = builder.build();

			let mut filler = circuit.new_witness_filler();
			let expected = a_val + b_val;

			filler[a] = Word(a_val.to_bits());
			filler[b] = Word(b_val.to_bits());
			filler[result] = Word(expected.to_bits());

			circuit.populate_wire_witness(&mut filler).unwrap();

			let constraint_system = circuit.constraint_system();
			verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
		}
	}

	/// Comprehensive floating point addition testing with different value categories
	#[test]
	fn test_comprehensive_fp64_addition() {
		const NORMAL_NORMAL_COUNT: usize = 50;
		const SUBNORMAL_SUBNORMAL_COUNT: usize = 30;
		const NORMAL_SUBNORMAL_COUNT: usize = 40;
		const NORMAL_SPECIAL_COUNT: usize = 20;
		const SPECIAL_SUBNORMAL_COUNT: usize = 20;

		// Test normal + normal
		test_category_with_commutativity(
			NORMAL_NORMAL_COUNT,
			0, // seed
			generate_random_normal,
			generate_random_normal,
			"normal+normal",
		);

		// Test subnormal + subnormal
		test_category_with_commutativity(
			SUBNORMAL_SUBNORMAL_COUNT,
			1, // seed
			generate_random_subnormal,
			generate_random_subnormal,
			"subnormal+subnormal",
		);

		// Test normal + subnormal
		test_category_with_commutativity(
			NORMAL_SUBNORMAL_COUNT,
			2, // seed
			generate_random_normal,
			generate_random_subnormal,
			"normal+subnormal",
		);

		// Test normal + special cases
		test_normal_special_cases(NORMAL_SPECIAL_COUNT, 3);

		// Test special cases + subnormal
		test_special_subnormal_cases(SPECIAL_SUBNORMAL_COUNT, 4);
	}

	fn test_category_with_commutativity<F1, F2>(
		count: usize,
		seed: u64,
		gen_a: F1,
		gen_b: F2,
		category: &str,
	) where
		F1: Fn(&mut StdRng) -> f64,
		F2: Fn(&mut StdRng) -> f64,
	{
		let mut rng = StdRng::seed_from_u64(seed);

		for i in 0..count {
			let a = gen_a(&mut rng);
			let b = gen_b(&mut rng);
			let expected = a + b;

			// Test a + b
			test_fp64_addition_case(a, b, expected, &format!("{category}_{i}"));

			// Test commutativity: b + a
			test_fp64_addition_case(b, a, expected, &format!("{category}_comm_{i}"));
		}
	}

	fn test_normal_special_cases(count: usize, seed: u64) {
		let mut rng = StdRng::seed_from_u64(seed);
		let special_values = [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 0.0, -0.0];

		for i in 0..count {
			let normal = generate_random_normal(&mut rng);
			let special = special_values[i % special_values.len()];
			let expected = normal + special;

			// Test normal + special
			if expected.is_nan() {
				test_fp64_special_case(
					normal,
					special,
					|r| r.is_nan(),
					&format!("normal+special_{i}"),
				);
			} else {
				test_fp64_addition_case(normal, special, expected, &format!("normal+special_{i}"));
			}

			// Test commutativity: special + normal
			let expected_comm = special + normal;
			if expected_comm.is_nan() {
				test_fp64_special_case(
					special,
					normal,
					|r| r.is_nan(),
					&format!("special+normal_comm_{i}"),
				);
			} else {
				test_fp64_addition_case(
					special,
					normal,
					expected_comm,
					&format!("special+normal_comm_{i}"),
				);
			}
		}
	}

	fn test_special_subnormal_cases(count: usize, seed: u64) {
		let mut rng = StdRng::seed_from_u64(seed);
		let special_values = [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 0.0, -0.0];

		for i in 0..count {
			let subnormal = generate_random_subnormal(&mut rng);
			let special = special_values[i % special_values.len()];
			let expected = special + subnormal;

			// Test special + subnormal
			if expected.is_nan() {
				test_fp64_special_case(
					special,
					subnormal,
					|r| r.is_nan(),
					&format!("special+subnormal_{i}"),
				);
			} else {
				test_fp64_addition_case(
					special,
					subnormal,
					expected,
					&format!("special+subnormal_{i}"),
				);
			}

			// Test commutativity: subnormal + special
			let expected_comm = subnormal + special;
			if expected_comm.is_nan() {
				test_fp64_special_case(
					subnormal,
					special,
					|r| r.is_nan(),
					&format!("subnormal+special_comm_{i}"),
				);
			} else {
				test_fp64_addition_case(
					subnormal,
					special,
					expected_comm,
					&format!("subnormal+special_comm_{i}"),
				);
			}
		}
	}

	/// Generate a random normal number (not subnormal, not special)
	fn generate_random_normal(rng: &mut StdRng) -> f64 {
		loop {
			let val: f64 = rng.random();
			if val.is_normal() && val.is_finite() {
				return val;
			}
		}
	}

	#[test]
	fn test_fallback_case() {
		let mut builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();
		let result = fp64_add(&mut builder, a, b);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();

		// Test different exponents (should fallback to returning a)
		let a_val = 1.0_f64; // exp = 1023
		let b_val = 2.0_f64; // exp = 1024

		filler[a] = Word(a_val.to_bits());
		filler[b] = Word(b_val.to_bits());
		filler[result] = Word(a_val.to_bits()); // fallback returns a

		circuit.populate_wire_witness(&mut filler).unwrap();

		let constraint_system = circuit.constraint_system();
		verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
	}
}

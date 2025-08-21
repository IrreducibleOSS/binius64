use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire};

/// Creates a wire containing the constant value 0.
pub fn zero(builder: &CircuitBuilder) -> Wire {
	builder.add_constant_64(0)
}

/// Creates a wire containing the constant value 1.
pub fn one(builder: &CircuitBuilder) -> Wire {
	builder.add_constant_64(1)
}

/// Creates a wire containing all-ones (0xFFFFFFFFFFFFFFFF).
pub fn all_ones(builder: &CircuitBuilder) -> Wire {
	builder.add_constant(Word::ALL_ONE)
}

/// Performs integer addition: `a + b`.
///
/// This is a wrapper around the circuit builder's integer addition that handles
/// carry-in/carry-out automatically with zero carry-in.
pub fn iadd(builder: &CircuitBuilder, a: Wire, b: Wire) -> Wire {
	let (s, _c) = builder.iadd_cin_cout(a, b, zero(builder));
	s
}

/// Performs integer subtraction: `a - b`.
///
/// This is a wrapper around the circuit builder's integer subtraction that handles
/// borrow-in/borrow-out automatically with zero borrow-in.
pub fn isub(builder: &CircuitBuilder, a: Wire, b: Wire) -> Wire {
	let (d, _b) = builder.isub_bin_bout(a, b, zero(builder));
	d
}

/// Returns an all-ones mask if `x` is zero, all-zeros mask otherwise.
///
/// This is equivalent to `x == 0 ? 0xFFFFFFFFFFFFFFFF : 0x0000000000000000`.
pub fn is_zero_mask(builder: &CircuitBuilder, x: Wire) -> Wire {
	builder.icmp_eq(x, zero(builder))
}

/// Returns an all-ones mask if `x` is non-zero, all-zeros mask otherwise.
///
/// This is equivalent to `x != 0 ? 0xFFFFFFFFFFFFFFFF : 0x0000000000000000`.
pub fn is_nonzero_mask(builder: &CircuitBuilder, x: Wire) -> Wire {
	builder.bnot(is_zero_mask(builder, x))
}

/// Converts a 0/1 value to an all-0/all-1 mask.
///
/// Input: `b01` should be 0 or 1
/// Output: 0x0000000000000000 if `b01` is 0, 0xFFFFFFFFFFFFFFFF if `b01` is 1
pub fn to_mask01(builder: &CircuitBuilder, b01: Wire) -> Wire {
	isub(builder, zero(builder), builder.band(b01, one(builder)))
}

/// Extracts bit `i` from `x` as a 0/1 value.
///
/// Returns `(x >> i) & 1`.
pub fn bit_lsb(builder: &CircuitBuilder, x: Wire, i: u32) -> Wire {
	builder.band(builder.shr(x, i), one(builder))
}

/// Extracts bit `i` from `x` as an all-0/all-1 mask.
///
/// Returns 0xFFFFFFFFFFFFFFFF if bit `i` is set, 0x0000000000000000 otherwise.
pub fn bit_mask(builder: &CircuitBuilder, x: Wire, i: u32) -> Wire {
	to_mask01(builder, bit_lsb(builder, x, i))
}

/// Performs variable right shift with sticky bit tracking.
///
/// This implements a barrel shifter that can shift by any amount 0-63,
/// with optional saturation. All bits shifted out are OR'd together to
/// create a "sticky" bit that tracks whether any precision was lost.
///
/// # Parameters
/// - `x`: Value to shift
/// - `d`: Shift amount (0-63, or optionally saturated at 63)
/// - `saturate_at_63`: If true, shifts >= 64 are treated as 63; if false, they wrap
///
/// # Returns
/// - First wire: The shifted value
/// - Second wire: Sticky bit (all-1 mask if any bits were lost, all-0 otherwise)
pub fn var_shr_with_sticky(
	builder: &CircuitBuilder,
	x: Wire,
	d: Wire,
	saturate_at_63: bool,
) -> (Wire, Wire) {
	let c63 = builder.add_constant_64(63);
	let c64 = builder.add_constant_64(64);
	let d_eff = if saturate_at_63 {
		let lt64 = builder.icmp_ult(d, c64);
		builder.select(lt64, d, c63)
	} else {
		builder.band(d, c63)
	};

	let mut v = x;
	let mut sticky = zero(builder);

	// Stage 32 (bit 5)
	{
		let cond = bit_mask(builder, d_eff, 5);
		let lost = builder.band(v, builder.add_constant_64((1u64 << 32) - 1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 32);
		v = builder.select(cond, shifted, v);
	}
	// Stage 16 (bit 4)
	{
		let cond = bit_mask(builder, d_eff, 4);
		let lost = builder.band(v, builder.add_constant_64((1u64 << 16) - 1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 16);
		v = builder.select(cond, shifted, v);
	}
	// Stage 8 (bit 3)
	{
		let cond = bit_mask(builder, d_eff, 3);
		let lost = builder.band(v, builder.add_constant_64((1u64 << 8) - 1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 8);
		v = builder.select(cond, shifted, v);
	}
	// Stage 4 (bit 2)
	{
		let cond = bit_mask(builder, d_eff, 2);
		let lost = builder.band(v, builder.add_constant_64((1u64 << 4) - 1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 4);
		v = builder.select(cond, shifted, v);
	}
	// Stage 2 (bit 1)
	{
		let cond = bit_mask(builder, d_eff, 1);
		let lost = builder.band(v, builder.add_constant_64((1u64 << 2) - 1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 2);
		v = builder.select(cond, shifted, v);
	}
	// Stage 1 (bit 0)
	{
		let cond = bit_mask(builder, d_eff, 0);
		let lost = builder.band(v, builder.add_constant_64(1));
		let lost_nz = is_nonzero_mask(builder, lost);
		sticky = builder.bor(sticky, builder.band(lost_nz, cond));
		let shifted = builder.shr(v, 1);
		v = builder.select(cond, shifted, v);
	}

	(v, sticky)
}

/// Performs variable left shift.
///
/// This implements a barrel shifter that can shift left by any amount 0-63.
/// Shift amounts >= 64 are masked to 0-63 range (i.e., `d & 63`).
///
/// # Parameters
/// - `x`: Value to shift
/// - `d`: Shift amount (effectively `d & 63`)
///
/// # Returns
/// The left-shifted value `x << (d & 63)`
pub fn var_shl(builder: &CircuitBuilder, x: Wire, d: Wire) -> Wire {
	let d_eff = builder.band(d, builder.add_constant_64(63));
	let mut v = x;

	{
		let cond = bit_mask(builder, d_eff, 5); // 32
		let shifted = builder.shl(v, 32);
		v = builder.select(cond, shifted, v);
	}
	{
		let cond = bit_mask(builder, d_eff, 4); // 16
		let shifted = builder.shl(v, 16);
		v = builder.select(cond, shifted, v);
	}
	{
		let cond = bit_mask(builder, d_eff, 3); // 8
		let shifted = builder.shl(v, 8);
		v = builder.select(cond, shifted, v);
	}
	{
		let cond = bit_mask(builder, d_eff, 2); // 4
		let shifted = builder.shl(v, 4);
		v = builder.select(cond, shifted, v);
	}
	{
		let cond = bit_mask(builder, d_eff, 1); // 2
		let shifted = builder.shl(v, 2);
		v = builder.select(cond, shifted, v);
	}
	{
		let cond = bit_mask(builder, d_eff, 0); // 1
		let shifted = builder.shl(v, 1);
		v = builder.select(cond, shifted, v);
	}

	v
}

/// Count leading zeroes in `x`
pub fn clz64(builder: &CircuitBuilder, x: Wire) -> Wire {
	let mut n = zero(builder);
	let mut y = x;

	// step(32)
	{
		let t = builder.shr(y, 32);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(32)));
		y = builder.select(z, builder.shl(y, 32), y);
	}
	// step(16)
	{
		let t = builder.shr(y, 48);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(16)));
		y = builder.select(z, builder.shl(y, 16), y);
	}
	// step(8)
	{
		let t = builder.shr(y, 56);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(8)));
		y = builder.select(z, builder.shl(y, 8), y);
	}
	// step(4)
	{
		let t = builder.shr(y, 60);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(4)));
		y = builder.select(z, builder.shl(y, 4), y);
	}
	// step(2)
	{
		let t = builder.shr(y, 62);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(2)));
		y = builder.select(z, builder.shl(y, 2), y);
	}
	// step(1)
	{
		let t = builder.shr(y, 63);
		let z = is_zero_mask(builder, t);
		n = iadd(builder, n, builder.band(z, builder.add_constant_64(1)));
	}
	n
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_is_zero_mask() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let output = is_zero_mask(&builder, input);
		let expected = builder.add_inout();
		builder.assert_eq("test_output", output, expected);

		let circuit = builder.build();

		let test_cases = [
			(0, u64::MAX),
			(1, 0),
			(0xFFFFFFFFFFFFFFFF, 0),
			(0x8000000000000000, 0),
		];

		for (val, expected_val) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[expected] = Word(expected_val);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_is_nonzero_mask() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let output = is_nonzero_mask(&builder, input);
		let expected = builder.add_inout();
		builder.assert_eq("test_output", output, expected);

		let circuit = builder.build();

		let test_cases = [
			(0, 0),
			(1, u64::MAX),
			(0xFFFFFFFFFFFFFFFF, u64::MAX),
			(0x8000000000000000, u64::MAX),
		];

		for (val, expected_val) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[expected] = Word(expected_val);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_bit_lsb() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let output0 = bit_lsb(&builder, input, 0);
		let output1 = bit_lsb(&builder, input, 1);
		let output63 = bit_lsb(&builder, input, 63);
		let expected0 = builder.add_inout();
		let expected1 = builder.add_inout();
		let expected63 = builder.add_inout();
		builder.assert_eq("test_output0", output0, expected0);
		builder.assert_eq("test_output1", output1, expected1);
		builder.assert_eq("test_output63", output63, expected63);

		let circuit = builder.build();

		let test_cases = [
			(0b101, 1, 0, 0),              // bit 0=1, bit 1=0, bit 63=0
			(0b110, 0, 1, 0),              // bit 0=0, bit 1=1, bit 63=0
			(0x8000000000000001, 1, 0, 1), // bit 0=1, bit 1=0, bit 63=1
		];

		for (val, exp0, exp1, exp63) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[expected0] = Word(exp0);
			w[expected1] = Word(exp1);
			w[expected63] = Word(exp63);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_clz64() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let output = clz64(&builder, input);
		let expected = builder.add_inout();
		builder.assert_eq("test_output", output, expected);

		let circuit = builder.build();

		let test_cases = [
			(0x8000000000000000u64, 0),  // Top bit set
			(0x4000000000000000u64, 1),  // Second bit set
			(0x0000000000000001u64, 63), // Only bottom bit set
			(0xFFFFFFFFFFFFFFFFu64, 0),  // All bits set
			(0x0000000000008000u64, 48), // Bit 15 set
		];

		for (val, expected_clz) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[expected] = Word(expected_clz);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_var_shl() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let shift = builder.add_inout();
		let output = var_shl(&builder, input, shift);
		let expected = builder.add_inout();
		builder.assert_eq("test_output", output, expected);

		let circuit = builder.build();

		let test_cases = [
			(1, 0, 1),        // No shift
			(1, 1, 2),        // Shift left by 1
			(1, 8, 256),      // Shift left by 8
			(0xFF, 4, 0xFF0), // Shift 0xFF left by 4
			(1, 64, 1),       // Shift amount wraps (64 & 63 = 0)
		];

		for (val, shift_amt, expected_result) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[shift] = Word(shift_amt);
			w[expected] = Word(expected_result);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_var_shr_with_sticky() {
		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let shift = builder.add_inout();
		let (output, sticky) = var_shr_with_sticky(&builder, input, shift, false);
		let expected_out = builder.add_inout();
		let expected_sticky = builder.add_inout();
		builder.assert_eq("test_output", output, expected_out);
		builder.assert_eq("test_sticky", sticky, expected_sticky);

		let circuit = builder.build();

		let test_cases = [
			(8, 1, 4, 0),                           // 8 >> 1 = 4, no bits lost
			(7, 1, 3, Word::ALL_ONE.as_u64()),      // 7 >> 1 = 3, bit lost (sticky)
			(0xFF, 4, 0xF, Word::ALL_ONE.as_u64()), // 0xFF >> 4 = 0xF, bits lost
			(0xF0, 4, 0xF, 0),                      // 0xF0 >> 4 = 0xF, no bits lost
		];

		for (val, shift_amt, expected_result, expected_sticky_val) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[input] = Word(val);
			w[shift] = Word(shift_amt);
			w[expected_out] = Word(expected_result);
			w[expected_sticky] = Word(expected_sticky_val);

			circuit.populate_wire_witness(&mut w).unwrap();
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}
}

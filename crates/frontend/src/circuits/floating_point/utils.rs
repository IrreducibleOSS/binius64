//! IEEE 754 utility functions for floating point operations.

use crate::compiler::{CircuitBuilder, Wire};

/// Extracts the sign, exponent, and mantissa from a 64-bit float wire.
/// Returns (sign, exponent, mantissa)
pub fn extract_ieee754_components(builder: &CircuitBuilder, f: Wire) -> (Wire, Wire, Wire) {
	let sign = builder.shr(f, 63_u32);
	let exp = builder.band(builder.shr(f, 52_u32), builder.add_constant_64((1 << 11) - 1));
	let mant = builder.band(f, builder.add_constant_64((1 << 52) - 1));
	(sign, exp, mant)
}

/// Packs the sign, exponent, and mantissa into a 64-bit float wire.
pub fn pack_ieee754_components(
	builder: &CircuitBuilder,
	sign: Wire,
	exp: Wire,
	mant: Wire,
) -> Wire {
	let sign_part = builder.shl(sign, 63_u32);
	let exp_part = builder.shl(exp, 52_u32);
	let mant_part = builder.band(mant, builder.add_constant_64((1 << 52) - 1));
	builder.bor(builder.bor(sign_part, exp_part), mant_part)
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	fn test_extract_pack_roundtrip(value: f64) {
		let bits = value.to_bits();

		let builder = CircuitBuilder::new();
		let input = builder.add_inout();

		// Extract components
		let (sign, exp, mant) = extract_ieee754_components(&builder, input);

		// Pack them back
		let output = pack_ieee754_components(&builder, sign, exp, mant);

		// Should be identical to input
		builder.assert_eq("roundtrip", input, output);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();
		filler[input] = Word(bits);
		circuit.populate_wire_witness(&mut filler).unwrap();

		let constraint_system = circuit.constraint_system();
		verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
	}

	fn test_extract_components_manual(value: f64) {
		let bits = value.to_bits();
		let expected_sign = (bits >> 63) & 1;
		let expected_exp = (bits >> 52) & 0x7FF;
		let expected_mant = bits & 0xFFFFFFFFFFFFF;

		let builder = CircuitBuilder::new();
		let input = builder.add_inout();
		let expected_sign_wire = builder.add_inout();
		let expected_exp_wire = builder.add_inout();
		let expected_mant_wire = builder.add_inout();

		// Extract components
		let (sign, exp, mant) = extract_ieee754_components(&builder, input);

		builder.assert_eq("sign", sign, expected_sign_wire);
		builder.assert_eq("exp", exp, expected_exp_wire);
		builder.assert_eq("mant", mant, expected_mant_wire);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();
		filler[input] = Word(bits);
		filler[expected_sign_wire] = Word(expected_sign);
		filler[expected_exp_wire] = Word(expected_exp);
		filler[expected_mant_wire] = Word(expected_mant);
		circuit.populate_wire_witness(&mut filler).unwrap();

		let constraint_system = circuit.constraint_system();
		verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_component_extraction() {
		use rand::{Rng, SeedableRng, rngs::StdRng};

		// Test basic values
		test_extract_components_manual(1.0);
		test_extract_components_manual(2.0);
		test_extract_components_manual(3.0);
		test_extract_components_manual(-1.0);
		test_extract_components_manual(0.0);

		// Test special values
		test_extract_components_manual(f64::INFINITY);
		test_extract_components_manual(f64::NEG_INFINITY);

		// Test random values with seeded randomness for reproducibility
		let mut rng = StdRng::seed_from_u64(0);
		for _ in 0..10 {
			let val: f64 = rng.random();
			test_extract_components_manual(val);
		}
	}

	#[test]
	fn test_roundtrip() {
		use rand::{Rng, SeedableRng, rngs::StdRng};

		// Test roundtrip for various values
		test_extract_pack_roundtrip(1.0);
		test_extract_pack_roundtrip(2.0);
		test_extract_pack_roundtrip(3.0);
		test_extract_pack_roundtrip(-1.0);
		test_extract_pack_roundtrip(0.0);
		test_extract_pack_roundtrip(f64::INFINITY);
		test_extract_pack_roundtrip(f64::NEG_INFINITY);

		// Test random values with seeded randomness for reproducibility
		let mut rng = StdRng::seed_from_u64(1);
		for _ in 0..10 {
			let val: f64 = rng.random();
			test_extract_pack_roundtrip(val);
		}
	}
}

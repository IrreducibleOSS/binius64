// Copyright 2025 Irreducible Inc.

use std::iter::successors;

use crate::circuit_builder::CircuitBuilder;

pub fn extrapolate_line<Builder: CircuitBuilder>(
	builder: &mut Builder,
	y0: Builder::Wire,
	y1: Builder::Wire,
	z: Builder::Wire,
) -> Builder::Wire {
	// y(z) = y0 + (y1 - y0) * z
	// In binary fields, subtraction is addition (XOR)
	let diff = builder.add(y1, y0);
	let scaled = builder.mul(diff, z);
	builder.add(y0, scaled)
}

pub fn evaluate_univariate<Builder: CircuitBuilder>(
	builder: &mut Builder,
	coeffs: &[Builder::Wire],
	z: Builder::Wire,
) -> Builder::Wire {
	use binius_field::{BinaryField128bGhash as B128, Field};

	// Use Horner's method: p(z) = a0 + z(a1 + z(a2 + z(...)))
	// Start from highest degree coefficient and work backwards
	if coeffs.is_empty() {
		return builder.constant(B128::ZERO);
	}

	coeffs[..coeffs.len() - 1]
		.iter()
		.rev()
		.fold(coeffs[coeffs.len() - 1], |acc, &coeff| {
			let temp = builder.mul(acc, z);
			builder.add(temp, coeff)
		})
}

pub fn evaluate_multilinear<Builder: CircuitBuilder>(
	builder: &mut Builder,
	coeffs: &[Builder::Wire],
	coords: &[Builder::Wire],
) -> Vec<Builder::Wire> {
	// coords has length n, coeffs has length 2^n
	// Evaluation algorithm: fold over each coordinate in reverse order
	// For each coordinate, interpolate between pairs: lo + coord * (hi - lo)
	coords
		.iter()
		.rev()
		.fold(coeffs.to_vec(), |current, &coord| {
			let half_len = current.len() / 2;
			(0..half_len)
				.map(|i| {
					let lo = current[i];
					let hi = current[half_len + i];
					// Compute lo + coord * (hi - lo) = lo + coord * (hi + lo) in binary field
					let diff = builder.add(hi, lo);
					let scaled = builder.mul(coord, diff);
					builder.add(lo, scaled)
				})
				.collect()
		})
}

pub fn powers<Builder: CircuitBuilder>(
	builder: &mut Builder,
	x: Builder::Wire,
	n: usize,
) -> Vec<Builder::Wire> {
	// return a vector of n wires containing the values of x^i for i in [1, n]
	successors(Some(x), |&prev| Some(builder.mul(prev, x)))
		.take(n)
		.collect()
}

pub fn square<Builder: CircuitBuilder>(builder: &mut Builder, x: Builder::Wire) -> Builder::Wire {
	builder.mul(x, x)
}

pub fn assert_is_bit<Builder: CircuitBuilder>(builder: &mut Builder, val: Builder::Wire) {
	let val_sq = square(builder, val);
	builder.assert_eq(val_sq, val);
}

#[cfg(test)]
mod tests {
	use std::iter;

	use binius_field::{BinaryField128bGhash as B128, Field};

	use super::*;
	use crate::{
		circuit_builder::{ConstraintBuilder, WitnessGenerator},
		constraint_system::WitnessLayout,
		wire_elimination::{CostModel, run_wire_elimination},
	};

	#[test]
	fn test_square() {
		// Test x^2 for x = 5
		let x_val = B128::new(5);
		let expected = x_val * x_val;

		fn build_square_circuit<Builder: CircuitBuilder>(
			builder: &mut Builder,
			x: Builder::Wire,
			expected: Builder::Wire,
		) {
			let result = square(builder, x);
			builder.assert_eq(result, expected);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let x = constraint_builder.alloc_inout();
		let expected_out = constraint_builder.alloc_inout();
		build_square_circuit(&mut constraint_builder, x, expected_out);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let x_w = witness_gen.write_inout(x, x_val);
		let expected_w = witness_gen.write_inout(expected_out, expected);
		build_square_circuit(&mut witness_gen, x_w, expected_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_assert_is_bit_zero() {
		// Test that 0 is a valid bit
		let val = B128::ZERO;

		fn build_bit_circuit<Builder: CircuitBuilder>(builder: &mut Builder, val: Builder::Wire) {
			assert_is_bit(builder, val);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let val_wire = constraint_builder.alloc_inout();
		build_bit_circuit(&mut constraint_builder, val_wire);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let val_w = witness_gen.write_inout(val_wire, val);
		build_bit_circuit(&mut witness_gen, val_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_assert_is_bit_one() {
		// Test that 1 is a valid bit
		let val = B128::ONE;

		fn build_bit_circuit<Builder: CircuitBuilder>(builder: &mut Builder, val: Builder::Wire) {
			assert_is_bit(builder, val);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let val_wire = constraint_builder.alloc_inout();
		build_bit_circuit(&mut constraint_builder, val_wire);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let val_w = witness_gen.write_inout(val_wire, val);
		build_bit_circuit(&mut witness_gen, val_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_extrapolate_line() {
		// Test y(z) = y0 + (y1 - y0) * z
		// With y0=2, y1=5, z=3 in binary field (XOR arithmetic)
		let y0_val = B128::new(2);
		let y1_val = B128::new(5);
		let z_val = B128::new(3);
		let expected = y0_val + (y1_val + y0_val) * z_val; // In binary field, - is +

		fn build_extrapolate_circuit<Builder: CircuitBuilder>(
			builder: &mut Builder,
			y0: Builder::Wire,
			y1: Builder::Wire,
			z: Builder::Wire,
			expected: Builder::Wire,
		) {
			let result = extrapolate_line(builder, y0, y1, z);
			builder.assert_eq(result, expected);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let y0 = constraint_builder.alloc_inout();
		let y1 = constraint_builder.alloc_inout();
		let z = constraint_builder.alloc_inout();
		let expected_out = constraint_builder.alloc_inout();
		build_extrapolate_circuit(&mut constraint_builder, y0, y1, z, expected_out);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let y0_w = witness_gen.write_inout(y0, y0_val);
		let y1_w = witness_gen.write_inout(y1, y1_val);
		let z_w = witness_gen.write_inout(z, z_val);
		let expected_w = witness_gen.write_inout(expected_out, expected);
		build_extrapolate_circuit(&mut witness_gen, y0_w, y1_w, z_w, expected_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_evaluate_univariate() {
		// Test polynomial [1, 2, 3] at z=4
		// p(z) = 1 + 2*z + 3*z^2 = 1 + 2*4 + 3*16 = 1 + 8 + 48 = 57
		// But in binary field, addition is XOR
		let coeffs_vals = [B128::new(1), B128::new(2), B128::new(3)];
		let z_val = B128::new(4);
		let expected = coeffs_vals[0] + coeffs_vals[1] * z_val + coeffs_vals[2] * z_val * z_val;

		fn build_univariate_circuit<Builder: CircuitBuilder>(
			builder: &mut Builder,
			coeffs: &[Builder::Wire],
			z: Builder::Wire,
			expected: Builder::Wire,
		) {
			let result = evaluate_univariate(builder, coeffs, z);
			builder.assert_eq(result, expected);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let coeffs: Vec<_> = (0..3).map(|_| constraint_builder.alloc_inout()).collect();
		let z = constraint_builder.alloc_inout();
		let expected_out = constraint_builder.alloc_inout();
		build_univariate_circuit(&mut constraint_builder, &coeffs, z, expected_out);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let coeffs_w: Vec<_> = iter::zip(&coeffs, &coeffs_vals)
			.map(|(&wire, &val)| witness_gen.write_inout(wire, val))
			.collect();
		let z_w = witness_gen.write_inout(z, z_val);
		let expected_w = witness_gen.write_inout(expected_out, expected);
		build_univariate_circuit(&mut witness_gen, &coeffs_w, z_w, expected_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_evaluate_multilinear() {
		// Test 2-variable multilinear with coeffs [a, b, c, d] at coords [x, y]
		// Result: a(1-x)(1-y) + b*x*(1-y) + c*(1-x)*y + d*x*y
		// In binary field: result is the unique multilinear that evaluates to
		// a at (0,0), b at (1,0), c at (0,1), d at (1,1)
		let coeffs_vals = [B128::new(1), B128::new(2), B128::new(3), B128::new(4)];
		let coords_vals = [B128::new(5), B128::new(7)];

		// Manually compute expected value
		let x = coords_vals[0];
		let y = coords_vals[1];
		let expected = coeffs_vals[0] * (B128::ONE + x) * (B128::ONE + y)
			+ coeffs_vals[1] * x * (B128::ONE + y)
			+ coeffs_vals[2] * (B128::ONE + x) * y
			+ coeffs_vals[3] * x * y;

		fn build_multilinear_circuit<Builder: CircuitBuilder>(
			builder: &mut Builder,
			coeffs: &[Builder::Wire],
			coords: &[Builder::Wire],
			expected: Builder::Wire,
		) {
			let result = evaluate_multilinear(builder, coeffs, coords);
			assert_eq!(result.len(), 1);
			builder.assert_eq(result[0], expected);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let coeffs: Vec<_> = (0..4).map(|_| constraint_builder.alloc_inout()).collect();
		let coords: Vec<_> = (0..2).map(|_| constraint_builder.alloc_inout()).collect();
		let expected_out = constraint_builder.alloc_inout();
		build_multilinear_circuit(&mut constraint_builder, &coeffs, &coords, expected_out);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let coeffs_w: Vec<_> = iter::zip(&coeffs, &coeffs_vals)
			.map(|(&wire, &val)| witness_gen.write_inout(wire, val))
			.collect();
		let coords_w: Vec<_> = iter::zip(&coords, &coords_vals)
			.map(|(&wire, &val)| witness_gen.write_inout(wire, val))
			.collect();
		let expected_w = witness_gen.write_inout(expected_out, expected);
		build_multilinear_circuit(&mut witness_gen, &coeffs_w, &coords_w, expected_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}

	#[test]
	fn test_powers() {
		// Test x=2, n=4 -> [2, 4, 8, 16]
		let x_val = B128::new(2);
		let expected_vals = [
			x_val,
			x_val * x_val,
			x_val * x_val * x_val,
			x_val * x_val * x_val * x_val,
		];

		fn build_powers_circuit<Builder: CircuitBuilder>(
			builder: &mut Builder,
			x: Builder::Wire,
			expected: &[Builder::Wire],
		) {
			let result = powers(builder, x, 4);
			assert_eq!(result.len(), expected.len());
			for (r, &e) in iter::zip(&result, expected) {
				builder.assert_eq(*r, e);
			}
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let x = constraint_builder.alloc_inout();
		let expected_wires: Vec<_> = (0..4).map(|_| constraint_builder.alloc_inout()).collect();
		build_powers_circuit(&mut constraint_builder, x, &expected_wires);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let optimized_cs = ir.finalize();
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs);

		let mut witness_gen = WitnessGenerator::new(&optimized_cs, &layout);
		let x_w = witness_gen.write_inout(x, x_val);
		let expected_w: Vec<_> = iter::zip(&expected_wires, &expected_vals)
			.map(|(&wire, &val)| witness_gen.write_inout(wire, val))
			.collect();
		build_powers_circuit(&mut witness_gen, x_w, &expected_w);
		let witness = witness_gen.build();

		optimized_cs.validate(&layout, &witness);
	}
}

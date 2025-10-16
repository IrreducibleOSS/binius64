// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use std::mem;

use super::{
	circuit_builder::ConstraintSystemIR,
	constraint_system::{MulConstraint, WireKind, ZeroConstraint},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MulPosition {
	A,
	B,
	C,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UseSite {
	Add { index: u32 },
	Mul { index: u32, position: MulPosition },
}

#[derive(Debug, Clone)]
enum WireStatus {
	Pinned,
	Pruned,
	Unknown {
		/// Vector of constraints where this wire is used.
		uses: Vec<UseSite>,
	},
}

fn remove_use(uses: &mut Vec<UseSite>, use_site: &UseSite) -> Option<UseSite> {
	let use_site_idx = uses
		.iter()
		.position(|use_site_rhs| use_site_rhs == use_site)?;
	Some(uses.swap_remove(use_site_idx))
}

impl Default for WireStatus {
	fn default() -> Self {
		WireStatus::Unknown { uses: Vec::new() }
	}
}

#[derive(Debug, Clone)]
pub struct CostModel {
	pub wire_cost: u64,
	pub mul_cost: u64,
	pub ref_cost: u64,
}

impl Default for CostModel {
	fn default() -> Self {
		CostModel {
			wire_cost: 16,
			mul_cost: 2,
			ref_cost: 1,
		}
	}
}

// Passes:
// - Constant folding
// - Wire elimination
//   - inputs: Add constraints, mul constraints, wires
//   - outputs: mul constraints, wires
//
// ConstraintSystem IR over wires
//
// WitnessLayout (Separate)
// - map from subset of ConstraintWire to WitnessIndex
// - witness_size
//
// R1CS System
// - constants
// - log_public_size
// - log_witness_size
//
//
// - Wire mapping

/// Wire elimination optimization pass on ConstraintSystemIR.
///
/// Eliminates private wires from zero constraints by substitution, reducing the size
/// of the witness while maintaining constraint system validity.
pub struct WireEliminationPass {
	cost_model: CostModel,
	ir: ConstraintSystemIR,
	// Values are indices with WireKind::Private
	private_wires: Vec<WireStatus>,
}

pub fn run_wire_elimination(cost_model: CostModel, ir: ConstraintSystemIR) -> ConstraintSystemIR {
	let mut pass = WireEliminationPass::new(cost_model, ir);
	pass.run();
	pass.finish()
}

impl WireEliminationPass {
	pub fn new(cost_model: CostModel, ir: ConstraintSystemIR) -> Self {
		let mut private_wires = vec![WireStatus::default(); ir.private_wires_alive.len()];

		// TODO: Refactor the two loops below
		for (i, ZeroConstraint(term)) in ir.zero_constraints.iter().enumerate() {
			for wire in term.wires() {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize]
				{
					uses.push(UseSite::Add { index: i as u32 });
				}
			}
		}

		for (i, MulConstraint { a, b, c }) in ir.mul_constraints.iter().enumerate() {
			for (position, operand) in [
				(MulPosition::A, a),
				(MulPosition::B, b),
				(MulPosition::C, c),
			] {
				for wire in operand.wires() {
					if matches!(wire.kind, WireKind::Private)
						&& let WireStatus::Unknown { ref mut uses } =
							private_wires[wire.id as usize]
					{
						uses.push(UseSite::Mul {
							index: i as u32,
							position,
						});
					}
				}
			}
		}

		Self {
			cost_model,
			ir,
			private_wires,
		}
	}

	fn run(&mut self) {
		// Go over each ADD constraint, in order, and find its best candidate. Eliminate it if
		// there's a candidate.
		for constraint_idx in 0..self.ir.zero_constraints.len() {
			if let Some(idx) = self.pruning_candidate(constraint_idx) {
				self.eliminate(constraint_idx, idx);
			}
		}
	}

	fn pruning_candidate(&self, constraint_idx: usize) -> Option<usize> {
		let operand = &self.ir.zero_constraints[constraint_idx].0;

		let (idx, n_uses) = (0..operand.len())
			.filter_map(|idx| {
				let wire = operand.wires()[idx];
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { uses } = &self.private_wires[wire.id as usize]
				{
					Some((idx, uses.len()))
				} else {
					None
				}
			})
			.min_by_key(|(_idx, uses_len)| *uses_len)?;

		let decrement = self.cost_model.wire_cost
			+ self.cost_model.mul_cost
			+ operand.len() as u64 * self.cost_model.ref_cost;

		// For each other wire in the ADD constraint operand, we must add one reference for each
		// constraint that the eliminated wire was used in.
		let increment = (n_uses as u64) * (operand.len() as u64 - 1) * self.cost_model.ref_cost;

		if decrement > increment {
			Some(idx)
		} else {
			None
		}
	}

	fn eliminate(&mut self, constraint_idx: usize, idx: usize) {
		// Remove the constraint with `take`. Empty ADD constraints are dropped in `finish()`.
		let operand = mem::take(&mut self.ir.zero_constraints[constraint_idx].0);

		// Remove the eliminated constraint from all uses.
		let eliminated_use_site = UseSite::Add {
			index: constraint_idx as u32,
		};
		for wire in operand.wires() {
			if matches!(wire.kind, WireKind::Private)
				&& let WireStatus::Unknown { uses } = &mut self.private_wires[wire.id as usize]
			{
				remove_use(uses, &eliminated_use_site)
					.expect("invariant: uses are kept in sync by algorithm invariant");
			}
		}

		// Prune the wire and get its remaining uses.
		let wire_idx = operand.wires()[idx].id as usize;
		let WireStatus::Unknown { uses } =
			mem::replace(&mut self.private_wires[wire_idx], WireStatus::Pruned)
		else {
			unreachable!("precondition: the referenced wire in the constraint must be prunable");
		};

		// Replace the eliminated wire in all use sites.
		for use_site in uses {
			let dst_operand = match use_site {
				UseSite::Add { index } => &mut self.ir.zero_constraints[index as usize].0,
				UseSite::Mul { index, position } => {
					let constraint = &mut self.ir.mul_constraints[index as usize];
					match position {
						MulPosition::A => &mut constraint.a,
						MulPosition::B => &mut constraint.b,
						MulPosition::C => &mut constraint.c,
					}
				}
			};

			let (additions, removals) = dst_operand.merge(&operand);
			for wire in additions.wires() {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { uses } = &mut self.private_wires[wire.id as usize]
				{
					uses.push(use_site.clone());
				}
			}
			for wire in removals.wires() {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { uses } = &mut self.private_wires[wire.id as usize]
				{
					remove_use(uses, &use_site)
						.expect("invariant: uses are kept in sync by algorithm invariant");
				}
			}
		}
	}

	fn finish(mut self) -> ConstraintSystemIR {
		// Update private_wires_alive in the IR based on pruned status
		for (idx, status) in self.private_wires.iter().enumerate() {
			if matches!(status, WireStatus::Pruned) {
				self.ir.private_wires_alive[idx] = false;
			}
		}

		self.ir
	}
}

#[cfg(test)]
mod tests {
	use std::{iter, iter::successors};

	use binius_field::{BinaryField, BinaryField128bGhash as B128, Field, PackedField};

	use super::*;
	use crate::{
		circuit_builder::{CircuitBuilder, ConstraintBuilder, WitnessGenerator},
		constraint_system::WitnessLayout,
	};

	fn fibonacci<Builder: CircuitBuilder>(
		builder: &mut Builder,
		x0: Builder::Wire,
		x1: Builder::Wire,
		n: usize,
	) -> Builder::Wire {
		if n == 0 {
			return x0;
		}

		let (_xnsub1, xn) = successors(Some((x0, x1)), |&(a, b)| {
			let next = builder.mul(a, b);
			Some((b, next))
		})
		.nth(n - 1)
		.expect("closure always returns Some");

		xn
	}

	#[test]
	fn test_wire_elimination_fibonacci() {
		// Build constraint system for fibonacci(20)
		let mut constraint_builder = ConstraintBuilder::new();
		let one_wire = constraint_builder.constant(B128::ONE);
		let x0 = constraint_builder.alloc_inout();
		let x1 = constraint_builder.alloc_inout();
		let xn = constraint_builder.alloc_inout();
		let out = fibonacci(&mut constraint_builder, x0, x1, 20);
		constraint_builder.assert_eq(out, xn);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let private_wires_alive = ir.private_wires_alive.clone();
		let optimized_cs = ir.finalize(one_wire);
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs, &private_wires_alive);

		// Generate witness for optimized constraint system
		let mut witness_generator = WitnessGenerator::new(&optimized_cs, &layout);
		let x0_val = witness_generator.write_inout(x0, B128::ONE);
		let x1_val = witness_generator.write_inout(x1, B128::MULTIPLICATIVE_GENERATOR);
		let xn_val = witness_generator.write_inout(xn, B128::MULTIPLICATIVE_GENERATOR.pow(6765));
		let out_val = fibonacci(&mut witness_generator, x0_val, x1_val, 20);
		witness_generator.assert_eq(out_val, xn_val);
		let witness = witness_generator.build();

		// Validate witness against optimized constraint system
		optimized_cs.validate(&layout, &witness);

		// Verify that some optimization occurred
		let n_alive = private_wires_alive.iter().filter(|&&alive| alive).count();
		assert!(
			n_alive < private_wires_alive.len(),
			"Expected some private wires to be eliminated, but all {} are still alive",
			private_wires_alive.len()
		);
	}

	#[test]
	fn test_chain_of_adds() {
		fn chain_adds<Builder: CircuitBuilder>(
			builder: &mut Builder,
			inputs: &[Builder::Wire],
		) -> Builder::Wire {
			let mut acc = inputs[0];
			for &input in &inputs[1..] {
				acc = builder.add(acc, input);
			}
			acc
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let one_wire = constraint_builder.constant(B128::ONE);

		// Create 8 input wires and 1 sum wire
		let inputs: Vec<_> = (0..8).map(|_| constraint_builder.alloc_inout()).collect();
		let sum_wire = constraint_builder.alloc_inout();

		// Build constraint system
		let result = chain_adds(&mut constraint_builder, &inputs);
		constraint_builder.assert_eq(result, sum_wire);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let private_wires_alive = ir.private_wires_alive.clone();
		let optimized_cs = ir.finalize(one_wire);
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs, &private_wires_alive);

		// Generate test values
		let input_values: Vec<_> = (0..8).map(|i| B128::new(1u128 << i)).collect();
		let sum_value: B128 = input_values.iter().copied().sum();

		// Generate witness
		let mut witness_generator = WitnessGenerator::new(&optimized_cs, &layout);
		let input_wires: Vec<_> = iter::zip(&inputs, &input_values)
			.map(|(&wire, &value)| witness_generator.write_inout(wire, value))
			.collect();

		let result = chain_adds(&mut witness_generator, &input_wires);
		let sum = witness_generator.write_inout(sum_wire, sum_value);
		witness_generator.assert_eq(result, sum);
		let witness = witness_generator.build();

		optimized_cs.validate(&layout, &witness);

		// Verify optimization occurred
		let n_alive = private_wires_alive.iter().filter(|&&alive| alive).count();
		assert!(
			n_alive < private_wires_alive.len(),
			"Expected some private wires to be eliminated, but all {} are still alive",
			private_wires_alive.len()
		);
	}

	#[test]
	fn test_long_chain_of_adds() {
		// This circuit computes a product of of cumulative partial sums of a sequence.
		// It is designed so that long add terms are reused in multiplication constraints.
		fn chain_add_muls<Builder: CircuitBuilder>(
			builder: &mut Builder,
			inputs: &[Builder::Wire],
		) -> Builder::Wire {
			let mut add_acc = inputs[0];
			let mut mul_acc = inputs[0];
			for &input in &inputs[1..] {
				add_acc = builder.add(add_acc, input);
				mul_acc = builder.mul(mul_acc, add_acc);
			}
			mul_acc
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let one_wire = constraint_builder.constant(B128::ONE);

		// Create 40 input wires and 1 output wire
		let inputs: Vec<_> = (0..40).map(|_| constraint_builder.alloc_inout()).collect();
		let output = constraint_builder.alloc_inout();

		// Build constraint system
		let result = chain_add_muls(&mut constraint_builder, &inputs);
		constraint_builder.assert_eq(result, output);
		let ir = constraint_builder.build();
		let original_mul_constraint_count = ir.mul_constraints.len();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let private_wires_alive = ir.private_wires_alive.clone();
		let optimized_cs = ir.finalize(one_wire);
		let optimized_mul_constraint_count = optimized_cs.mul_constraints().len();

		// Assert some multiplication constraints were added in place of zero constraints.
		// This is a strict inequality because not all zero constraints should get eliminated.
		assert!(optimized_mul_constraint_count > original_mul_constraint_count);

		let layout = WitnessLayout::sparse_from_cs(&optimized_cs, &private_wires_alive);

		// Generate test values
		let input_values: Vec<_> = (0..40).map(|i| B128::new(1u128 << i)).collect();
		let (_, output_value) =
			input_values
				.iter()
				.fold((B128::ZERO, B128::ONE), |(add_acc, mul_acc), &value| {
					let add_acc = add_acc + value;
					let mul_acc = mul_acc * add_acc;
					(add_acc, mul_acc)
				});

		// Generate witness
		let mut witness_generator = WitnessGenerator::new(&optimized_cs, &layout);
		let input_wires: Vec<_> = iter::zip(&inputs, &input_values)
			.map(|(&wire, &value)| witness_generator.write_inout(wire, value))
			.collect();

		let result = chain_add_muls(&mut witness_generator, &input_wires);
		let sum = witness_generator.write_inout(output, output_value);
		witness_generator.assert_eq(result, sum);
		let witness = witness_generator.build();

		optimized_cs.validate(&layout, &witness);

		let max_mul_operand_len = optimized_cs
			.mul_constraints
			.iter()
			.map(|c| c.a.len())
			.max()
			.unwrap();
		// Assert equality with empirically determined value. The important thing is that it's far
		// less than 40 (the maximum addition chain length).
		assert_eq!(max_mul_operand_len, 12);

		// Verify optimization occurred
		let n_alive = private_wires_alive.iter().filter(|&&alive| alive).count();
		assert!(
			n_alive < private_wires_alive.len(),
			"Expected some private wires to be eliminated, but all {} are still alive",
			private_wires_alive.len()
		);
	}

	#[test]
	fn test_two_inout_equality() {
		fn assert_equality<Builder: CircuitBuilder>(
			builder: &mut Builder,
			w0: Builder::Wire,
			w1: Builder::Wire,
		) {
			builder.assert_eq(w0, w1);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let one_wire = constraint_builder.constant(B128::ONE);

		let w0 = constraint_builder.alloc_inout();
		let w1 = constraint_builder.alloc_inout();

		// Build constraint system
		assert_equality(&mut constraint_builder, w0, w1);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let private_wires_alive = ir.private_wires_alive.clone();
		let optimized_cs = ir.finalize(one_wire);
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs, &private_wires_alive);

		// Generate witness
		let value = B128::new(42);
		let mut witness_generator = WitnessGenerator::new(&optimized_cs, &layout);
		let w0_val = witness_generator.write_inout(w0, value);
		let w1_val = witness_generator.write_inout(w1, value);
		assert_equality(&mut witness_generator, w0_val, w1_val);
		let witness = witness_generator.build();

		optimized_cs.validate(&layout, &witness);

		// Verify no private wires were created
		assert_eq!(private_wires_alive.len(), 0, "Expected no private wires");
	}

	#[test]
	fn test_grouped_adds_into_mul() {
		fn grouped_adds_mul<Builder: CircuitBuilder>(
			builder: &mut Builder,
			inputs: &[Builder::Wire; 9],
		) {
			// Sum first 3 to get a
			let a = builder.add(inputs[0], inputs[1]);
			let a = builder.add(a, inputs[2]);

			// Sum second 3 to get b
			let b = builder.add(inputs[3], inputs[4]);
			let b = builder.add(b, inputs[5]);

			// Sum third 3 to get c
			let c = builder.add(inputs[6], inputs[7]);
			let c = builder.add(c, inputs[8]);

			// Return (a * b, c) for assertion
			let a_times_b = builder.mul(a, b);
			builder.assert_eq(a_times_b, c);
		}

		let mut constraint_builder = ConstraintBuilder::new();
		let one_wire = constraint_builder.constant(B128::ONE);

		// Create 9 input wires
		let inputs: Vec<_> = (0..9).map(|_| constraint_builder.alloc_inout()).collect();

		// Build constraint system: assert a * b = c where a, b, c are sums of 3 inputs each
		let inputs_array: [_; 9] = inputs.clone().try_into().unwrap();
		grouped_adds_mul(&mut constraint_builder, &inputs_array);
		let ir = constraint_builder.build();

		let ir = run_wire_elimination(CostModel::default(), ir);
		let private_wires_alive = ir.private_wires_alive.clone();
		let optimized_cs = ir.finalize(one_wire);
		let layout = WitnessLayout::sparse_from_cs(&optimized_cs, &private_wires_alive);

		// Generate test values: a = 2, b = 3, c = 6
		// In binary field: 2 * 3 = 6
		let input_values = vec![
			B128::new(2),
			B128::ZERO,
			B128::ZERO, // a = 2
			B128::new(3),
			B128::ZERO,
			B128::ZERO, // b = 3
			B128::new(6),
			B128::ZERO,
			B128::ZERO, // c = 6
		];

		// Generate witness
		let mut witness_generator = WitnessGenerator::new(&optimized_cs, &layout);
		let input_wires: Vec<_> = iter::zip(&inputs, &input_values)
			.map(|(&wire, &value)| witness_generator.write_inout(wire, value))
			.collect();

		let input_wires_array: [_; 9] = input_wires.try_into().unwrap();
		grouped_adds_mul(&mut witness_generator, &input_wires_array);
		let witness = witness_generator.build();

		optimized_cs.validate(&layout, &witness);

		// Verify optimization occurred
		let n_alive = private_wires_alive.iter().filter(|&&alive| alive).count();
		assert!(
			n_alive < private_wires_alive.len(),
			"Expected some private wires to be eliminated, but all {} are still alive",
			private_wires_alive.len()
		);
	}
}

// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use std::mem;

use super::constraint_system::{
	AddConstraint, ConstraintSystem, ConstraintWire, MulConstraint as OperandMulConstraint,
	MulConstraint, Operand, WireKind,
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

impl Default for WireStatus {
	fn default() -> Self {
		WireStatus::Unknown { uses: Vec::new() }
	}
}

pub struct WireEliminationStageOut {
	cs: ConstraintSystem,
	private_wires_alive: Vec<bool>,
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

/// The purpose of this is to do the wire-elimination transform. Rename appropriately.
///
/// Before: constants, private, public and AND constraints
pub struct WireEliminationPass {
	cost_model: CostModel,
	cs: ConstraintSystem,
	one_wire: ConstraintWire,
	// Values are indices with WireKind::Private
	private_wires: Vec<WireStatus>,
}

impl WireEliminationPass {
	#[allow(clippy::too_many_arguments)]
	pub fn new(cost_model: CostModel, cs: ConstraintSystem, one_wire: ConstraintWire) -> Self {
		assert_eq!(one_wire.kind, WireKind::Constant);

		let mut private_wires = vec![WireStatus::default(); cs.n_private() as usize];

		// TODO: Refactor the two loops below
		for (i, AddConstraint(term)) in cs.zero_constraints.iter().enumerate() {
			for wire in term.wires() {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize]
				{
					uses.push(UseSite::Add { index: i as u32 });
				}
			}
		}

		for (i, MulConstraint { a, b, c }) in cs.mul_constraints.iter().enumerate() {
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
			cs,
			one_wire,
			private_wires,
		}
	}

	fn run(&mut self) {
		// Go over each ADD constraint, in order, and find its best candidate. Eliminate it if
		// there's a candidate.
		for constraint_idx in 0..self.cs.zero_constraints.len() {
			if let Some(idx) = self.pruning_candidate(constraint_idx) {
				self.eliminate(constraint_idx, idx);
			}
		}
	}

	fn pruning_candidate(&self, constraint_idx: usize) -> Option<usize> {
		let operand = &self.cs.zero_constraints[constraint_idx].0;

		let (idx, n_uses) = (0..operand.len())
			.filter_map(|idx| {
				let wire_idx = operand.wires()[idx].id as usize;
				if let WireStatus::Unknown { uses } = &self.private_wires[wire_idx] {
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
		let operand = mem::take(&mut self.cs.zero_constraints[constraint_idx].0);

		let wire_idx = operand.wires()[idx].id as usize;
		let WireStatus::Unknown { uses } =
			mem::replace(&mut self.private_wires[wire_idx], WireStatus::Pruned)
		else {
			unreachable!("precondition: the referenced wire in the constraint must be prunable");
		};

		for use_site in uses {
			let dst_operand = match use_site {
				UseSite::Add { index } => &mut self.cs.zero_constraints[index as usize].0,
				UseSite::Mul { index, position } => {
					let constraint = &mut self.cs.mul_constraints[index as usize];
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
					let use_site_idx = uses
						.iter()
						.position(|use_site_rhs| use_site_rhs == &use_site)
						.expect("invariant: uses are kept in sync by algorithm invariant");
					uses.remove(use_site_idx);
				}
			}
		}
	}

	/*
	fn cost_of_replacement(&self, constraint_idx: usize, wire_idx: usize) -> Option<(u64, u64)> {
		let operand = &self.add_constraints[constraint_idx];
		let WireStatus::Unknown { uses } = &self.private_wires[wire_idx] else {
			return None;
		};

		let decrement = self.cost_model.wire_cost
			+ self.cost_model.mul_cost
			+ operand.0.len() as u64 * self.cost_model.ref_cost;

		// For each other wire in the ADD constraint operand, we must add one reference for each
		// constraint that the eliminated wire was used in.
		let increment =
			(uses.len() as u64) * (operand.0.len() as u64 - 1) * self.cost_model.ref_cost;

		Some((decrement, increment))
	}
	 */

	fn finish(self) -> WireEliminationStageOut {
		let Self {
			cost_model: _,
			mut cs,
			one_wire,
			private_wires,
		} = self;

		// Replace all zero constraints with mul constraints
		let one_operand = Operand::from(one_wire);
		let zero_operand = Operand::default();
		for AddConstraint(operand) in mem::take(&mut cs.zero_constraints) {
			if !operand.is_empty() {
				cs.mul_constraints.push(OperandMulConstraint {
					a: operand,
					b: one_operand.clone(),
					c: zero_operand.clone(),
				});
			}
		}

		let private_wires_alive = private_wires
			.into_iter()
			.map(|status| !matches!(status, WireStatus::Pruned))
			.collect::<Vec<_>>();

		WireEliminationStageOut {
			cs,
			private_wires_alive,
		}
	}
}

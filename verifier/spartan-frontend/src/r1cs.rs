// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use std::{cmp::Ordering, mem};

use binius_field::BinaryField128bGhash as B128;
use smallvec::{SmallVec, smallvec};

use crate::{AddConstraint, ConstraintWire, MulConstraint, WireKind};

struct OperandMulConstraint {
	a: Operand,
	b: Operand,
	c: Operand,
}

#[derive(Debug, Default, Clone)]
struct Operand(SmallVec<[ConstraintWire; 4]>);

impl Operand {
	// TODO: unit test this
	pub fn new(mut term: SmallVec<[ConstraintWire; 4]>) -> Self {
		term.sort_unstable();

		let has_duplicate_wire = term.windows(2).any(|w| w[0] == w[1]);
		let term = if has_duplicate_wire {
			term.chunk_by(|a, b| a == b)
				.flat_map(|group| {
					// Group is a slice of wires that are all equal. We want to return an empty
					// iterator if the group is even length and a singleton iterator otherwise.
					let last_even_idx = group.len() / 2 * 2;
					group[last_even_idx..].iter().copied()
				})
				.collect()
		} else {
			term
		};

		Self(term)
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	fn merge(&mut self, rhs: &Self) -> (Operand, Operand) {
		// Classic merge algorithm for sorted vectors, but where duplicate items cancel out.
		let lhs = mem::take(&mut self.0);
		let dst = &mut self.0;

		let mut lhs_iter = lhs.into_iter().peekable();
		let mut rhs_iter = rhs.0.iter().copied().peekable();

		let mut additions = Operand::default();
		let mut removals = Operand::default();

		loop {
			match (lhs_iter.peek(), rhs_iter.peek()) {
				(Some(next_lhs), Some(next_rhs)) => {
					match next_lhs.cmp(next_rhs) {
						Ordering::Equal => {
							// Advance both iterators, but don't push the wires because they cancel.
							let wire = lhs_iter.next().expect("peek returned Some");
							let _ = rhs_iter.next().expect("peek returned Some");

							removals.0.push(wire);
						}
						Ordering::Less => dst.push(lhs_iter.next().expect("peek returned Some")),
						Ordering::Greater => {
							let wire = rhs_iter.next().expect("peek returned Some");
							additions.0.push(wire);
							dst.push(wire);
						}
					}
				}
				(Some(_), None) => dst.push(lhs_iter.next().expect("peek returned Some")),
				(None, Some(_)) => {
					let wire = rhs_iter.next().expect("peek returned Some");
					additions.0.push(wire);
					dst.push(wire);
				}
				(None, None) => break,
			}
		}

		(additions, removals)
	}
}

impl From<ConstraintWire> for Operand {
	fn from(value: ConstraintWire) -> Self {
		Operand(smallvec![value])
	}
}

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
	constants: Vec<B128>,
	// // TODO: This can just be a vec with binary search, BTreeMap not necessary.
	// index_map: BTreeMap<ConstraintWire, WitnessIndex>,
	add_constraints: Vec<Operand>,
	mul_constraints: Vec<OperandMulConstraint>,
	// Values are indices with WireKind::Private
	private_wires: Vec<WireStatus>,
}

pub struct CostModel {
	pub wire_cost: u64,
	pub mul_cost: u64,
	pub ref_cost: u64,
}

// Passes:
// - Constant folding
// - Wire elimination
//   - inputs: Add constraints, mul constraints, wires
//   - outputs: mul constraints, wires
// - Wire mapping

/// The purpose of this is to do the wire-elimination transform. Rename appropriately.
///
/// Before: constants, private, public and AND constraints
pub struct R1CS {
	cost_model: CostModel,
	constants: Vec<B128>,
	// // TODO: This can just be a vec with binary search, BTreeMap not necessary.
	// index_map: BTreeMap<ConstraintWire, WitnessIndex>,
	add_constraints: Vec<Operand>,
	mul_constraints: Vec<OperandMulConstraint>,
	// Values are indices with WireKind::Private
	private_wires: Vec<WireStatus>,
}

impl R1CS {
	pub fn new(
		_n_constant: usize,
		_n_public: usize,
		n_private: usize,
		cost_model: CostModel,
		constants: Vec<B128>, //HashMap<B128, u32>,
		add_constraints: Vec<AddConstraint>,
		mul_constraints: Vec<MulConstraint>,
	) -> Self {
		let mut private_wires = vec![WireStatus::default(); n_private];

		let mut r1cs_add_constraints = Vec::with_capacity(add_constraints.len());
		for (i, AddConstraint(term)) in add_constraints.into_iter().enumerate() {
			for wire in &term {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize]
				{
					uses.push(UseSite::Add { index: i as u32 });
				}
			}
			r1cs_add_constraints.push(Operand::new(term));
		}

		let mut r1cs_mul_constraints = Vec::with_capacity(mul_constraints.len());
		for (i, MulConstraint { a, b, c }) in mul_constraints.into_iter().enumerate() {
			for (position, wire) in [
				(MulPosition::A, a),
				(MulPosition::B, b),
				(MulPosition::C, c),
			] {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize]
				{
					uses.push(UseSite::Mul {
						index: i as u32,
						position,
					});
				}
			}
			r1cs_mul_constraints.push(OperandMulConstraint {
				a: a.into(),
				b: b.into(),
				c: c.into(),
			});
		}

		Self {
			cost_model,
			constants,
			add_constraints: r1cs_add_constraints,
			mul_constraints: r1cs_mul_constraints,
			private_wires,
		}
	}

	fn optimize_pass(&mut self) {
		// Go over each ADD constraint, in order, and find its best candidate. Eliminate it if
		// there's a candidate.
		for constraint_idx in 0..self.add_constraints.len() {
			if let Some(idx) = self.pruning_candidate(constraint_idx) {
				self.eliminate(constraint_idx, idx);
			}
		}
	}

	fn pruning_candidate(&self, constraint_idx: usize) -> Option<usize> {
		let operand = &self.add_constraints[constraint_idx];

		let (idx, n_uses) = (0..operand.len())
			.filter_map(|idx| {
				let wire_idx = operand.0[idx].id as usize;
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
		let operand = mem::take(&mut self.add_constraints[constraint_idx]);

		let wire_idx = operand.0[idx].id as usize;
		let WireStatus::Unknown { uses } =
			mem::replace(&mut self.private_wires[wire_idx], WireStatus::Pruned)
		else {
			unreachable!("precondition: the referenced wire in the constraint must be prunable");
		};

		for use_site in uses {
			let dst_operand = match use_site {
				UseSite::Add { index } => &mut self.add_constraints[index as usize],
				UseSite::Mul { index, position } => {
					let constraint = &mut self.mul_constraints[index as usize];
					match position {
						MulPosition::A => &mut constraint.a,
						MulPosition::B => &mut constraint.b,
						MulPosition::C => &mut constraint.c,
					}
				}
			};

			let (additions, removals) = dst_operand.merge(&operand);
			for wire in additions.0 {
				if matches!(wire.kind, WireKind::Private)
					&& let WireStatus::Unknown { uses } = &mut self.private_wires[wire.id as usize]
				{
					uses.push(use_site.clone());
				}
			}
			for wire in removals.0 {
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
		todo!()
	}
}

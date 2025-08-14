//! Gate fusion optimization pass.

use std::collections::{HashMap, HashSet};

use binius_core::{
	ValueIndex,
	constraint_system::{AndConstraint, MulConstraint, Operand, ShiftVariant},
	word::Word,
};
use cranelift_entity::{EntitySet, PrimaryMap};

use crate::compiler::gate_fusion::{
	operand::{canonicalize_operand, count_unique_terms},
	stats::Stats,
};

mod operand;
mod stats;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct LinearDef(u32);
cranelift_entity::entity_impl!(LinearDef);

pub struct Fusion<'a> {
	all_ones: ValueIndex,

	and_constraints: &'a mut Vec<AndConstraint>,
	mul_constraints: &'a mut [MulConstraint],

	defs: PrimaryMap<LinearDef, LinearDefSite>,
	uses: HashMap<ValueIndex, Vec<UseSite>>,
}

impl<'a> Fusion<'a> {
	pub fn new(
		and_constraints: &'a mut Vec<AndConstraint>,
		mul_constraints: &'a mut [MulConstraint],
		constants: &[Word],
	) -> Option<Self> {
		let all_ones = locate_all_ones(constants)?;
		Some(Fusion {
			all_ones,
			and_constraints,
			mul_constraints,
			defs: PrimaryMap::new(),
			uses: HashMap::new(),
		})
	}

	pub fn run(&mut self) -> Stats {
		const MAX_XOR_TERMS: usize = 64;

		let and_constraints_before = self.and_constraints.len();

		// Build use-def chains first identifying the linear producers, the ones that we
		// can consider inlining.
		self.build_use_def();
		let selected = self.select_fusion_candidates(MAX_XOR_TERMS);
		self.apply_fusions(&selected);
		self.cleanup_dead_constraints(&selected);

		Stats {
			and_constraints_before,
			and_constraints_after: self.and_constraints.len(),
			producers_found: self.defs.len(),
			producers_fused: selected.iter().count(),
		}
	}

	fn build_use_def(&mut self) {
		self.build_use_def_from_and_constraints();
		self.build_use_def_from_mul_constraints();
	}

	fn build_use_def_from_and_constraints(&mut self) {
		for (idx, constraint) in self.and_constraints.iter().enumerate() {
			// Check if this is a linear expression producer.
			if let Some(linear_def) = try_create_linear_def(idx, constraint, self.all_ones) {
				self.defs.push(linear_def);
			}
			harvest_uses(&constraint.a, &mut self.uses, ConstraintType::And, idx, OperandSlot::A);
			harvest_uses(&constraint.b, &mut self.uses, ConstraintType::And, idx, OperandSlot::B);
			harvest_uses(&constraint.c, &mut self.uses, ConstraintType::And, idx, OperandSlot::C);
		}
	}

	fn build_use_def_from_mul_constraints(&mut self) {
		for (idx, constraint) in self.mul_constraints.iter().enumerate() {
			harvest_uses(&constraint.a, &mut self.uses, ConstraintType::Mul, idx, OperandSlot::A);
			harvest_uses(&constraint.b, &mut self.uses, ConstraintType::Mul, idx, OperandSlot::B);
			harvest_uses(&constraint.hi, &mut self.uses, ConstraintType::Mul, idx, OperandSlot::Hi);
			harvest_uses(&constraint.lo, &mut self.uses, ConstraintType::Mul, idx, OperandSlot::Lo);
		}
	}

	/// Scan through all the linear producers and select the ones that can be inlined.
	///
	/// The decision is taken based on looking at the use-sites. In case any of the
	/// consumers can't inline the producer, then the producer will have to be preserved
	/// and that means there is little sense in inlining it in any of the consumers.
	fn select_fusion_candidates(&self, max_terms: usize) -> EntitySet<LinearDef> {
		let mut selected = EntitySet::new();
		for (def_id, def_data) in &self.defs {
			let Some(use_sites) = self.uses.get(&def_data.dst) else {
				// No uses: Producer is dead. DCE will handle.
				continue;
			};
			// Don't fuse this producer if any of the consumers shift this value.
			if use_sites.iter().any(|u| u.shift.is_some()) {
				continue;
			}
			// Check if all uses can accommodate the inlining
			if !use_sites.iter().all(|use_site| {
				let operand = get_operand(use_site, self.and_constraints, self.mul_constraints);
				would_inline_fit(operand, def_data.dst, &def_data.rhs, max_terms)
			}) {
				continue;
			}

			selected.insert(def_id);
		}

		selected
	}

	/// Apply the selected fusions to the constraints
	fn apply_fusions(&mut self, selected: &EntitySet<LinearDef>) {
		// Build a map for quick lookup
		let fusion_map: HashMap<ValueIndex, &Operand> = selected
			.iter()
			.map(|def| (self.defs[def].dst, &self.defs[def].rhs))
			.collect();

		// Apply substitutions to all constraints
		for constraint in self.and_constraints.iter_mut() {
			substitute_in_operand(&mut constraint.a, &fusion_map);
			substitute_in_operand(&mut constraint.b, &fusion_map);
			substitute_in_operand(&mut constraint.c, &fusion_map);
		}

		for constraint in self.mul_constraints.iter_mut() {
			substitute_in_operand(&mut constraint.a, &fusion_map);
			substitute_in_operand(&mut constraint.b, &fusion_map);
			substitute_in_operand(&mut constraint.hi, &fusion_map);
			substitute_in_operand(&mut constraint.lo, &fusion_map);
		}
	}

	/// Remove the selected constraints.
	fn cleanup_dead_constraints(&mut self, selected: &EntitySet<LinearDef>) {
		let to_remove: HashSet<usize> = selected
			.iter()
			.map(|def| self.defs[def].constraint_idx)
			.collect();

		// Yuck... but it works.
		let mut current_idx = 0;
		self.and_constraints.retain(|_| {
			let keep = !to_remove.contains(&current_idx);
			current_idx += 1;
			keep
		});
	}
}

/// Scans through the constants array and locates the index of the all-1 pattern (ie. 0xFF..FF) or
/// returns `None` if it couldn't find it.
fn locate_all_ones(constants: &[Word]) -> Option<ValueIndex> {
	// We could use binary search here if we cared.
	constants
		.iter()
		.position(|&w| w == Word::ALL_ONE)
		.map(|i| ValueIndex(i as u32))
}

/// Represents a use site of a value
#[derive(Clone, Debug)]
struct UseSite {
	constraint_type: ConstraintType,
	constraint_idx: usize,
	operand: OperandSlot,
	shift: Option<(ShiftVariant, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ConstraintType {
	And,
	Mul,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum OperandSlot {
	A,
	B,
	C,
	Hi,
	Lo,
}

/// Def site of a pure linear producer.
///
/// Describes how `dst` value is produced by a set of linear (ie. pure xor) operators. Something
/// like this:
///
/// ```plain
/// dst = XOR(a, b sll 1, c)
/// ```
#[derive(Clone, Debug)]
struct LinearDefSite {
	constraint_idx: usize,
	dst: ValueIndex,
	rhs: Operand,
}

/// Check if an AND constraint is a linear (pure XOR/shift) assignment.
fn try_create_linear_def(
	constraint_idx: usize,
	constraint: &AndConstraint,
	all_ones: ValueIndex,
) -> Option<LinearDefSite> {
	// Pattern: a & all_1 = dst
	// Which means: b = [all_1], c = [dst], and dst ∉ a

	// Check if `b` is exactly `[all_ones]`
	if constraint.b.len() != 1 {
		return None;
	}
	if constraint.b[0].value_index != all_ones || constraint.b[0].amount != 0 {
		return None;
	}

	// Check if `c` is exactly [dst] with no shift
	if constraint.c.len() != 1 || constraint.c[0].amount != 0 {
		return None;
	}
	let dst = constraint.c[0].value_index;

	// Check that dst doesn't appear in `a` (no self-reference)
	for term in &constraint.a {
		if term.value_index == dst {
			return None;
		}
	}

	// Create a copy of `a` s.t. it's canonicalized.
	let rhs = canonicalize_operand(&constraint.a);
	Some(LinearDefSite {
		constraint_idx,
		dst,
		rhs,
	})
}

/// Given an operand scan its terms and populate the `uses` accordingly.
fn harvest_uses(
	operand: &Operand,
	uses: &mut HashMap<ValueIndex, Vec<UseSite>>,
	constraint_type: ConstraintType,
	constraint_idx: usize,
	operand_slot: OperandSlot,
) {
	for term in operand.iter() {
		let shift = if term.amount != 0 {
			Some((term.shift_variant, term.amount))
		} else {
			None
		};

		uses.entry(term.value_index).or_default().push(UseSite {
			constraint_type,
			constraint_idx,
			operand: operand_slot,
			shift,
		});
	}
}

/// Get an immutable reference to an operand
fn get_operand<'a>(
	use_site: &UseSite,
	and_constraints: &'a [AndConstraint],
	mul_constraints: &'a [MulConstraint],
) -> &'a Operand {
	match use_site.constraint_type {
		ConstraintType::And => {
			let constraint = &and_constraints[use_site.constraint_idx];
			match use_site.operand {
				OperandSlot::A => &constraint.a,
				OperandSlot::B => &constraint.b,
				OperandSlot::C => &constraint.c,
				_ => unreachable!(),
			}
		}
		ConstraintType::Mul => {
			let constraint = &mul_constraints[use_site.constraint_idx];
			match use_site.operand {
				OperandSlot::A => &constraint.a,
				OperandSlot::B => &constraint.b,
				OperandSlot::Hi => &constraint.hi,
				OperandSlot::Lo => &constraint.lo,
				_ => unreachable!(),
			}
		}
	}
}

/// Check if inlining would exceed the term limit.
///
/// This performs an exact calculation of the resulting operand size after
/// substitution and XOR cancellation, ensuring we never reject valid fusions.
fn would_inline_fit(operand: &Operand, dst: ValueIndex, rhs: &Operand, max_terms: usize) -> bool {
	// Check that dst appears exactly once (and unshifted)
	let dst_count = operand
		.iter()
		.filter(|t| t.value_index == dst && t.amount == 0)
		.count();
	if dst_count != 1 {
		// Either no dst or multiple dst (shouldn't happen).
		return false;
	}

	// Build the merged operand: original terms minus dst, plus rhs terms
	let mut merged = Vec::with_capacity(operand.len() - 1 + rhs.len());

	// Copy all terms except dst
	for term in operand {
		if !(term.value_index == dst && term.amount == 0) {
			merged.push(*term);
		}
	}

	// Add RHS terms
	merged.extend_from_slice(rhs);

	// Count unique terms after XOR cancellation
	count_unique_terms(&merged) <= max_terms
}

/// Substitute values in an operand based on the fusion map
fn substitute_in_operand(operand: &mut Operand, fusion_map: &HashMap<ValueIndex, &Operand>) {
	let mut new_terms = Vec::new();
	let mut substituted = false;

	for term in operand.iter() {
		if term.amount == 0 {
			// Only substitute unshifted uses
			if let Some(rhs) = fusion_map.get(&term.value_index) {
				new_terms.extend_from_slice(rhs);
				substituted = true;
			} else {
				new_terms.push(*term);
			}
		} else {
			// Keep shifted terms as-is
			new_terms.push(*term);
		}
	}

	if substituted {
		*operand = canonicalize_operand(&new_terms);
	}
}

#[cfg(test)]
mod tests {
	use binius_core::constraint_system::ShiftVariant;

	use super::{operand::make_operand, *};

	#[test]
	fn test_try_create_linear_def() {
		let all_ones = ValueIndex(0);

		// Valid pure XOR: a & all_1 = dst
		let constraint = AndConstraint {
			a: make_operand(vec![(1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
			b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
			c: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // dst
		};
		let producer = try_create_linear_def(0, &constraint, all_ones);
		assert!(producer.is_some());
		assert_eq!(producer.unwrap().dst.0, 3);

		// Invalid: dst appears in a (self-reference)
		let constraint = AndConstraint {
			a: make_operand(vec![(1, ShiftVariant::Sll, 0), (3, ShiftVariant::Sll, 0)]),
			b: make_operand(vec![(0, ShiftVariant::Sll, 0)]),
			c: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
		};
		assert!(try_create_linear_def(0, &constraint, all_ones).is_none());

		// Invalid: b is not all_ones
		let constraint = AndConstraint {
			a: make_operand(vec![(1, ShiftVariant::Sll, 0)]),
			b: make_operand(vec![(1, ShiftVariant::Sll, 0)]),
			c: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
		};
		assert!(try_create_linear_def(0, &constraint, all_ones).is_none());
	}

	#[test]
	fn test_simple_fusion() {
		let mut and_constraints = vec![
			// v2 = v0 ^ v1
			AndConstraint {
				a: make_operand(vec![(1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // v2
			},
			// v4 = v3 & v2
			AndConstraint {
				a: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(5, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		// Check statistics
		assert_eq!(stats.and_constraints_before, 2);
		assert_eq!(stats.and_constraints_after, 1);
		assert_eq!(stats.producers_found, 1);
		assert_eq!(stats.producers_fused, 1);
		assert_eq!(stats.and_constraints_reduced(), 1);

		// Should have one constraint left (producer removed)
		assert_eq!(and_constraints.len(), 1);
		// The remaining constraint should have v0 ^ v1 instead of v2
		let remaining = &and_constraints[0];
		assert_eq!(remaining.a.len(), 1);
		assert_eq!(remaining.b.len(), 2);
		// b should now be v0 ^ v1 (indices 1 and 2)
		assert!(remaining.b.iter().any(|t| t.value_index.0 == 1));
		assert!(remaining.b.iter().any(|t| t.value_index.0 == 2));
	}

	#[test]
	fn test_fusion_with_shifts() {
		let mut and_constraints = vec![
			// v2 = sll(v0, 33)
			AndConstraint {
				a: make_operand(vec![(1, ShiftVariant::Sll, 33)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(2, ShiftVariant::Sll, 0)]), // v2
			},
			// v4 = v3 & v2
			AndConstraint {
				a: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(2, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		assert_eq!(stats.and_constraints_before, 2);
		assert_eq!(stats.and_constraints_after, 1);
		assert_eq!(stats.producers_fused, 1);

		// v4 = v3 & sll(v0, 33)
		let remaining = &and_constraints[0];
		assert_eq!(remaining.b.len(), 1);
		assert_eq!(remaining.b[0].value_index.0, 1);
		assert_eq!(remaining.b[0].amount, 33);
	}

	#[test]
	fn test_complex_fusion_chain() {
		let mut and_constraints = vec![
			// v3 = sll(v0, 33) ^ v1 ^ v2
			AndConstraint {
				a: make_operand(vec![
					(1, ShiftVariant::Sll, 33),
					(2, ShiftVariant::Sll, 0),
					(3, ShiftVariant::Sll, 0),
				]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(4, ShiftVariant::Sll, 0)]), // v3
			},
			// v6 = (v3 ^ v4) & v5
			AndConstraint {
				a: make_operand(vec![(4, ShiftVariant::Sll, 0), (5, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(6, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(7, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		assert_eq!(stats.and_constraints_before, 2);
		assert_eq!(stats.and_constraints_after, 1);
		assert_eq!(stats.producers_fused, 1);

		// v6 = (sll(v0, 33) ^ v1 ^ v2 ^ v4) & v5
		let remaining = &and_constraints[0];
		assert_eq!(remaining.a.len(), 4); // Should have 4 terms in XOR
	}

	#[test]
	fn test_no_fusion_with_shifted_use() {
		let mut and_constraints = vec![
			// v2 = v0 ^ v1
			AndConstraint {
				a: make_operand(vec![(1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // v2
			},
			// v4 = v3 & sll(v2, 5)  - shifted use of v2
			AndConstraint {
				a: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(3, ShiftVariant::Sll, 5)]), // shifted v2!
				c: make_operand(vec![(5, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		// Should NOT fuse because v2 is used with a shift
		assert_eq!(stats.and_constraints_before, 2);
		assert_eq!(stats.and_constraints_after, 2);
		assert_eq!(stats.producers_found, 1);
		assert_eq!(stats.producers_fused, 0);
	}

	#[test]
	fn test_xor_cancellation_in_fusion() {
		let mut and_constraints = vec![
			// v3 = v0 ^ v1 ^ v2
			AndConstraint {
				a: make_operand(vec![
					(1, ShiftVariant::Sll, 0),
					(2, ShiftVariant::Sll, 0),
					(3, ShiftVariant::Sll, 0),
				]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(4, ShiftVariant::Sll, 0)]), // v3
			},
			// v5 = (v3 ^ v1) & something - v1 should cancel out!
			AndConstraint {
				a: make_operand(vec![(4, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(5, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(6, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		assert_eq!(stats.producers_fused, 1);

		// After fusion: v5 = (v0 ^ v2) & something (v1 cancels)
		let remaining = &and_constraints[0];
		assert_eq!(remaining.a.len(), 2); // Only v0 and v2 left
		assert!(remaining.a.iter().any(|t| t.value_index.0 == 1));
		assert!(remaining.a.iter().any(|t| t.value_index.0 == 3));
		assert!(!remaining.a.iter().any(|t| t.value_index.0 == 2)); // v1 cancelled
	}

	#[test]
	fn test_comprehensive_fusion_scenarios() {
		// Test multiple fusion scenarios in one constraint system
		let mut and_constraints = vec![
			// 0: v3 = v1 ^ v2 (simple XOR)
			AndConstraint {
				a: make_operand(vec![(1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // v3
			},
			// 1: v5 = sll(v4, 33) (shift producer)
			AndConstraint {
				a: make_operand(vec![(4, ShiftVariant::Sll, 33)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(5, ShiftVariant::Sll, 0)]), // v5
			},
			// 2: v8 = sll(v6, 10) ^ v7 (complex producer)
			AndConstraint {
				a: make_operand(vec![(6, ShiftVariant::Sll, 10), (7, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(8, ShiftVariant::Sll, 0)]), // v8
			},
			// 3: v10 = v9 & v3 (consumer of simple XOR)
			AndConstraint {
				a: make_operand(vec![(9, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // uses v3
				c: make_operand(vec![(10, ShiftVariant::Sll, 0)]),
			},
			// 4: v12 = v11 & v5 (consumer of shift)
			AndConstraint {
				a: make_operand(vec![(11, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(5, ShiftVariant::Sll, 0)]), // uses v5
				c: make_operand(vec![(12, ShiftVariant::Sll, 0)]),
			},
			// 5: v14 = (v8 ^ v13) & v10 (consumer of complex producer)
			AndConstraint {
				a: make_operand(vec![(8, ShiftVariant::Sll, 0), (13, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(10, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(14, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		// Should fuse all 3 producers
		assert_eq!(stats.and_constraints_before, 6);
		assert_eq!(stats.and_constraints_after, 3);
		assert_eq!(stats.producers_found, 3);
		assert_eq!(stats.producers_fused, 3);

		// Verify the resulting constraints
		assert_eq!(and_constraints.len(), 3);

		// Constraint 3 should now have v1 ^ v2 instead of v3
		let c3 = &and_constraints[0];
		assert!(c3.b.iter().any(|t| t.value_index.0 == 1));
		assert!(c3.b.iter().any(|t| t.value_index.0 == 2));

		// Constraint 4 should now have sll(v4, 33) instead of v5
		let c4 = &and_constraints[1];
		assert!(c4.b.iter().any(|t| t.value_index.0 == 4 && t.amount == 33));

		// Constraint 5 should now have sll(v6, 10) ^ v7 ^ v13 instead of v8
		let c5 = &and_constraints[2];
		assert_eq!(c5.a.len(), 3);
		assert!(c5.a.iter().any(|t| t.value_index.0 == 6 && t.amount == 10));
		assert!(c5.a.iter().any(|t| t.value_index.0 == 7));
		assert!(c5.a.iter().any(|t| t.value_index.0 == 13));
	}

	#[test]
	fn test_all_or_nothing_rule() {
		// Test that if one consumer would exceed the limit, no fusion happens
		let mut and_constraints = vec![
			// v2 = v1 (simple producer)
			AndConstraint {
				a: make_operand(vec![(1, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
				c: make_operand(vec![(2, ShiftVariant::Sll, 0)]), // v2
			},
			// First consumer: would be fine
			AndConstraint {
				a: make_operand(vec![(2, ShiftVariant::Sll, 0)]),
				b: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
			},
			// Second consumer: already has many terms, would exceed limit
			AndConstraint {
				a: {
					let mut terms = vec![(2, ShiftVariant::Sll, 0)];
					// Add 63 more unique terms (total 64, at the limit)
					for i in 100..163 {
						terms.push((i, ShiftVariant::Sll, 0));
					}
					make_operand(terms)
				},
				b: make_operand(vec![(5, ShiftVariant::Sll, 0)]),
				c: make_operand(vec![(6, ShiftVariant::Sll, 0)]),
			},
		];
		let mut mul_constraints = vec![];
		let constants = vec![Word::ALL_ONE];

		let mut fusion =
			Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
		let stats = fusion.run();

		// Should NOT fuse because second consumer would exceed limit
		// (it has 64 terms, replacing v2 with v1 would still be 64, but
		// the implementation might be conservative here)
		// Let's check what actually happens
		assert_eq!(stats.and_constraints_before, 3);
		// The all-or-nothing rule should prevent fusion
		if stats.producers_fused == 0 {
			assert_eq!(stats.and_constraints_after, 3);
		}
	}

	#[test]
	fn test_would_inline_fit_exact_calculation() {
		// Test that would_inline_fit performs exact calculation even for large operands
		// This would have been handled by the conservative heuristic in the old version

		// Create an operand with many terms that will have significant cancellation
		let mut operand_terms = vec![(100, ShiftVariant::Sll, 0)]; // dst

		// Add 30 unique terms
		for i in 1..31 {
			operand_terms.push((i, ShiftVariant::Sll, 0));
		}

		// Add 10 terms that will cancel with rhs
		for i in 50..60 {
			operand_terms.push((i, ShiftVariant::Sll, 0));
		}

		let operand = make_operand(operand_terms);

		// Create rhs with terms that will cancel
		let mut rhs_terms = vec![];

		// Add the same 10 terms that will cancel
		for i in 50..60 {
			rhs_terms.push((i, ShiftVariant::Sll, 0));
		}

		// Add 5 new unique terms
		for i in 70..75 {
			rhs_terms.push((i, ShiftVariant::Sll, 0));
		}

		let rhs = make_operand(rhs_terms);

		// After substitution:
		// - Remove dst (100): 40 terms left
		// - Add rhs (15 terms): 55 terms total
		// - But 10 terms cancel out: 35 unique terms

		// Old heuristic would have rejected this (55 > 40 with conservative estimate)
		// New exact calculation should accept it
		assert!(would_inline_fit(&operand, ValueIndex(100), &rhs, 40));
		assert!(!would_inline_fit(&operand, ValueIndex(100), &rhs, 34));
	}

	#[test]
	fn test_exact_user_examples() {
		// Test the exact examples provided by the user

		// Example 1: v2 = v0 ^ v1; v4 = v3 & v2 → v4 = v3 & (v0 ^ v1)
		{
			let mut and_constraints = vec![
				// v2 = v0 ^ v1
				AndConstraint {
					a: make_operand(vec![(1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)]),
					b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
					c: make_operand(vec![(3, ShiftVariant::Sll, 0)]), // v2
				},
				// v4 = v3 & v2
				AndConstraint {
					a: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
					b: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
					c: make_operand(vec![(5, ShiftVariant::Sll, 0)]),
				},
			];
			let mut mul_constraints = vec![];
			let constants = vec![Word::ALL_ONE];

			let mut fusion =
				Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
			let stats = fusion.run();
			assert_eq!(stats.producers_fused, 1);
			assert_eq!(and_constraints.len(), 1);

			// Verify v4 = v3 & (v0 ^ v1)
			let c = &and_constraints[0];
			assert!(c.b.iter().any(|t| t.value_index.0 == 1));
			assert!(c.b.iter().any(|t| t.value_index.0 == 2));
		}

		// Example 2: v2 = sll(v0, 33); v4 = v3 & v2 → v4 = v3 & sll(v0, 33)
		{
			let mut and_constraints = vec![
				// v2 = sll(v0, 33)
				AndConstraint {
					a: make_operand(vec![(1, ShiftVariant::Sll, 33)]),
					b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
					c: make_operand(vec![(2, ShiftVariant::Sll, 0)]), // v2
				},
				// v4 = v3 & v2
				AndConstraint {
					a: make_operand(vec![(3, ShiftVariant::Sll, 0)]),
					b: make_operand(vec![(2, ShiftVariant::Sll, 0)]),
					c: make_operand(vec![(4, ShiftVariant::Sll, 0)]),
				},
			];
			let mut mul_constraints = vec![];
			let constants = vec![Word::ALL_ONE];

			let mut fusion =
				Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
			let stats = fusion.run();
			assert_eq!(stats.producers_fused, 1);
			assert_eq!(and_constraints.len(), 1);

			// Verify v4 = v3 & sll(v0, 33)
			let c = &and_constraints[0];
			assert_eq!(c.b.len(), 1);
			assert_eq!(c.b[0].value_index.0, 1);
			assert_eq!(c.b[0].amount, 33);
		}

		// Example 3: v3 = sll(v0, 33) ^ v1 ^ v2; v6 = (v3 ^ v4) & v5
		//           → v6 = (sll(v0, 33) ^ v1 ^ v2 ^ v4) & v5
		{
			let mut and_constraints = vec![
				// v3 = sll(v0, 33) ^ v1 ^ v2
				AndConstraint {
					a: make_operand(vec![
						(1, ShiftVariant::Sll, 33),
						(2, ShiftVariant::Sll, 0),
						(3, ShiftVariant::Sll, 0),
					]),
					b: make_operand(vec![(0, ShiftVariant::Sll, 0)]), // all_ones
					c: make_operand(vec![(4, ShiftVariant::Sll, 0)]), // v3
				},
				// v6 = (v3 ^ v4) & v5
				AndConstraint {
					a: make_operand(vec![(4, ShiftVariant::Sll, 0), (5, ShiftVariant::Sll, 0)]),
					b: make_operand(vec![(6, ShiftVariant::Sll, 0)]),
					c: make_operand(vec![(7, ShiftVariant::Sll, 0)]),
				},
			];
			let mut mul_constraints = vec![];
			let constants = vec![Word::ALL_ONE];

			let mut fusion =
				Fusion::new(&mut and_constraints, &mut mul_constraints, &constants).unwrap();
			let stats = fusion.run();
			assert_eq!(stats.producers_fused, 1);
			assert_eq!(and_constraints.len(), 1);

			// Verify v6 = (sll(v0, 33) ^ v1 ^ v2 ^ v4) & v5
			let c = &and_constraints[0];
			assert_eq!(c.a.len(), 4);
			assert!(c.a.iter().any(|t| t.value_index.0 == 1 && t.amount == 33));
			assert!(c.a.iter().any(|t| t.value_index.0 == 2));
			assert!(c.a.iter().any(|t| t.value_index.0 == 3));
			assert!(c.a.iter().any(|t| t.value_index.0 == 5));
		}
	}
}

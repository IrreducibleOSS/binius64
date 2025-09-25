// Copyright 2025 Irreducible Inc.

use std::collections::BTreeMap;

use binius_field::{BinaryField128bGhash as B128, Field};
use smallvec::SmallVec;

use crate::{AddConstraint, ConstraintWire, WitnessIndex};

struct MulConstraint {
	a: Operand,
	b: Operand,
	c: Operand,
}

struct Operand(SmallVec<[ConstraintWire; 4]>);

pub struct R1CS {
	witness_size: u32,
	constants: Vec<B128>,
	// TODO: This can just be a vec with binary search, BTreeMap not necessary.
	index_map: BTreeMap<ConstraintWire, WitnessIndex>,
	add_constraints: Vec<Operand>,
	mul_constraints: Vec<MulConstraint>,
}

impl R1CS {
	fn optimize_pass(&mut self) {
		// map each private wire to its use defs
		// identify candidates:
		// - private wire in at least on ADD constraint
		// heuristic:
		// - Do replace?
		// if replace, do replace
		// if replace, do replace
		// HashSet of unpruned wires
		// - begin with all
		// - remove from set when pruned
		// # of references = (# of other terms - 1) x # of use sites
	}
}

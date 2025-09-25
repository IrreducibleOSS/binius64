// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128bGhash as B128, Field};
use smallvec::{SmallVec, smallvec};

use crate::{AddConstraint, ConstraintWire, MulConstraint, WireKind, WitnessIndex};

struct OperandMulConstraint {
	a: Operand,
	b: Operand,
	c: Operand,
}

struct Operand(SmallVec<[ConstraintWire; 4]>);

impl From<ConstraintWire> for Operand {
	fn from(value: ConstraintWire) -> Self {
		Operand(smallvec![value])
	}
}

#[derive(Debug, Clone)]
enum UseSite {
	Add { index: u32 },
	Mul { index: u32 },
}

#[derive(Debug, Clone)]
enum WireStatus {
	Pinned,
	Pruned,
	Unknown { uses: Vec<UseSite> },
}

impl Default for WireStatus {
	fn default() -> Self {
		WireStatus::Unknown { uses: Vec::new() }
	}
}

pub struct R1CS {
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
		n_constant: usize,
		n_public: usize,
		n_private: usize,
		constants: Vec<B128>, //HashMap<B128, u32>,
		add_constraints: Vec<AddConstraint>,
		mul_constraints: Vec<MulConstraint>,
	) -> Self {
		let mut private_wires = vec![WireStatus::default(); n_private];

		let mut r1cs_add_constraints = Vec::with_capacity(add_constraints.len());
		for (i, AddConstraint(term)) in add_constraints.into_iter().enumerate() {
			for wire in &term {
				if matches!(wire.kind, WireKind::Private) {
					if let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize] {
						uses.push(UseSite::Add { index: i as u32 });
					}
				}
			}
			r1cs_add_constraints.push(Operand(term));
		}

		let mut r1cs_mul_constraints = Vec::with_capacity(mul_constraints.len());
		for (i, MulConstraint { a, b, c }) in mul_constraints.into_iter().enumerate() {
			for wire in [a, b, c] {
				if matches!(wire.kind, WireKind::Private) {
					if let WireStatus::Unknown { ref mut uses } = private_wires[wire.id as usize] {
						uses.push(UseSite::Mul { index: i as u32 });
					}
				}
			}
			r1cs_mul_constraints.push(OperandMulConstraint {
				a: a.into(),
				b: b.into(),
				c: c.into(),
			});
		}

		Self {
			constants,
			add_constraints: r1cs_add_constraints,
			mul_constraints: r1cs_mul_constraints,
			private_wires,
		}
	}

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

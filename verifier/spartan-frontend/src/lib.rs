// Copyright 2025 Irreducible Inc.

use std::{array, collections::BTreeMap, iter::successors};

use binius_field::{BinaryField128bGhash as B128, Field};
use bytemuck::zeroed_vec;
use itertools::chain;
use smallvec::{SmallVec, smallvec};

pub trait CircuitBuilder {
	type Wire: Copy;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire);

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		inputs: [Self::Wire; IN],
		f: F,
	) -> [Self::Wire; OUT];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireKind {
	Constant,
	Public,
	Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConstraintWire {
	kind: WireKind,
	id: u32,
}

#[derive(Debug)]
pub struct WireAllocator {
	n_wires: u32,
	kind: WireKind,
}

impl WireAllocator {
	pub fn new(kind: WireKind) -> Self {
		WireAllocator { n_wires: 0, kind }
	}

	pub fn alloc(&mut self) -> ConstraintWire {
		let wire = ConstraintWire {
			kind: self.kind,
			id: self.n_wires,
		};
		self.n_wires += 1;
		wire
	}
}

struct AddConstraint(SmallVec<[ConstraintWire; 4]>);

struct MulConstraint {
	a: ConstraintWire,
	b: ConstraintWire,
	c: ConstraintWire,
}

pub struct ConstraintSystem {
	witness_size: u32,
	// TODO: This can just be a vec with binary search, BTreeMap not necessary.
	index_map: BTreeMap<ConstraintWire, WitnessIndex>,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
}

impl ConstraintSystem {
	pub fn validate(&self, witness: &[B128]) {
		assert_eq!(witness.len(), self.witness_size as usize);

		let wire_val = |wire| witness[self.index_map[wire].0 as usize];

		for AddConstraint(term) in &self.add_constraints {
			let sum = term.iter().map(wire_val).sum::<B128>();
			assert!(sum.is_zero());
		}

		for MulConstraint { a, b, c } in &self.mul_constraints {
			assert_eq!(wire_val(a) * wire_val(b), wire_val(c));
		}
	}
}

// Witness values are a permuted subset of the wire values.
// Need a way to fingerprint a constraint system.

pub struct ConstraintBuilder {
	public_alloc: WireAllocator,
	private_alloc: WireAllocator,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
}

impl ConstraintBuilder {
	pub fn new() -> Self {
		ConstraintBuilder {
			public_alloc: WireAllocator::new(WireKind::Public),
			private_alloc: WireAllocator::new(WireKind::Private),
			add_constraints: Vec::new(),
			mul_constraints: Vec::new(),
		}
	}

	pub fn alloc_inout(&mut self) -> ConstraintWire {
		self.public_alloc.alloc()
	}

	pub fn build(self) -> ConstraintSystem {
		let Self {
			public_alloc,
			private_alloc,
			add_constraints,
			mul_constraints,
		} = self;
		let witness_size = public_alloc.n_wires + private_alloc.n_wires;
		let private_offset = public_alloc.n_wires;

		let index_map = chain!(
			(0..public_alloc.n_wires).map(|i| {
				let wire = ConstraintWire {
					kind: WireKind::Public,
					id: i,
				};
				(wire, WitnessIndex(i))
			}),
			(0..private_alloc.n_wires).map(|i| {
				let wire = ConstraintWire {
					kind: WireKind::Private,
					id: i,
				};
				(wire, WitnessIndex(private_offset + i))
			})
		)
		.collect();
		ConstraintSystem {
			witness_size,
			index_map,
			add_constraints,
			mul_constraints,
		}
	}
}

impl CircuitBuilder for ConstraintBuilder {
	type Wire = ConstraintWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		self.add_constraints
			.push(AddConstraint(smallvec![lhs, rhs]));
	}

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.private_alloc.alloc();
		self.add_constraints
			.push(AddConstraint(smallvec![lhs, rhs, out]));
		out
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.private_alloc.alloc();
		self.mul_constraints.push(MulConstraint {
			a: lhs,
			b: rhs,
			c: out,
		});
		out
	}

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		_inputs: [Self::Wire; IN],
		_f: F,
	) -> [Self::Wire; OUT] {
		array::from_fn(|_| self.private_alloc.alloc())
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WitnessIndex(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessWire(B128);

impl WitnessWire {
	#[inline]
	pub fn val(self) -> B128 {
		self.0
	}
}

pub struct WitnessGenerator<'a> {
	alloc: WireAllocator,
	value_vec: Vec<B128>,
	index_map: &'a BTreeMap<ConstraintWire, WitnessIndex>,
}

impl<'a> WitnessGenerator<'a> {
	pub fn new(witness_size: usize, index_map: &'a BTreeMap<ConstraintWire, WitnessIndex>) -> Self {
		Self {
			alloc: WireAllocator::new(WireKind::Private),
			value_vec: zeroed_vec(witness_size),
			index_map,
		}
	}

	fn alloc_value(&mut self, value: B128) -> WitnessWire {
		let wire = self.alloc.alloc();
		self.write_value(wire, value)
	}

	fn write_value(&mut self, wire: ConstraintWire, value: B128) -> WitnessWire {
		if let Some(&index) = self.index_map.get(&wire) {
			self.value_vec[index.0 as usize] = value;
		}
		WitnessWire(value)
	}

	pub fn write_inout(&mut self, wire: ConstraintWire, value: B128) -> WitnessWire {
		assert_eq!(wire.kind, WireKind::Public);
		self.write_value(wire, value)
	}

	pub fn build(self) -> Vec<B128> {
		self.value_vec
	}
}

impl<'a> CircuitBuilder for WitnessGenerator<'a> {
	type Wire = WitnessWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		// This should set a flag instead of panicking
		assert_eq!(lhs, rhs);
	}

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		self.alloc_value(lhs.val() + rhs.val())
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		self.alloc_value(lhs.val() * rhs.val())
	}

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		inputs: [Self::Wire; IN],
		f: F,
	) -> [Self::Wire; OUT] {
		f(inputs.map(WitnessWire::val)).map(|value| self.alloc_value(value))
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField, Field, PackedField};

	use super::*;

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
	fn test_fibonacci() {
		let mut constraint_builder = ConstraintBuilder::new();
		let x0 = constraint_builder.alloc_inout();
		let x1 = constraint_builder.alloc_inout();
		let xn = constraint_builder.alloc_inout();
		let out = fibonacci(&mut constraint_builder, x0, x1, 20);
		constraint_builder.assert_eq(out, xn);
		let constraint_system = constraint_builder.build();

		let mut witness_generator = WitnessGenerator::new(
			constraint_system.witness_size as usize,
			&constraint_system.index_map,
		);
		let x0 = witness_generator.write_inout(x0, B128::ONE);
		let x1 = witness_generator.write_inout(x1, B128::MULTIPLICATIVE_GENERATOR);
		let xn = witness_generator.write_inout(xn, B128::MULTIPLICATIVE_GENERATOR.pow(6765));
		let out = fibonacci(&mut witness_generator, x0, x1, 20);
		witness_generator.assert_eq(out, xn);
		let witness = witness_generator.build();

		constraint_system.validate(&witness);
	}
}

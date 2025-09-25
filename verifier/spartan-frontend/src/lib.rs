// Copyright 2025 Irreducible Inc.

use std::{array, collections::BTreeMap, iter::successors};

use binius_field::BinaryField128bGhash as B128;
use bytemuck::zeroed_vec;
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
pub struct ConstraintWire(u32);

#[derive(Debug)]
pub struct WireAllocator {
	n_wires: u32,
}

impl WireAllocator {
	pub fn new() -> Self {
		WireAllocator { n_wires: 0 }
	}

	pub fn alloc(&mut self) -> ConstraintWire {
		let wire = ConstraintWire(self.n_wires);
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
	index_map: BTreeMap<ConstraintWire, WitnessIndex>,
}

pub struct ConstraintBuilder {
	alloc: WireAllocator,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
}

impl ConstraintBuilder {
	pub fn new() -> Self {
		ConstraintBuilder {
			alloc: WireAllocator::new(),
			add_constraints: Vec::new(),
			mul_constraints: Vec::new(),
		}
	}

	pub fn alloc_inout(&mut self) -> ConstraintWire {
		self.alloc.alloc()
	}

	pub fn build(self) -> ConstraintSystem {
		let witness_size = self.alloc.n_wires;
		let index_map = (0..witness_size)
			.map(|i| (ConstraintWire(i), WitnessIndex(i)))
			.collect();
		ConstraintSystem {
			witness_size,
			index_map,
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
		let out = self.alloc.alloc();
		self.add_constraints
			.push(AddConstraint(smallvec![lhs, rhs, out]));
		out
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.alloc.alloc();
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
		array::from_fn(|_| self.alloc.alloc())
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
			alloc: WireAllocator::new(),
			value_vec: zeroed_vec(witness_size),
			index_map,
		}
	}

	fn write_value(&mut self, value: B128) -> WitnessWire {
		let wire = self.alloc.alloc();
		if let Some(&index) = self.index_map.get(&wire) {
			self.value_vec[index.0 as usize] = value;
		}
		WitnessWire(value)
	}

	pub fn write_inout(&mut self, value: B128) -> WitnessWire {
		self.write_value(value)
	}
}

impl<'a> CircuitBuilder for WitnessGenerator<'a> {
	type Wire = WitnessWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		// This should set a flag instead of panicking
		assert_eq!(lhs, rhs);
	}

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		self.write_value(lhs.val() + rhs.val())
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		self.write_value(lhs.val() * rhs.val())
	}

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		inputs: [Self::Wire; IN],
		f: F,
	) -> [Self::Wire; OUT] {
		f(inputs.map(WitnessWire::val)).map(|value| self.write_value(value))
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
		let x0 = witness_generator.write_inout(B128::ONE);
		let x1 = witness_generator.write_inout(B128::MULTIPLICATIVE_GENERATOR);
		let xn = witness_generator.write_inout(B128::MULTIPLICATIVE_GENERATOR.pow(6765));
		let out = fibonacci(&mut witness_generator, x0, x1, 20);
		witness_generator.assert_eq(out, xn);
	}
}

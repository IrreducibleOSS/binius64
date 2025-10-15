// Copyright 2025 Irreducible Inc.

use std::{array, collections::HashMap};

use binius_field::BinaryField128bGhash as B128;
use bytemuck::zeroed_vec;
use smallvec::{SmallVec, smallvec};

use crate::constraint_system::{
	AddConstraint, ConstraintSystem, ConstraintWire, MulConstraint, Operand, WireKind,
	WitnessLayout,
};

pub trait CircuitBuilder {
	type Wire: Copy;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire);

	fn constant(&mut self, val: B128) -> Self::Wire;

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		inputs: [Self::Wire; IN],
		f: F,
	) -> [Self::Wire; OUT];
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

// TODO: Add string labels for constraints to make validation easier.
struct BuilderAddConstraint(SmallVec<[ConstraintWire; 4]>);

struct BuilderMulConstraint {
	a: ConstraintWire,
	b: ConstraintWire,
	c: ConstraintWire,
}

// Witness values are a permuted subset of the wire values.
// Need a way to fingerprint a constraint system.

pub struct ConstraintBuilder {
	constant_alloc: WireAllocator,
	public_alloc: WireAllocator,
	private_alloc: WireAllocator,
	constants: HashMap<B128, u32>,
	add_constraints: Vec<BuilderAddConstraint>,
	mul_constraints: Vec<BuilderMulConstraint>,
}

impl ConstraintBuilder {
	#[allow(clippy::new_without_default)]
	pub fn new() -> Self {
		ConstraintBuilder {
			constant_alloc: WireAllocator::new(WireKind::Constant),
			public_alloc: WireAllocator::new(WireKind::InOut),
			private_alloc: WireAllocator::new(WireKind::Private),
			constants: HashMap::new(),
			add_constraints: Vec::new(),
			mul_constraints: Vec::new(),
		}
	}

	pub fn alloc_inout(&mut self) -> ConstraintWire {
		self.public_alloc.alloc()
	}

	pub fn build(self) -> ConstraintSystem {
		let Self {
			constant_alloc,
			public_alloc,
			private_alloc,
			constants: constants_map,
			add_constraints,
			mul_constraints,
		} = self;

		let mut constants = zeroed_vec(constant_alloc.n_wires as usize);
		for (val, id) in constants_map {
			constants[id as usize] = val;
		}

		let add_constraints = add_constraints
			.into_iter()
			.map(|BuilderAddConstraint(term)| AddConstraint(Operand::new(term)))
			.collect();

		let mul_constraints = mul_constraints
			.into_iter()
			.map(|BuilderMulConstraint { a, b, c }| MulConstraint {
				a: a.into(),
				b: b.into(),
				c: c.into(),
			})
			.collect();

		ConstraintSystem::new(
			constants,
			public_alloc.n_wires,
			private_alloc.n_wires,
			add_constraints,
			mul_constraints,
		)
	}
}

impl CircuitBuilder for ConstraintBuilder {
	type Wire = ConstraintWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		self.add_constraints
			.push(BuilderAddConstraint(smallvec![lhs, rhs]));
	}

	fn constant(&mut self, val: B128) -> Self::Wire {
		let id = self
			.constants
			.entry(val)
			.or_insert_with(|| self.constant_alloc.alloc().id);
		ConstraintWire {
			kind: WireKind::Constant,
			id: *id,
		}
	}

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.private_alloc.alloc();
		self.add_constraints
			.push(BuilderAddConstraint(smallvec![lhs, rhs, out]));
		out
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.private_alloc.alloc();
		self.mul_constraints.push(BuilderMulConstraint {
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
	witness: Vec<B128>,
	layout: &'a WitnessLayout,
}

impl<'a> WitnessGenerator<'a> {
	pub fn new(cs: &'a ConstraintSystem, layout: &'a WitnessLayout) -> Self {
		let witness_size = layout.size();

		assert_eq!(cs.constants.len(), layout.n_constants());

		let mut witness = zeroed_vec(witness_size);
		witness[..cs.constants.len()].copy_from_slice(&cs.constants);

		Self {
			alloc: WireAllocator::new(WireKind::Private),
			witness,
			layout,
		}
	}

	fn alloc_value(&mut self, value: B128) -> WitnessWire {
		let wire = self.alloc.alloc();
		self.write_value(wire, value)
	}

	fn write_value(&mut self, wire: ConstraintWire, value: B128) -> WitnessWire {
		if let Some(index) = self.layout.get(&wire) {
			self.witness[index.0 as usize] = value;
		}
		WitnessWire(value)
	}

	pub fn write_inout(&mut self, wire: ConstraintWire, value: B128) -> WitnessWire {
		assert_eq!(wire.kind, WireKind::InOut);
		self.write_value(wire, value)
	}

	pub fn build(self) -> Vec<B128> {
		self.witness
	}
}

impl<'a> CircuitBuilder for WitnessGenerator<'a> {
	type Wire = WitnessWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		// This should set a flag instead of panicking
		assert_eq!(lhs, rhs);
	}

	fn constant(&mut self, val: B128) -> Self::Wire {
		WitnessWire(val)
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
	use std::iter::successors;

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

		let layout = WitnessLayout::dense_from_cs(&constraint_system);
		let mut witness_generator = WitnessGenerator::new(&constraint_system, &layout);
		let x0 = witness_generator.write_inout(x0, B128::ONE);
		let x1 = witness_generator.write_inout(x1, B128::MULTIPLICATIVE_GENERATOR);
		let xn = witness_generator.write_inout(xn, B128::MULTIPLICATIVE_GENERATOR.pow(6765));
		let out = fibonacci(&mut witness_generator, x0, x1, 20);
		witness_generator.assert_eq(out, xn);
		let witness = witness_generator.build();

		constraint_system.validate(&layout, &witness);
	}
}

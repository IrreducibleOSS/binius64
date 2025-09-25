// Copyright 2025 Irreducible Inc.

use std::{array, iter::successors};

use binius_field::BinaryField128bGhash as B128;
use smallvec::{SmallVec, smallvec};

pub trait CircuitBuilder {
	type Wire: Copy;

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire;

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		inputs: [Self::Wire; IN],
		f: F,
	) -> [Self::Wire; OUT];
}

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
	.nth(n)
	.expect("closure always returns Some");

	xn
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstraintWire(u32);

pub struct WireAllocator {
	n_wires: u32,
}

impl WireAllocator {
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

pub struct ConstraintBuilder {
	alloc: WireAllocator,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
}

impl CircuitBuilder for ConstraintBuilder {
	type Wire = ConstraintWire;

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

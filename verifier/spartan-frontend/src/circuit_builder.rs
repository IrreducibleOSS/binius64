// Copyright 2025 Irreducible Inc.

use std::{array, collections::HashMap};

use binius_field::BinaryField128bGhash as B128;
use bytemuck::zeroed_vec;
use smallvec::smallvec;

use crate::constraint_system::{
	ConstraintSystem, ConstraintWire, MulConstraint, Operand, WireKind, WitnessLayout,
	ZeroConstraint,
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

// Witness values are a permuted subset of the wire values.
// Need a way to fingerprint a constraint system.

/// Intermediate representation of a constraint system that can be manipulated and optimized.
///
/// This IR is used during circuit construction and optimization passes like wire elimination.
/// It tracks wire allocators, constants, and constraints, along with metadata about which
/// private wires are still alive (not eliminated by optimization).
pub struct ConstraintSystemIR {
	pub(crate) constant_alloc: WireAllocator,
	pub(crate) public_alloc: WireAllocator,
	pub(crate) private_alloc: WireAllocator,
	pub(crate) constants: HashMap<B128, u32>,
	pub(crate) zero_constraints: Vec<ZeroConstraint>,
	pub(crate) mul_constraints: Vec<MulConstraint>,
	/// Tracks which private wires are still alive (not eliminated).
	/// Index corresponds to private wire ID. Initially all wires are alive.
	pub(crate) private_wires_alive: Vec<bool>,
}

impl ConstraintSystemIR {
	/// Finalize the IR into a ConstraintSystem by converting remaining ZeroConstraints
	/// to MulConstraints and computing the final witness layout.
	///
	/// The `one_wire` parameter specifies a constant wire with value 1, used to convert
	/// ZeroConstraints of the form `A = 0` into MulConstraints `A * 1 = 0`.
	pub fn finalize(mut self, one_wire: ConstraintWire) -> ConstraintSystem {
		use std::mem;

		assert_eq!(one_wire.kind, WireKind::Constant);

		// Convert constants HashMap to Vec
		let mut constants = zeroed_vec(self.constant_alloc.n_wires as usize);
		for (val, id) in self.constants {
			constants[id as usize] = val;
		}

		// Replace all remaining zero constraints with mul constraints
		let one_operand = Operand::from(one_wire);
		let zero_operand = Operand::default();
		for ZeroConstraint(operand) in mem::take(&mut self.zero_constraints) {
			if !operand.is_empty() {
				self.mul_constraints.push(MulConstraint {
					a: operand,
					b: one_operand.clone(),
					c: zero_operand.clone(),
				});
			}
		}

		// Calculate final n_private from alive wires
		let n_private = self
			.private_wires_alive
			.iter()
			.filter(|&&alive| alive)
			.count() as u32;

		ConstraintSystem::new(constants, self.public_alloc.n_wires, n_private, self.mul_constraints)
	}
}

pub struct ConstraintBuilder {
	ir: ConstraintSystemIR,
}

impl ConstraintBuilder {
	#[allow(clippy::new_without_default)]
	pub fn new() -> Self {
		ConstraintBuilder {
			ir: ConstraintSystemIR {
				constant_alloc: WireAllocator::new(WireKind::Constant),
				public_alloc: WireAllocator::new(WireKind::InOut),
				private_alloc: WireAllocator::new(WireKind::Private),
				constants: HashMap::new(),
				zero_constraints: Vec::new(),
				mul_constraints: Vec::new(),
				private_wires_alive: Vec::new(),
			},
		}
	}

	pub fn alloc_inout(&mut self) -> ConstraintWire {
		self.ir.public_alloc.alloc()
	}

	pub fn build(self) -> ConstraintSystemIR {
		self.ir
	}
}

impl CircuitBuilder for ConstraintBuilder {
	type Wire = ConstraintWire;

	fn assert_eq(&mut self, lhs: Self::Wire, rhs: Self::Wire) {
		self.ir
			.zero_constraints
			.push(ZeroConstraint(Operand::new(smallvec![lhs, rhs])));
	}

	fn constant(&mut self, val: B128) -> Self::Wire {
		let id = self
			.ir
			.constants
			.entry(val)
			.or_insert_with(|| self.ir.constant_alloc.alloc().id);
		ConstraintWire {
			kind: WireKind::Constant,
			id: *id,
		}
	}

	fn add(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.ir.private_alloc.alloc();
		self.ir.private_wires_alive.push(true);
		self.ir
			.zero_constraints
			.push(ZeroConstraint(Operand::new(smallvec![lhs, rhs, out])));
		out
	}

	fn mul(&mut self, lhs: Self::Wire, rhs: Self::Wire) -> Self::Wire {
		let out = self.ir.private_alloc.alloc();
		self.ir.private_wires_alive.push(true);
		self.ir.mul_constraints.push(MulConstraint {
			a: lhs.into(),
			b: rhs.into(),
			c: out.into(),
		});
		out
	}

	fn hint<F: Fn([B128; IN]) -> [B128; OUT], const IN: usize, const OUT: usize>(
		&mut self,
		_inputs: [Self::Wire; IN],
		_f: F,
	) -> [Self::Wire; OUT] {
		array::from_fn(|_| {
			let wire = self.ir.private_alloc.alloc();
			self.ir.private_wires_alive.push(true);
			wire
		})
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
		let one_wire = constraint_builder.constant(B128::ONE);
		let x0 = constraint_builder.alloc_inout();
		let x1 = constraint_builder.alloc_inout();
		let xn = constraint_builder.alloc_inout();
		let out = fibonacci(&mut constraint_builder, x0, x1, 20);
		constraint_builder.assert_eq(out, xn);
		let ir = constraint_builder.build();
		let constraint_system = ir.finalize(one_wire);

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

// Copyright 2025 Irreducible Inc.

mod r1cs;

use std::{array, collections::HashMap, iter::successors};

use binius_field::{BinaryField128bGhash as B128, Field};
use binius_utils::checked_arithmetics::log2_ceil_usize;
use bytemuck::zeroed_vec;
use smallvec::{SmallVec, smallvec};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireKind {
	Constant,
	InOut,
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

// TODO: Add string labels for constraints to make validation easier.
struct AddConstraint(SmallVec<[ConstraintWire; 4]>);

struct MulConstraint {
	a: ConstraintWire,
	b: ConstraintWire,
	c: ConstraintWire,
}

pub struct ConstraintSystem {
	constants: Vec<B128>,
	n_inout: u32,
	n_private: u32,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
}

impl ConstraintSystem {
	pub fn validate(&self, layout: &WitnessLayout, witness: &[B128]) {
		assert_eq!(witness.len(), layout.size());

		let wire_val = |wire| {
			let Some(idx) = layout.get(wire) else {
				panic!("wire {wire:?} not found");
			};
			witness[idx.0 as usize]
		};

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
	constant_alloc: WireAllocator,
	public_alloc: WireAllocator,
	private_alloc: WireAllocator,
	constants: HashMap<B128, u32>,
	add_constraints: Vec<AddConstraint>,
	mul_constraints: Vec<MulConstraint>,
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

		ConstraintSystem {
			constants,
			n_inout: public_alloc.n_wires,
			n_private: private_alloc.n_wires,
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

#[derive(Debug)]
pub struct WitnessLayout {
	n_constants: u32,
	n_inout: u32,
	n_private: u32,
	log_public: u32,
	log_size: u32,
	private_index_map: HashMap<u32, u32>,
}

impl WitnessLayout {
	pub fn dense(n_constants: u32, n_inout: u32, n_private: u32) -> Self {
		let n_public = n_constants + n_inout;
		let log_public = log2_ceil_usize(n_public as usize) as u32;

		let private_offset = 1 << log_public;
		let log_size = log2_ceil_usize((private_offset + n_private) as usize) as u32;

		let private_index_map = (0..n_private).map(|i| (i, private_offset + i)).collect();
		Self {
			n_constants,
			n_inout,
			n_private,
			log_public,
			log_size,
			private_index_map,
		}
	}

	pub fn dense_from_cs(cs: &ConstraintSystem) -> Self {
		Self::dense(cs.constants.len() as u32, cs.n_inout, cs.n_private)
	}

	pub fn sparse(n_constants: u32, n_inout: u32, private_alive: &[bool]) -> Self {
		let n_public = n_constants + n_inout;
		let log_public = log2_ceil_usize(n_public as usize) as u32;

		let private_offset = 1 << log_public;
		let private_index_map = private_alive
			.iter()
			.enumerate()
			.filter_map(|(i, &alive)| alive.then_some((i as u32, private_offset + i as u32)))
			.collect::<HashMap<_, _>>();

		let n_private = private_index_map.len() as u32;
		let log_size = log2_ceil_usize((private_offset + n_private) as usize) as u32;

		Self {
			n_constants,
			n_inout,
			n_private,
			log_public,
			log_size,
			private_index_map,
		}
	}

	pub fn size(&self) -> usize {
		1 << self.log_size as usize
	}

	pub fn n_constants(&self) -> usize {
		self.n_constants as usize
	}

	pub fn n_inout(&self) -> usize {
		self.n_inout as usize
	}

	pub fn n_private(&self) -> usize {
		self.n_private as usize
	}

	/// Returns the first index of the inout
	pub fn inout_offset(&self) -> WitnessIndex {
		WitnessIndex(self.n_constants)
	}

	pub fn private_offset(&self) -> WitnessIndex {
		WitnessIndex(1 << self.log_public)
	}

	pub fn get(&self, wire: &ConstraintWire) -> Option<WitnessIndex> {
		match wire.kind {
			WireKind::Constant => {
				assert!(wire.id < self.n_constants);
				Some(WitnessIndex(wire.id))
			}
			WireKind::InOut => {
				assert!(wire.id < self.n_inout);
				Some(WitnessIndex(self.inout_offset().0 + wire.id))
			}
			WireKind::Private => self
				.private_index_map
				.get(&wire.id)
				.map(|&id| WitnessIndex(id)),
		}
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

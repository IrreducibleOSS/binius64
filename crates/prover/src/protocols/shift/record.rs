// Copyright 2025 Irreducible Inc.

use std::ops::Range;

use binius_field::Field;
use binius_frontend::constraint_system::{
	AndConstraint, ConstraintSystem, MulConstraint, Operand, ShiftedValueIndex,
};
use binius_verifier::config::WORD_SIZE_BITS;

use super::{BITMUL_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT};

/// document this operation
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum Operation {
	BitwiseAnd,
	IntegerMul,
}

// TODO: document
// ok this is the key
// first we have an operation identifier
// then we have an id that
// the id represents the operand number
// and the shift variant and amount
// i guess it represents a "matrix"
// together with the operation it specifies an accumulator
//
#[derive(Debug, Clone)]
pub struct Key {
	// OPERAND * 3 * WORD_SIZE_BITS
	// we could incorporate the operation into the id
	// but not as clean and no diff in performance
	pub operation: Operation,
	pub id: u16,
	pub range: Range<u32>,
}

impl Key {
	/// Given a tensor of challenge evaluations, sums the values at positions
	/// corresponding to all constraints that use this shift variant and amount.
	/// Requires the constraint_indices slice from the KeyCollection.
	#[inline]
	pub fn accumulate<F: Field>(&self, constraint_indices: &[u32], tensor: &[F]) -> F {
		let Range { start, end } = self.range;
		constraint_indices[start as usize..end as usize]
			.iter()
			.map(|&i| tensor[i as usize])
			.sum()
	}
}

// TODO: document
#[derive(Debug, Clone)]
pub struct ProverConstraintSystem {
	pub keys: Vec<Key>,
	// mention how this could be a single number but
	// parallelization makes that tricky
	pub key_ranges: Vec<Range<u32>>,
	pub constraint_indices: Vec<u32>,
}

struct BuilderKey {
	pub id: u16,
	pub operation: Operation,
	pub constraint_indices: Vec<u32>,
}

fn update_with_operand(
	operation: Operation,
	operand_index: usize,
	operand_values: impl Iterator<Item = impl AsRef<Operand>>,
	key_lists: &mut [Vec<BuilderKey>],
) {
	for (constraint_idx, operand) in operand_values.enumerate() {
		for ShiftedValueIndex {
			value_index,
			shift_variant,
			amount,
		} in operand.as_ref()
		{
			let builder_keys = &mut key_lists[value_index.0 as usize];
			let id = (operand_index as u16 * SHIFT_VARIANT_COUNT as u16 + *shift_variant as u16)
				* WORD_SIZE_BITS as u16
				+ *amount as u16;

			if let Some(builder_key) = builder_keys
				.iter_mut()
				.find(|key| key.id == id && key.operation == operation)
			{
				builder_key.constraint_indices.push(constraint_idx as u32);
			} else {
				builder_keys.push(BuilderKey {
					id,
					operation,
					constraint_indices: vec![constraint_idx as u32],
				});
			}
		}
	}
}

pub fn build_prover_constraint_system(cs: &ConstraintSystem) -> ProverConstraintSystem {
	let mut builder_key_lists: Vec<Vec<BuilderKey>> = (0..cs.value_vec_layout.total_len)
		.map(|_| Vec::new())
		.collect();

	let bitmul_operand_getters: [fn(&AndConstraint) -> &Operand; BITMUL_ARITY] =
		[|c| &c.a, |c| &c.b, |c| &c.c];
	let intmul_operand_getters: [fn(&MulConstraint) -> &Operand; INTMUL_ARITY] =
		[|c| &c.a, |c| &c.b, |c| &c.hi, |c| &c.lo];

	bitmul_operand_getters
		.iter()
		.enumerate()
		.for_each(|(operand_idx, get_operand)| {
			update_with_operand(
				Operation::BitwiseAnd,
				operand_idx,
				cs.and_constraints.iter().map(get_operand),
				&mut builder_key_lists,
			);
		});

	intmul_operand_getters
		.iter()
		.enumerate()
		.for_each(|(operand_idx, get_operand)| {
			update_with_operand(
				Operation::IntegerMul,
				operand_idx,
				cs.mul_constraints.iter().map(get_operand),
				&mut builder_key_lists,
			);
		});

	let mut keys = Vec::new();
	let key_ranges = builder_key_lists
		.iter()
		.scan(0u32, |offset, builder_keys| {
			let start = *offset;
			*offset += builder_keys.len() as u32;
			Some(start..*offset)
		})
		.collect();
	let mut constraint_indices = Vec::new();

	for builder_key in builder_key_lists.into_iter().flatten() {
		let start = constraint_indices.len() as u32;
		constraint_indices.extend(&builder_key.constraint_indices);
		let end = constraint_indices.len() as u32;
		keys.push(Key {
			id: builder_key.id,
			operation: builder_key.operation,
			range: start..end,
		});
	}

	ProverConstraintSystem {
		keys,
		key_ranges,
		constraint_indices,
	}
}

// Copyright 2025 Irreducible Inc.

use binius_field::Field;
use binius_frontend::constraint_system::{
	ConstraintSystem, Operand, ShiftVariant, ShiftedValueIndex,
};

// TODO: document
#[derive(Debug, Clone)]
pub struct ShiftedValueKey<F> {
	// The shift variant together with the amount form an identifier.
	// With 3 variants, and amounts up to 64, this can fit in 8 bits.
	// Using a u8 identifier could save space and increase speed in
	// the hot accumulation loops due to less indirection.
	/// The type of shift operation (logical left, logical right, arithmetic right)
	pub op: ShiftVariant,
	/// Number of bit positions to shift (0-63)
	pub s: usize,
	/// Indices of all constraints that use this exact shift operation
	pub constraint_indices: Vec<u32>,
	/// Just to try memoization
	pub memo: F,
}

impl<F: Field> ShiftedValueKey<F> {
	/// Given a tensor of challenge evaluations, sums the values at positions
	/// corresponding to all constraints that use this shift variant and amount.
	#[inline]
	pub fn accumulate(&self, tensor: &[F]) -> F {
		self.constraint_indices
			.iter()
			.map(|&i| tensor[i as usize])
			.sum()
	}
}

/// TODO: document
pub type Record<F> = Vec<Vec<ShiftedValueKey<F>>>;

/// TODO: document
pub fn build_record<F: Field>(
	word_count: usize,
	operands: impl Iterator<Item = impl AsRef<Operand>>,
) -> Record<F> {
	let mut record: Vec<Vec<ShiftedValueKey<F>>> = (0..word_count).map(|_| Vec::new()).collect();

	for (i, operand) in operands.enumerate() {
		for ShiftedValueIndex {
			value_index,
			shift_variant,
			amount,
		} in operand.as_ref()
		{
			let keys = &mut record[value_index.0 as usize];

			if let Some(key) = keys
				.iter_mut()
				.find(|key| key.op as u8 == *shift_variant as u8 && key.s == *amount)
			{
				key.constraint_indices.push(i as u32);
			} else {
				keys.push(ShiftedValueKey {
					op: *shift_variant,
					s: *amount,
					constraint_indices: vec![i as u32],
					memo: F::ZERO,
				});
			}
		}
	}

	record
}

/// Build records for bitmul constraints
pub fn build_record_for_bitmul_constraints<F: Field>(cs: &ConstraintSystem) -> [Record<F>; 3] {
	let word_count = cs.value_vec_layout.total_len;
	let constraints = &cs.and_constraints;
	[
		build_record(word_count, constraints.iter().map(|c| &c.a)),
		build_record(word_count, constraints.iter().map(|c| &c.b)),
		build_record(word_count, constraints.iter().map(|c| &c.c)),
	]
}

/// Build records for intmul constraints
pub fn build_record_for_intmul_constraints<F: Field>(cs: &ConstraintSystem) -> [Record<F>; 4] {
	let word_count = cs.value_vec_layout.total_len;
	let constraints = &cs.mul_constraints;
	[
		build_record(word_count, constraints.iter().map(|c| &c.a)),
		build_record(word_count, constraints.iter().map(|c| &c.b)),
		build_record(word_count, constraints.iter().map(|c| &c.hi)),
		build_record(word_count, constraints.iter().map(|c| &c.lo)),
	]
}

#[cfg(test)]
mod tests {
	use std::ops::IndexMut;

	use binius_field::BinaryField128bGhash as Ghash;
	use binius_frontend::{
		compiler::CircuitBuilder,
		constraint_system::{AndConstraint, MulConstraint, ValueIndex},
		word::Word,
	};

	use super::*;
	use crate::protocols::shift::tests::*;

	#[test]
	fn test_invert_cs_simple_circuit() {
		let builder = CircuitBuilder::new();
		let a = builder.add_inout();
		let b = builder.add_inout();

		let _zero = builder.add_constant(Word::ZERO);

		let result = builder.icmp_ult(a, b);
		let expected = builder.add_inout();
		builder.assert_eq("test", result, expected);

		let circuit = builder.build();
		let cs = circuit.constraint_system();

		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_jwt_claims() {
		let (cs, _) = create_jwt_claims_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_sha256() {
		let (cs, _) = create_sha256_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_base64() {
		let (cs, _) = create_base64_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_concat() {
		let (cs, _) = create_concat_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_slice() {
		let (cs, _) = create_slice_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	#[test]
	fn test_invert_cs_rs256() {
		let (cs, _) = create_rs256_cs_with_witness();
		invert_constraints::<Ghash>(cs);
	}

	// Tools for testing

	fn find_max_constraint_index<F>(record: &Record<F>) -> u32 {
		record
			.iter()
			.flat_map(|keys| keys.iter())
			.flat_map(|key| key.constraint_indices.iter())
			.max()
			.copied()
			.unwrap_or(0)
	}

	/// Generic function to fill operands from record data
	fn fill_operand_list_from_record<F, Operands>(
		record: &[Vec<ShiftedValueKey<F>>],
		operand_list: &mut Operands,
	) where
		Operands: IndexMut<usize, Output = Operand>,
	{
		for (word_index, keys) in record.iter().enumerate() {
			for key in keys {
				let shifted_value_index = ShiftedValueIndex {
					value_index: ValueIndex(word_index as u32),
					shift_variant: key.op,
					amount: key.s,
				};

				for &constraint_index in &key.constraint_indices {
					operand_list[constraint_index as usize].push(shifted_value_index);
				}
			}
		}
	}

	fn revert_bitmul_constraints<F>(bitmul_records: &[Record<F>; 3]) -> Vec<AndConstraint> {
		let [a_record, b_record, c_record] = bitmul_records;
		let max_index = [
			find_max_constraint_index(a_record),
			find_max_constraint_index(b_record),
			find_max_constraint_index(c_record),
		]
		.into_iter()
		.max()
		.unwrap_or(0);

		// if max_index == 0 {
		// 	return Vec::new();
		// }

		let mut constraints: Vec<AndConstraint> = (0..=max_index)
			.map(|_| AndConstraint {
				a: Vec::new(),
				b: Vec::new(),
				c: Vec::new(),
			})
			.collect();

		// Create separate operand collections for each constraint operand
		let mut a_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();
		let mut b_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();
		let mut c_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();

		// Fill each operand collection separately
		fill_operand_list_from_record(&a_record, &mut a_operands);
		fill_operand_list_from_record(&b_record, &mut b_operands);
		fill_operand_list_from_record(&c_record, &mut c_operands);

		// Copy operands back to constraints
		for (i, constraint) in constraints.iter_mut().enumerate() {
			constraint.a = a_operands[i].clone();
			constraint.b = b_operands[i].clone();
			constraint.c = c_operands[i].clone();
		}

		constraints
	}

	fn revert_intmul_constraints<F>(intmul_records: &[Record<F>; 4]) -> Vec<MulConstraint> {
		let [a_record, b_record, hi_record, lo_record] = intmul_records;
		let max_index = [
			find_max_constraint_index(a_record),
			find_max_constraint_index(b_record),
			find_max_constraint_index(hi_record),
			find_max_constraint_index(lo_record),
		]
		.into_iter()
		.max()
		.unwrap_or(0);

		// if max_index == 0 {
		// 	return Vec::new();
		// }

		let mut constraints: Vec<MulConstraint> = (0..=max_index)
			.map(|_| MulConstraint {
				a: Vec::new(),
				b: Vec::new(),
				hi: Vec::new(),
				lo: Vec::new(),
			})
			.collect();

		// Create separate operand collections for each constraint operand
		let mut a_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();
		let mut b_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();
		let mut hi_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();
		let mut lo_operands: Vec<Operand> = (0..=max_index).map(|_| Vec::new()).collect();

		// Fill each operand collection separately
		fill_operand_list_from_record(&a_record, &mut a_operands);
		fill_operand_list_from_record(&b_record, &mut b_operands);
		fill_operand_list_from_record(&hi_record, &mut hi_operands);
		fill_operand_list_from_record(&lo_record, &mut lo_operands);

		// Copy operands back to constraints
		for (i, constraint) in constraints.iter_mut().enumerate() {
			constraint.a = a_operands[i].clone();
			constraint.b = b_operands[i].clone();
			constraint.hi = hi_operands[i].clone();
			constraint.lo = lo_operands[i].clone();
		}

		constraints
	}

	/// Sort operand for canonical ordering by value_index, shift_variant, and amount
	fn sort_operand(operand: &mut Vec<ShiftedValueIndex>) {
		operand.sort_by_key(|idx| (idx.value_index.0, idx.shift_variant as u8, idx.amount));
	}

	fn sort_bitmul_constraint_operands(bitmul: &mut AndConstraint) {
		sort_operand(&mut bitmul.a);
		sort_operand(&mut bitmul.b);
		sort_operand(&mut bitmul.c);
	}

	fn sort_intmul_constraint_operands(intmul: &mut MulConstraint) {
		sort_operand(&mut intmul.a);
		sort_operand(&mut intmul.b);
		sort_operand(&mut intmul.hi);
		sort_operand(&mut intmul.lo);
	}

	// The reversion function
	fn invert_constraints<F: Field>(cs: ConstraintSystem) {
		let mut original_bitmul = cs.and_constraints.clone();
		let mut original_intmul = cs.mul_constraints.clone();

		// Sort original constraints for canonical ordering
		original_bitmul
			.iter_mut()
			.for_each(sort_bitmul_constraint_operands);
		original_intmul
			.iter_mut()
			.for_each(sort_intmul_constraint_operands);

		let bitmul_records: [Record<F>; 3] = build_record_for_bitmul_constraints(&cs);
		let intmul_records: [Record<F>; 4] = build_record_for_intmul_constraints(&cs);

		let mut reverted_bitmul = revert_bitmul_constraints(&bitmul_records);
		let mut reverted_intmul = revert_intmul_constraints(&intmul_records);

		// Sort reverted constraints for canonical ordering
		reverted_bitmul
			.iter_mut()
			.for_each(sort_bitmul_constraint_operands);
		reverted_intmul
			.iter_mut()
			.for_each(sort_intmul_constraint_operands);

		// Assert that original and reverted constraints are identical
		assert_eq!(original_bitmul, reverted_bitmul);
		assert_eq!(original_intmul, reverted_intmul);
	}
}

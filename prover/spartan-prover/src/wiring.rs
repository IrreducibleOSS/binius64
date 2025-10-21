// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use binius_spartan_frontend::constraint_system::{MulConstraint, WitnessIndex};

/// Transpose of the wiring sparse matrix.
pub struct WiringTranspose {
	flat_keys: Vec<Key>,
	keys_start_by_witness_index: Vec<u32>,
}

#[derive(Debug, Clone)]
struct Key {
	pub operand_idx: u8,
	pub constraint_idx: u32,
}

impl WiringTranspose {
	pub fn transpose(witness_size: usize, mul_constraints: &[MulConstraint<WitnessIndex>]) -> Self {
		let mut operands_keys_by_wit_idx = vec![Vec::new(); witness_size];

		let mut n_total_keys = 0;
		for (i, MulConstraint { a, b, c }) in mul_constraints.iter().enumerate() {
			for (operand_idx, operand) in [a, b, c].into_iter().enumerate() {
				for &witness_idx in operand.wires() {
					operands_keys_by_wit_idx[witness_idx.0 as usize].push(Key {
						operand_idx: operand_idx as u8,
						constraint_idx: i as u32,
					});
					n_total_keys += 1;
				}
			}
		}

		// Flatten the sparse matrix representation.
		let mut operand_keys = Vec::with_capacity(n_total_keys);
		let mut operand_key_start_by_word = Vec::with_capacity(witness_size);
		for keys in operands_keys_by_wit_idx {
			let start = operand_keys.len() as u32;
			operand_keys.extend(keys);
			operand_key_start_by_word.push(start);
		}

		Self {
			flat_keys: operand_keys,
			keys_start_by_witness_index: operand_key_start_by_word,
		}
	}
}

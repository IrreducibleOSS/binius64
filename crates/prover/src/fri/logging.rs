// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, BinaryField1b, ExtensionField};
use serde::Serialize;

use crate::formatting::impl_debug_with_json;

#[derive(Serialize)]
pub(super) struct SortAndMergeDimensionData {
	log_elems: usize,
	element_size: usize,
}

impl SortAndMergeDimensionData {
	pub(super) fn new<F: BinaryField>(log_elems: usize) -> Self {
		let element_size = <F as ExtensionField<BinaryField1b>>::DEGREE;
		Self {
			log_elems,
			element_size,
		}
	}
}

impl_debug_with_json!(SortAndMergeDimensionData);

#[derive(Serialize)]
pub(super) struct RSEncodeDimensionData {
	log_elems: usize,
	element_size: usize,
	log_batch_size: usize,
}

impl RSEncodeDimensionData {
	pub(super) fn new<F: BinaryField>(log_elems: usize, log_batch_size: usize) -> Self {
		let element_size = <F as ExtensionField<BinaryField1b>>::DEGREE;
		Self {
			log_elems,
			element_size,
			log_batch_size,
		}
	}
}

impl_debug_with_json!(RSEncodeDimensionData);

#[derive(Serialize)]
pub(super) struct MerkleTreeDimensionData {
	log_elems: usize,
	element_size: usize,
	batch_size: usize,
}

impl MerkleTreeDimensionData {
	pub(super) fn new<F: BinaryField>(log_elems: usize, batch_size: usize) -> Self {
		let element_size = <F as ExtensionField<BinaryField1b>>::DEGREE;
		Self {
			log_elems,
			element_size,
			batch_size,
		}
	}
}

impl_debug_with_json!(MerkleTreeDimensionData);

#[derive(Serialize)]
pub(super) struct FRIFoldData {
	log_len: usize,
	log_batch_size: usize,
	num_challenges: usize,
	codeword_tower_height: usize,
	ntt_tower_height: usize,
}

impl FRIFoldData {
	pub(super) fn new<F: BinaryField, FA: BinaryField>(
		log_len: usize,
		log_batch_size: usize,
		num_challenges: usize,
	) -> Self {
		Self {
			log_len,
			log_batch_size,
			num_challenges,
			codeword_tower_height: <F as ExtensionField<BinaryField1b>>::LOG_DEGREE,
			ntt_tower_height: <FA as ExtensionField<BinaryField1b>>::LOG_DEGREE,
		}
	}

	pub(super) fn log_len(&self) -> usize {
		self.log_len
	}
}

impl_debug_with_json!(FRIFoldData);

// Copyright 2025 Irreducible Inc.
//! Witness population utilities for hash-based signature verification.
//!
//! This module provides helper functions for populating witness data
//! in hash-based signature circuits, including XMSS and Winternitz OTS.

use rand::{RngCore, rngs::StdRng};

use super::{
	hashing::{
		build_chain_hash, build_message_hash, build_public_key_hash, build_tree_hash,
		hash_chain_keccak, hash_message, hash_public_key_keccak, hash_tree_node_keccak,
	},
	winternitz_ots::{WinternitzSpec, grind_nonce},
	xmss::XmssHashers,
};
use crate::compiler::circuit::WitnessFiller;

/// Builds a complete Merkle tree from leaf nodes.
///
/// This function assumes the number of leaves is a power of 2.
///
/// # Returns
/// A tuple containing:
/// - Vector of tree levels (index 0 = leaves, last index = root)
/// - The root hash
///
/// # Panics
/// Panics if leaves.len() is not a power of 2
pub fn build_merkle_tree(param: &[u8], leaves: &[[u8; 32]]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
	assert!(leaves.len().is_power_of_two(), "Number of leaves must be a power of 2");

	let tree_depth = leaves.len().trailing_zeros() as usize;
	let mut tree_levels = vec![leaves.to_vec()];

	for level in 0..tree_depth {
		let current_level = &tree_levels[level];
		let mut next_level = Vec::new();

		for i in (0..current_level.len()).step_by(2) {
			let parent = hash_tree_node_keccak(
				param,
				&current_level[i],
				&current_level[i + 1],
				level as u32,
				(i / 2) as u32,
			);
			next_level.push(parent);
		}

		tree_levels.push(next_level);
	}

	let root = tree_levels[tree_depth][0];
	(tree_levels, root)
}

/// Extracts the authentication path for a given leaf index in a Merkle tree.
///
/// This function assumes the tree has power-of-2 leaves.
///
/// # Arguments
/// * `tree_levels` - All levels of the tree (from build_merkle_tree)
/// * `leaf_index` - Index of the leaf to build path for
///
/// # Returns
/// Vector of sibling hashes from leaf to root
pub fn extract_auth_path(tree_levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
	let mut auth_path = Vec::new();
	let mut idx = leaf_index;
	let tree_height = tree_levels.len() - 1;

	for level in 0..tree_height {
		let sibling_idx = idx ^ 1;
		auth_path.push(tree_levels[level][sibling_idx]);
		idx /= 2;
	}

	auth_path
}

/// Helper structure containing signature data for a validator.
///
/// This is useful for generating test data or populating witness values
/// in multi-signature scenarios.
pub struct ValidatorSignatureData {
	/// Root hash of the validator's Merkle tree
	pub root: [u8; 32],
	/// Nonce (23 bytes)
	pub nonce: [u8; 23],
	/// Signature hashes for each Winternitz chain
	pub signature_hashes: Vec<[u8; 32]>,
	/// Public key hashes for each Winternitz chain
	pub public_key_hashes: Vec<[u8; 32]>,
	/// Authentication path in the Merkle tree
	pub auth_path: Vec<[u8; 32]>,
	/// Codeword coordinates
	pub coords: Vec<u8>,
}

impl ValidatorSignatureData {
	/// Generate a valid signature for a validator at a given epoch.
	///
	/// This function generates all the cryptographic data needed for a validator's
	/// signature including the Winternitz OTS signature, public key, and Merkle tree
	/// authentication path.
	///
	/// # Panics
	/// Panics if:
	/// - The epoch is greater than the number of leaves in the tree.
	/// - A `grind_nonce` fails to find a valid nonce
	/// - A coordinate returned by `grind_nonce` is invalid.
	pub fn generate(
		rng: &mut StdRng,
		param_bytes: &[u8],
		message_bytes: &[u8; 32],
		epoch: u32,
		spec: &WinternitzSpec,
		tree_height: usize,
	) -> Self {
		assert!(
			tree_height <= 31,
			"Tree height {} exceeds maximum supported height of 31",
			tree_height,
		);

		// Validate epoch is within valid range for the tree
		let num_leaves = 1usize << tree_height;
		assert!(
			(epoch as usize) < num_leaves,
			"Epoch {} exceeds maximum leaf index {} for tree height {}",
			epoch,
			num_leaves - 1,
			tree_height
		);

		let grind_result =
			grind_nonce(spec, rng, param_bytes, message_bytes).expect("Failed to find valid nonce");

		let mut nonce = [0u8; 23];
		nonce.copy_from_slice(&grind_result.nonce);
		let coords = grind_result.coords;

		// Generate Winternitz signature and public key
		let mut signature_hashes = Vec::new();
		let mut public_key_hashes = Vec::new();

		for (chain_idx, &coord) in coords.iter().enumerate() {
			assert!(
				(coord as usize) < spec.chain_len(),
				"Coordinate {} exceeds chain length {}",
				coord,
				spec.chain_len()
			);

			let mut sig_hash = [0u8; 32];
			rng.fill_bytes(&mut sig_hash);
			signature_hashes.push(sig_hash);

			let pk_hash = hash_chain_keccak(
				param_bytes,
				chain_idx,
				&sig_hash,
				coord as usize,
				spec.chain_len() - 1 - coord as usize,
			);
			public_key_hashes.push(pk_hash);
		}

		// Build a Merkle tree with 2^tree_height leaves
		let mut leaves = vec![[0u8; 32]; num_leaves];
		leaves[epoch as usize] = hash_public_key_keccak(param_bytes, &public_key_hashes);
		for (i, leaf) in leaves.iter_mut().enumerate() {
			if i != epoch as usize {
				rng.fill_bytes(leaf);
			}
		}

		let (tree_levels, root) = build_merkle_tree(param_bytes, &leaves);
		let auth_path = extract_auth_path(&tree_levels, epoch as usize);

		ValidatorSignatureData {
			root,
			nonce,
			signature_hashes,
			public_key_hashes,
			auth_path,
			coords,
		}
	}
}

/// Data structure containing all the information needed to populate XMSS hashers.
pub struct XmssHasherData {
	/// Parameter bytes (variable length based on spec)
	pub param_bytes: Vec<u8>,
	/// Message bytes (32 bytes)
	pub message_bytes: [u8; 32],
	/// Nonce bytes (variable length, typically 23)
	pub nonce_bytes: Vec<u8>,
	/// Epoch/leaf index
	pub epoch: u64,
	/// Codeword coordinates
	pub coords: Vec<u8>,
	/// Signature hashes for each chain
	pub sig_hashes: Vec<[u8; 32]>,
	/// Public key hashes for each chain
	pub pk_hashes: Vec<[u8; 32]>,
	/// Authentication path for Merkle tree
	pub auth_path: Vec<[u8; 32]>,
}

/// Populates all hashers in an XmssHashers struct with witness data.
///
/// This function fills in the message hasher, chain hashers, public key hasher,
/// and Merkle path hashers with the appropriate witness data for verification.
///
/// # Arguments
///
/// * `w` - The witness filler to populate
/// * `hashers` - The XMSS hashers to populate
/// * `spec` - The Winternitz specification
/// * `data` - The data to use for population
///
/// # Panics
/// Panics if:
/// - `data.coord.len()` is not equal to `spec.dimension()`
/// - `data.sig_hashes.len()` is not equal to `spec.dimension()`
/// - `data.pk_hashes.len()` is not equal to `spec.dimension()`
pub fn populate_xmss_hashers(
	w: &mut WitnessFiller,
	hashers: &XmssHashers,
	spec: &WinternitzSpec,
	data: &XmssHasherData,
) {
	assert_eq!(
		data.coords.len(),
		spec.dimension(),
		"Coordinates length {} doesn't match spec dimension {}",
		data.coords.len(),
		spec.dimension()
	);
	assert_eq!(
		data.sig_hashes.len(),
		spec.dimension(),
		"Signature hashes length {} doesn't match spec dimension {}",
		data.sig_hashes.len(),
		spec.dimension()
	);
	assert_eq!(
		data.pk_hashes.len(),
		spec.dimension(),
		"Public key hashes length {} doesn't match spec dimension {}",
		data.pk_hashes.len(),
		spec.dimension()
	);

	// Populate message hasher
	let message_hash = hash_message(&data.param_bytes, &data.nonce_bytes, &data.message_bytes);
	let tweaked_message =
		build_message_hash(&data.param_bytes, &data.nonce_bytes, &data.message_bytes);

	hashers
		.winternitz_ots
		.message_hasher
		.populate_message(w, &tweaked_message);
	hashers
		.winternitz_ots
		.message_hasher
		.populate_digest(w, message_hash);

	// Populate chain hashers
	let mut hasher_idx = 0;
	for (chain_idx, &coord) in data.coords.iter().enumerate() {
		let mut current_hash = data.sig_hashes[chain_idx];

		for step in 0..spec.chain_len() {
			let position = step + coord as usize;
			let position_plus_one = position + 1;

			let next_hash =
				hash_chain_keccak(&data.param_bytes, chain_idx, &current_hash, position, 1);

			let hasher = &hashers.winternitz_ots.chain_hashers[hasher_idx];
			let chain_message = build_chain_hash(
				&data.param_bytes,
				&current_hash,
				chain_idx as u64,
				position_plus_one as u64,
			);
			hasher.populate_message(w, &chain_message);
			hasher.populate_digest(w, next_hash);

			if position_plus_one < spec.chain_len() {
				current_hash = next_hash;
			}

			hasher_idx += 1;
		}
	}

	// Populate public key hasher
	let pk_message = build_public_key_hash(&data.param_bytes, &data.pk_hashes);
	let pk_hash = hash_public_key_keccak(&data.param_bytes, &data.pk_hashes);
	hashers.public_key_hasher.populate_message(w, &pk_message);
	hashers.public_key_hasher.populate_digest(w, pk_hash);

	// Populate merkle path hashers
	let mut current_hash = pk_hash;
	let mut current_index = data.epoch as usize;

	for (level, auth_sibling) in data.auth_path.iter().enumerate() {
		let (left, right) = if current_index % 2 == 0 {
			(&current_hash, auth_sibling)
		} else {
			(auth_sibling, &current_hash)
		};

		let parent = hash_tree_node_keccak(
			&data.param_bytes,
			left,
			right,
			level as u32,
			(current_index / 2) as u32,
		);

		let tree_message = build_tree_hash(
			&data.param_bytes,
			left,
			right,
			level as u32,
			(current_index / 2) as u32,
		);

		hashers.merkle_path_hashers[level].populate_message(w, &tree_message);
		hashers.merkle_path_hashers[level].populate_digest(w, parent);

		current_hash = parent;
		current_index /= 2;
	}
}

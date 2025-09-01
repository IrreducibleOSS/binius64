//! Test utilities for hash-based signature verification tests.
#[cfg(test)]
use super::{
	hashing::{
		build_chain_hash, build_message_hash, build_public_key_hash, build_tree_hash,
		hash_chain_keccak, hash_message, hash_public_key_keccak, hash_tree_node_keccak,
	},
	winternitz_ots::WinternitzSpec,
	xmss::XmssHashers,
};

/// Builds a complete Merkle tree from leaf nodes.
///
/// This function assumes the number of leaves is a power of 2, which is the case
/// for all hash-based signature tests.
///
/// # Returns
/// A tuple containing:
/// - Vector of tree levels (index 0 = leaves, last index = root)
/// - The root hash
#[cfg(test)]
pub fn build_merkle_tree(param: &[u8], leaves: &[[u8; 32]]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
	debug_assert!(leaves.len().is_power_of_two(), "Number of leaves must be a power of 2");

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
/// This function assumes the tree has power-of-2 leaves, which is the case
/// for all our hash-based signature tests.
///
/// # Arguments
/// * `tree_levels` - All levels of the tree (from build_merkle_tree)
/// * `leaf_index` - Index of the leaf to build path for
///
/// # Returns
/// Vector of sibling hashes from leaf to root
#[cfg(test)]
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

/// Data structure containing all the information needed to populate XMSS hashers.
#[cfg(test)]
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
#[cfg(test)]
pub fn populate_xmss_hashers(
	w: &mut crate::compiler::circuit::WitnessFiller,
	hashers: &XmssHashers,
	spec: &WinternitzSpec,
	data: &XmssHasherData,
) {
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

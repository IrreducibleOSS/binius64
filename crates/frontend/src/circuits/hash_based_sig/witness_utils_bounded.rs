//! Witness population utilities for bounded-hash XMSS (WOTS) verification.

use binius_core::Word;
use sha3::{Digest, Keccak256};

use super::{
	hashing::{
		build_chain_hash, build_message_hash, build_public_key_hash, build_tree_hash,
		hash_public_key_keccak,
	},
	winternitz_ots::WinternitzSpec,
	xmss_bounded::XmssBoundedHashers,
};
use crate::{compiler::circuit::WitnessFiller, util::pack_bytes_into_wires_le};

/// Data structure for bounded XMSS hasher population.
///
/// `pk_hashes` are H^{chain_len-1-x_i}(sig_i) per chain.
pub struct XmssBoundedHasherData {
	pub param_bytes: Vec<u8>,
	pub message_bytes: [u8; 32],
	pub nonce_bytes: Vec<u8>,
	pub epoch: u64,
	pub coords: Vec<u8>,
	pub sig_hashes: Vec<[u8; 32]>,
	pub pk_hashes: Vec<[u8; 32]>,
	pub auth_path: Vec<[u8; 32]>,
}

/// Populate all hashers for a bounded XMSS signature.
pub fn populate_xmss_bounded_hashers(
	w: &mut WitnessFiller,
	hashers: &XmssBoundedHashers,
	spec: &WinternitzSpec,
	data: &XmssBoundedHasherData,
) {
	assert_eq!(data.coords.len(), spec.dimension());
	assert_eq!(data.sig_hashes.len(), spec.dimension());
	assert_eq!(data.pk_hashes.len(), spec.dimension());

	// 1) Message hasher
	let tweaked_message =
		build_message_hash(&data.param_bytes, &data.nonce_bytes, &data.message_bytes);
	let message_digest: [u8; 32] = Keccak256::digest(&tweaked_message).into();
	hashers
		.winternitz_ots
		.message_hasher
		.populate_message(w, &tweaked_message);
	hashers
		.winternitz_ots
		.message_hasher
		.populate_digest(w, message_digest);

	// 2) Pooled step hashers: fill in chain messages, digests, and metadata (remaining steps)
	let mut idx = 0usize;
	for chain_idx in 0..spec.dimension() {
		let mut cur = data.sig_hashes[chain_idx];
		let xi = data.coords[chain_idx] as usize;
		let remaining = spec.chain_len() - 1 - xi;
		for step in 0..remaining {
			let msg =
				build_chain_hash(&data.param_bytes, &cur, chain_idx as u64, (xi + step + 1) as u64);
			let digest: [u8; 32] = Keccak256::digest(&msg).into();

			let keccak = &hashers.winternitz_ots.step_hashers[idx];
			keccak.populate_message(w, &msg);
			keccak.populate_digest(w, digest);

			pack_bytes_into_wires_le(w, &hashers.winternitz_ots.step_hash_inputs[idx], &cur);
			w[hashers.winternitz_ots.step_chain_indices[idx]] = Word::from_u64(chain_idx as u64);
			w[hashers.winternitz_ots.step_counts[idx]] = Word::from_u64((step + 1) as u64);
			w[hashers.winternitz_ots.step_positions[idx]] = Word::from_u64((xi + step + 1) as u64);

			cur = digest;
			idx += 1;
		}
	}

	// 3) Public key hasher
	let pk_msg = build_public_key_hash(&data.param_bytes, &data.pk_hashes);
	let pk_digest: [u8; 32] = Keccak256::digest(&pk_msg).into();
	hashers.public_key_hasher.populate_message(w, &pk_msg);
	hashers.public_key_hasher.populate_digest(w, pk_digest);

	// 4) Merkle path hashers (from leaf to root)
	let mut current = hash_public_key_keccak(&data.param_bytes, &data.pk_hashes);
	let mut index = data.epoch as u32;
	for (level, hasher) in hashers.merkle_path_hashers.iter().enumerate() {
		let sibling = data.auth_path[level];
		let is_left = (index & 1) == 0;
		let (left, right) = if is_left {
			(current, sibling)
		} else {
			(sibling, current)
		};
		let parent = Keccak256::digest(build_tree_hash(
			&data.param_bytes,
			&left,
			&right,
			level as u32,
			index >> 1,
		))
		.into();
		let msg = build_tree_hash(&data.param_bytes, &left, &right, level as u32, index >> 1);
		hasher.populate_message(w, &msg);
		hasher.populate_digest(w, parent);
		current = parent;
		index >>= 1;
	}
}

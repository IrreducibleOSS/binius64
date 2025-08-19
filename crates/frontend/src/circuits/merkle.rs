use std::array;

use binius_core::word::Word;
use itertools::izip;
use sha2::Digest;

use crate::{
	circuits::{keccak::Keccak, sha256::Sha256},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};

/// Trait for two-to-one compression functions used in merkle tree circuits.
///
/// This trait abstracts over different hash functions (like SHA256, Keccak) to enable
/// generic merkle tree verification circuits. Each level of a merkle tree computes
/// `hash(left_child || right_child)` using the compression function.
///
/// The trait bridges between:
/// - Circuit representation: `DigestWires` - the wires in the circuit that hold hash values
/// - Runtime representation: `Digest` - the actual hash bytes used during witness generation
pub trait Compression {
	/// Circuit wires that represent a hash digest in the constraint system.
	/// For example, a 32-byte hash might be represented as 4 wires of 64-bit words.
	type DigestWires: Clone;

	/// The actual hash value as bytes, used when populating witnesses.
	/// For example, `[u8; 32]` for SHA256 or Keccak256 hashes.
	type Digest: Clone;

	/// Iterate over the individual wires in a digest.
	fn iter_wires(wires: &Self::DigestWires) -> impl Iterator<Item = &Wire>;
	/// Create digest wires from an iterator (fails if wrong length).
	fn from_wires(iter: impl Iterator<Item = Wire>) -> Option<Self::DigestWires>;
	/// Get the left and right input digest wires for compression.
	fn inputs(&self, b: &CircuitBuilder) -> [Self::DigestWires; 2];
	/// Get the output digest wires after compression.
	fn output(&self, b: &CircuitBuilder) -> Self::DigestWires;
	/// Set witness values for digest wires from actual hash bytes.
	fn populate_digest(w: &mut WitnessFiller, wires: &Self::DigestWires, digest: &Self::Digest);
	/// Compute hash(left||right) and populate any witness values for the compression circuit.
	fn populate_compression(
		&mut self,
		w: &mut WitnessFiller,
		left: &Self::Digest,
		right: &Self::Digest,
	) -> Self::Digest;
}

impl Compression for Keccak {
	type Digest = [u8; 32];
	type DigestWires = [Wire; 4];

	fn iter_wires(wires: &Self::DigestWires) -> impl Iterator<Item = &Wire> {
		wires.iter()
	}

	fn from_wires(iter: impl Iterator<Item = Wire>) -> Option<Self::DigestWires> {
		iter.collect::<Vec<_>>().try_into().ok()
	}

	fn inputs(&self, _b: &CircuitBuilder) -> [Self::DigestWires; 2] {
		let message = &self.message;
		assert!(
			message.len() >= 8,
			"Keccak message should have at least 8 words for merkle compression"
		);
		let left: [Wire; 4] = message[..4].try_into().expect("message size 8");
		let right: [Wire; 4] = message[4..8].try_into().expect("message size 8");
		[left, right]
	}

	fn output(&self, _b: &CircuitBuilder) -> Self::DigestWires {
		let state = &self.digest;
		array::from_fn(|i| state[i])
	}

	fn populate_digest(w: &mut WitnessFiller, wires: &Self::DigestWires, digest: &[u8; 32]) {
		for (i, bytes) in digest.chunks(8).enumerate() {
			let word = u64::from_le_bytes(bytes.try_into().expect("size BYTES_PER_WORD = 8"));
			w[wires[i]] = Word(word);
		}
	}

	fn populate_compression(
		&mut self,
		w: &mut WitnessFiller,
		left: &[u8; 32],
		right: &[u8; 32],
	) -> [u8; 32] {
		const BYTES_PER_DIGEST: usize = 32;
		const INPUT_LEN: usize = 2 * BYTES_PER_DIGEST;

		let mut input = [0u8; INPUT_LEN];
		input[..BYTES_PER_DIGEST].copy_from_slice(left);
		input[BYTES_PER_DIGEST..].copy_from_slice(right);

		let mut hasher = sha3::Keccak256::new();
		hasher.update(input);
		let result = hasher.finalize();
		let digest: [u8; BYTES_PER_DIGEST] = result[..BYTES_PER_DIGEST]
			.try_into()
			.expect("hash should be 32 bytes");

		self.populate_len(w, INPUT_LEN);
		self.populate_message(w, &input);
		self.populate_digest(w, digest);

		digest
	}
}

impl Compression for Sha256 {
	type Digest = [u8; 32];
	type DigestWires = [Wire; 4];

	fn iter_wires(wires: &Self::DigestWires) -> impl Iterator<Item = &Wire> {
		wires.iter()
	}

	fn from_wires(iter: impl Iterator<Item = Wire>) -> Option<Self::DigestWires> {
		iter.collect::<Vec<_>>().try_into().ok()
	}

	fn inputs(&self, b: &CircuitBuilder) -> [Self::DigestWires; 2] {
		let message = self.message_to_le_wires(b);
		assert!(
			message.len() >= 8,
			"Keccak message should have at least 8 words for merkle compression"
		);
		let left: [Wire; 4] = message[..4].try_into().expect("message size 8");
		let right: [Wire; 4] = message[4..8].try_into().expect("message size 8");
		[left, right]
	}

	fn output(&self, b: &CircuitBuilder) -> Self::DigestWires {
		self.digest_to_le_wires(b)
	}

	fn populate_digest(w: &mut WitnessFiller, wires: &Self::DigestWires, digest: &[u8; 32]) {
		for (i, bytes) in digest.chunks(8).enumerate() {
			let word = u64::from_le_bytes(bytes.try_into().expect("size BYTES_PER_WORD = 8"));
			w[wires[i]] = Word(word);
		}
	}

	fn populate_compression(
		&mut self,
		w: &mut WitnessFiller,
		left: &[u8; 32],
		right: &[u8; 32],
	) -> [u8; 32] {
		const BYTES_PER_DIGEST: usize = 32;
		const INPUT_LEN: usize = 2 * BYTES_PER_DIGEST;
		let mut input = [0u8; INPUT_LEN];
		input[..BYTES_PER_DIGEST].copy_from_slice(left);
		input[BYTES_PER_DIGEST..].copy_from_slice(right);

		let mut hasher = sha2::Sha256::new();
		hasher.update(input);
		let result = hasher.finalize();
		let digest: [u8; BYTES_PER_DIGEST] = result[..BYTES_PER_DIGEST]
			.try_into()
			.expect("hash should be 32 bytes");

		self.populate_len(w, INPUT_LEN);
		self.populate_message(w, &input);
		self.populate_digest(w, digest);

		digest
	}
}

/// Circuit that verifies a merkle path from leaf to root.
///
/// Proves that a leaf with a given hash and index belongs to a merkle tree with a specific root.
/// Uses the provided compression function to hash siblings at each level.
pub struct MerklePath<C: Compression> {
	/// Tree depth (number of levels from leaf to root)
	pub depth: usize,
	/// Wire containing the leaf's position in the tree
	pub leaf_index: Wire,
	/// Wires containing the leaf hash
	pub leaf: C::DigestWires,
	/// Wires containing the expected root hash
	pub root: C::DigestWires,
	/// Wires containing sibling hashes for each level
	pub path: Vec<C::DigestWires>,

	/// Compression circuits for each level of the path
	compression_circuits: Vec<C>,
}

impl<C: Compression> MerklePath<C> {
	/// Creates a new merkle path verification circuit.
	///
	/// Builds constraints ensuring the leaf hashes up to the root via the sibling path.
	pub fn new(
		b: &CircuitBuilder,
		depth: usize,
		leaf: C::DigestWires,
		leaf_index: Wire,
		path: Vec<C::DigestWires>,
		hash_circuit_factory: impl Fn(&CircuitBuilder) -> C,
	) -> Self {
		assert!(depth > 0, "depth must be positive");
		assert_eq!(path.len(), depth, "path length must equal depth");

		let (root, path_hash_circuits) = Self::constrain_path_verification(
			b,
			depth,
			leaf.clone(),
			leaf_index,
			&path,
			&hash_circuit_factory,
		);

		Self {
			depth,
			leaf,
			leaf_index,
			root,
			path,
			compression_circuits: path_hash_circuits,
		}
	}

	/// Build constraints that verify the merkle path from leaf to root.
	fn constrain_path_verification(
		b: &CircuitBuilder,
		depth: usize,
		mut current_digest: C::DigestWires,
		mut current_index: Wire,
		path: &[C::DigestWires],
		compression_circuit_factory: impl Fn(&CircuitBuilder) -> C,
	) -> (C::DigestWires, Vec<C>) {
		assert_eq!(path.len(), depth, "path length must equal depth");
		let one = b.add_constant(Word::ONE);
		let mut compression_circuits = Vec::new();

		for level in 0..depth {
			let sibling = &path[level];

			// Determine if current node is right child (index_bit = 1) or left child (index_bit =
			// 0)
			let index_bit = b.band(current_index, one);
			let is_right = b.icmp_eq(index_bit, one);

			let merkle_left =
				C::from_wires(izip!(C::iter_wires(&current_digest), C::iter_wires(sibling)).map(
					|(&current, &sibling)| {
						// If right child: sibling | If left child: current_digest
						b.select(current, sibling, is_right)
					},
				))
				.expect("input len equals iter_wires len");
			let merkle_right =
				C::from_wires(izip!(C::iter_wires(sibling), C::iter_wires(&current_digest)).map(
					|(&sibling, &current)| {
						// If right child: current_digest | If left child: sibling
						b.select(sibling, current, is_right)
					},
				))
				.expect("input len equals iter_wires len");

			let compression_circuit = compression_circuit_factory(b);
			// Verify inputs match merkle computation
			let [compression_left, compression_right] = compression_circuit.inputs(b);
			izip!(
				C::iter_wires(&merkle_left),
				C::iter_wires(&compression_left),
				C::iter_wires(&merkle_right),
				C::iter_wires(&compression_right)
			)
			.for_each(|(&merkle_left, &compression_left, &merkle_right, &compression_right)| {
				b.assert_eq("input_left_agreement", merkle_left, compression_left);
				b.assert_eq("input_right_agreement", merkle_right, compression_right);
			});

			// Use compression output as next digest
			current_digest = compression_circuit.output(b);
			compression_circuits.push(compression_circuit);

			// Move to parent node index for next level
			current_index = b.shr(current_index, 1);
		}

		(current_digest, compression_circuits)
	}

	/// Set the leaf's index position in the tree.
	pub fn populate_leaf_index(&self, w: &mut WitnessFiller, leaf_index: u64) {
		assert!(
			leaf_index < (1u64 << self.depth),
			"leaf_index {leaf_index} out of bounds for depth {depth}",
			depth = self.depth
		);
		w[self.leaf_index] = Word(leaf_index);
	}

	/// Set the leaf hash value.
	pub fn populate_leaf(&self, w: &mut WitnessFiller, leaf: &C::Digest) {
		C::populate_digest(w, &self.leaf, leaf);
	}

	/// Set the expected root hash.
	pub fn populate_root(&self, w: &mut WitnessFiller, root: &C::Digest) {
		C::populate_digest(w, &self.root, root);
	}

	/// Set sibling hashes and populate all compression circuits.
	pub fn populate_path(
		&mut self,
		w: &mut WitnessFiller,
		path: &[&C::Digest],
		leaf: &C::Digest,
		leaf_index: u64,
	) {
		assert_eq!(
			path.len(),
			self.depth,
			"path length {path_len} must equal depth {depth}",
			path_len = path.len(),
			depth = self.depth
		);

		let mut current_digest = leaf.clone();
		let mut current_index = leaf_index;

		for level in 0..self.depth {
			let sibling = path[level];
			C::populate_digest(w, &self.path[level], sibling);

			let is_right = current_index & 1 == 1;
			let (left, right) = if is_right {
				(sibling, &current_digest)
			} else {
				(&current_digest, sibling)
			};

			let compression_result =
				C::populate_compression(&mut self.compression_circuits[level], w, left, right);

			current_digest = compression_result;
			current_index >>= 1;
		}
	}
}

#[cfg(test)]
mod tests {
	use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{
		circuits::tree::{HashOut, MerkleTree},
		compiler::circuit::Circuit,
		constraint_verifier::verify_constraints,
	};

	// TODO: Add tests for SHA3-512 which has output size 64 bytes
	// below only tests SHA256 and Keccak256 which have output size 32 bytes

	/// Create test merkle circuit for 32-byte hash functions (4 wires × 8 bytes).
	fn create_merkle_circuit_for_32_byte_output_compressions<
		C: Compression<DigestWires = [Wire; 4]>,
	>(
		depth: usize,
		factory: impl Fn(&CircuitBuilder) -> C,
	) -> (Circuit, MerklePath<C>) {
		let builder = CircuitBuilder::new();
		let leaf: [Wire; 4] = array::from_fn(|_| builder.add_witness());
		let leaf_index = builder.add_witness();
		let path = (0..depth)
			.map(|_| array::from_fn(|_| builder.add_witness()))
			.collect();

		let merkle = MerklePath::new(&builder, depth, leaf, leaf_index, path, factory);
		(builder.build(), merkle)
	}

	/// Create merkle circuit using Keccak256 compression.
	fn create_merkle_circuit_keccak(depth: usize) -> (Circuit, MerklePath<Keccak>) {
		create_merkle_circuit_for_32_byte_output_compressions(depth, |b: &CircuitBuilder| {
			let level_len = b.add_constant_64(64);
			let level_digest = array::from_fn(|_| b.add_witness());
			let level_data = (0..16).map(|_| b.add_witness()).collect();
			Keccak::new(b, 64, level_len, level_digest, level_data)
		})
	}

	/// Create merkle circuit using SHA256 compression.
	fn create_merkle_circuit_sha256(depth: usize) -> (Circuit, MerklePath<Sha256>) {
		create_merkle_circuit_for_32_byte_output_compressions(depth, |b: &CircuitBuilder| {
			let level_len = b.add_constant_64(64);
			let level_digest = array::from_fn(|_| b.add_witness());
			let level_data = (0..16).map(|_| b.add_witness()).collect();
			Sha256::new(b, 64, level_len, level_digest, level_data)
		})
	}

	#[test]
	fn test_merkle_circuit_for_sha256_compression_using_real_merkle_tree() {
		let mut rng = StdRng::seed_from_u64(0);

		for depth in [1, 2, 5, 11] {
			let num_leaves = 1 << depth;
			let leaves: Vec<HashOut> = (0..num_leaves)
				.map(|_| {
					let mut leaf = [0u8; 32];
					rng.fill_bytes(&mut leaf);
					leaf
				})
				.collect();

			let tree = MerkleTree::build(&leaves);
			let root = tree.root();

			// Test up to 5 random leaf indices for this tree depth
			for _ in 0..std::cmp::min(5, num_leaves) {
				let leaf_index = rng.random_range(0..num_leaves);
				let target_leaf = leaves[leaf_index];
				let path = tree.branch(leaf_index, 0);

				let (circuit, mut merkle_circuit) = create_merkle_circuit_sha256(depth);
				let mut witness = circuit.new_witness_filler();

				merkle_circuit.populate_leaf_index(&mut witness, leaf_index as u64);
				merkle_circuit.populate_leaf(&mut witness, &target_leaf);
				merkle_circuit.populate_root(&mut witness, &root);

				let path_refs: Vec<&[u8; 32]> = path.iter().collect();
				merkle_circuit.populate_path(
					&mut witness,
					&path_refs,
					&target_leaf,
					leaf_index as u64,
				);

				circuit.populate_wire_witness(&mut witness).unwrap();
				let constraints = circuit.constraint_system();
				verify_constraints(constraints, &witness.into_value_vec()).unwrap_or_else(|e| {
					panic!("Failed sha256 real tree test (depth={depth}, leaf={leaf_index}): {e}")
				});
			}
		}
	}

	/// Test merkle path verification for different hash functions
	fn test_merkle_circuit_for_32_byte_output_compressions<C>(
		create_circuit: impl Fn(usize) -> (Circuit, MerklePath<C>),
		hash_fn: impl Fn(&[u8]) -> C::Digest,
		name: &str,
	) where
		C: Compression<Digest = [u8; 32]>,
	{
		let mut rng = StdRng::seed_from_u64(0);

		// (depth, leaf_index)
		let test_cases = vec![
			// Single level trees
			(1, 0), // Left child
			(1, 1), // Right child
			// Multi-level trees
			(2, 0), // Leftmost
			(2, 3), // Rightmost
			(3, 0), // Deeper leftmost
			(3, 4), // Deeper middle
			(3, 7), // Deeper rightmost
		];

		for (depth, leaf_index) in test_cases {
			let leaf = [42u8; 32];
			let mut path = Vec::with_capacity(depth);
			let mut current_hash = leaf;

			// Build merkle path
			for level in 0..depth {
				let mut sibling = [0u8; 32];
				rng.fill_bytes(&mut sibling);

				let is_right = (leaf_index >> level) & 1 == 1;
				let (left, right) = if is_right {
					(sibling, current_hash)
				} else {
					(current_hash, sibling)
				};

				current_hash = hash_fn(&[left, right].concat());
				path.push(sibling);
			}

			let (circuit, mut merkle_circuit) = create_circuit(depth);
			let mut witness = circuit.new_witness_filler();

			merkle_circuit.populate_leaf_index(&mut witness, leaf_index);
			merkle_circuit.populate_leaf(&mut witness, &leaf);
			merkle_circuit.populate_root(&mut witness, &current_hash);

			let path_refs: Vec<&[u8; 32]> = path.iter().collect();
			merkle_circuit.populate_path(&mut witness, &path_refs, &leaf, leaf_index);

			circuit.populate_wire_witness(&mut witness).unwrap();
			let constraints = circuit.constraint_system();
			verify_constraints(constraints, &witness.into_value_vec()).unwrap_or_else(|e| {
				panic!("Failed {name} test (depth={depth}, leaf={leaf_index}): {e}")
			});
		}
	}

	/// Helper to compute hash and truncate to 32 bytes.
	fn hash_with_32_byte_output<D: Digest>(new_hasher: impl Fn() -> D, data: &[u8]) -> [u8; 32] {
		let mut hasher = new_hasher();
		hasher.update(data);
		let result = hasher.finalize();
		result[..32].try_into().expect("hash should be 32 bytes")
	}

	#[test]
	fn test_merkle_verification_keccak() {
		test_merkle_circuit_for_32_byte_output_compressions(
			create_merkle_circuit_keccak,
			|data| hash_with_32_byte_output(sha3::Keccak256::new, data),
			"Keccak",
		);
	}

	#[test]
	fn test_merkle_verification_sha256() {
		test_merkle_circuit_for_32_byte_output_compressions(
			create_merkle_circuit_sha256,
			|data| hash_with_32_byte_output(sha2::Sha256::new, data),
			"SHA256",
		);
	}
}

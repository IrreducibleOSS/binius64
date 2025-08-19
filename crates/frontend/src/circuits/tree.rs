use sha2::{Digest, Sha256};

/// Type alias for 32-byte hash output
pub type HashOut = [u8; 32];

/// A binary Merkle tree commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
	pub root: HashOut,
	pub depth: usize,
}

/// A binary Merkle tree that commits to vectors of 32-byte values
#[derive(Debug, Clone)]
pub struct MerkleTree {
	/// Base-2 logarithm of the number of leaves
	pub log_len: usize,
	/// The inner nodes, arranged as a flattened array of layers with the root at the end
	pub inner_nodes: Vec<HashOut>,
}

impl MerkleTree {
	/// Build a Merkle tree from leaf values
	///
	/// # Panics
	/// Panics if the number of leaves is not a power of two or is empty
	pub fn build(leaves: &[HashOut]) -> Self {
		assert!(!leaves.is_empty(), "Cannot build tree from empty leaves");
		assert!(leaves.len().is_power_of_two(), "Number of leaves must be power of two");

		let log_len = leaves.len().trailing_zeros() as usize;
		let total_nodes = (1 << (log_len + 1)) - 1;
		let mut inner_nodes = Vec::with_capacity(total_nodes);

		// Copy leaves as first layer
		inner_nodes.extend_from_slice(leaves);

		// Build tree layer by layer
		let mut layer_start = 0;
		let mut layer_size = leaves.len();

		while layer_size > 1 {
			for i in 0..(layer_size / 2) {
				let left = &inner_nodes[layer_start + 2 * i];
				let right = &inner_nodes[layer_start + 2 * i + 1];
				inner_nodes.push(compress_sha256(left, right));
			}
			layer_start += layer_size;
			layer_size /= 2;
		}

		MerkleTree {
			log_len,
			inner_nodes,
		}
	}

	/// Get the root hash of the tree
	pub fn root(&self) -> HashOut {
		self.inner_nodes[self.inner_nodes.len() - 1]
	}

	/// Get the commitment (root + depth)
	pub fn commitment(&self) -> Commitment {
		Commitment {
			root: self.root(),
			depth: self.log_len,
		}
	}

	/// Get the digests at a specific layer depth
	///
	/// # Panics
	/// Panics if layer_depth > log_len
	pub fn layer(&self, layer_depth: usize) -> &[HashOut] {
		assert!(layer_depth <= self.log_len, "Layer depth exceeds tree depth");

		let layer_size = 1 << layer_depth;
		let range_start = self.inner_nodes.len() + 1 - (1 << (layer_depth + 1));

		&self.inner_nodes[range_start..range_start + layer_size]
	}

	/// Get a Merkle branch for the given index
	///
	/// # Panics
	/// Panics if index is out of range or layer_depth > log_len
	pub fn branch(&self, index: usize, layer_depth: usize) -> Vec<HashOut> {
		assert!(index < (1 << self.log_len), "Index out of range");
		assert!(layer_depth <= self.log_len, "Layer depth exceeds tree depth");

		let mut branch = Vec::new();
		let mut current_index = index;
		let mut layer_start = 0;
		let mut layer_size = 1 << self.log_len;

		for _ in 0..(self.log_len - layer_depth) {
			let sibling_index = current_index ^ 1;
			branch.push(self.inner_nodes[layer_start + sibling_index]);

			layer_start += layer_size;
			layer_size /= 2;
			current_index /= 2;
		}

		branch
	}
}

/// Compress two 32-byte values using SHA256
pub fn compress_sha256(left: &HashOut, right: &HashOut) -> HashOut {
	let mut hasher = Sha256::new();
	hasher.update(left);
	hasher.update(right);
	hasher.finalize().into()
}

/// Verify a branch from a leaf to a specific layer
///
/// Returns true if the branch is valid
pub fn verify_branch_to_layer(
	leaf: &HashOut,
	index: usize,
	branch: &[HashOut],
	layer_depth: usize,
	layer_digests: &[HashOut],
) -> bool {
	assert!(layer_digests.len() == (1 << layer_depth), "Invalid layer size");

	let mut current_hash = *leaf;
	let mut current_index = index;

	for sibling in branch {
		if current_index & 1 == 0 {
			current_hash = compress_sha256(&current_hash, sibling);
		} else {
			current_hash = compress_sha256(sibling, &current_hash);
		}
		current_index /= 2;
	}

	current_hash == layer_digests[current_index]
}

/// Verify inclusion of a leaf in the tree
///
/// This is a thin wrapper around verify_branch_to_layer with layer_depth = 0
pub fn verify_inclusion(leaf: &HashOut, index: usize, branch: &[HashOut], root: &HashOut) -> bool {
	verify_branch_to_layer(leaf, index, branch, 0, &[*root])
}

/// Verify that a layer of digests correctly hashes to the root
///
/// Returns true if the layer is valid
pub fn verify_layer(root: &HashOut, layer_depth: usize, layer_digests: &[HashOut]) -> bool {
	assert!(layer_digests.len() == (1 << layer_depth), "Invalid layer size");
	assert!(layer_digests.len().is_power_of_two(), "Layer size must be power of two");

	let mut current_layer = layer_digests.to_vec();

	while current_layer.len() > 1 {
		let mut next_layer = Vec::new();
		for i in 0..(current_layer.len() / 2) {
			next_layer.push(compress_sha256(&current_layer[2 * i], &current_layer[2 * i + 1]));
		}
		current_layer = next_layer;
	}

	current_layer[0] == *root
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_leaves(n: usize) -> Vec<HashOut> {
		(0..n)
			.map(|i| {
				let mut leaf = [0u8; 32];
				leaf[0] = i as u8;
				leaf
			})
			.collect()
	}

	#[test]
	fn test_build_tree_2_leaves() {
		let leaves = test_leaves(2);
		let tree = MerkleTree::build(&leaves);

		assert_eq!(tree.log_len, 1);
		assert_eq!(tree.inner_nodes.len(), 3);

		// Check leaves are stored correctly
		assert_eq!(&tree.inner_nodes[0..2], &leaves[..]);

		// Check root is compression of two leaves
		let expected_root = compress_sha256(&leaves[0], &leaves[1]);
		assert_eq!(tree.root(), expected_root);
	}

	#[test]
	fn test_build_tree_4_leaves() {
		let leaves = test_leaves(4);
		let tree = MerkleTree::build(&leaves);

		assert_eq!(tree.log_len, 2);
		assert_eq!(tree.inner_nodes.len(), 7);

		// Check structure
		let h01 = compress_sha256(&leaves[0], &leaves[1]);
		let h23 = compress_sha256(&leaves[2], &leaves[3]);
		let root = compress_sha256(&h01, &h23);

		assert_eq!(tree.root(), root);
	}

	#[test]
	fn test_commitment() {
		let leaves = test_leaves(8);
		let tree = MerkleTree::build(&leaves);
		let commitment = tree.commitment();

		assert_eq!(commitment.root, tree.root());
		assert_eq!(commitment.depth, 3);
	}

	#[test]
	fn test_layer() {
		let leaves = test_leaves(8);
		let tree = MerkleTree::build(&leaves);

		// Layer 3 should have 8 leaves
		let layer3 = tree.layer(3);
		assert_eq!(layer3.len(), 8);
		assert_eq!(layer3, &leaves[..]);

		// Layer 2 should have 4 nodes
		let layer2 = tree.layer(2);
		assert_eq!(layer2.len(), 4);

		// Layer 1 should have 2 nodes
		let layer1 = tree.layer(1);
		assert_eq!(layer1.len(), 2);

		// Layer 0 should have 1 node (root)
		let layer0 = tree.layer(0);
		assert_eq!(layer0.len(), 1);
		assert_eq!(layer0[0], tree.root());
	}

	#[test]
	fn test_branch_and_verify() {
		let leaves = test_leaves(8);
		let tree = MerkleTree::build(&leaves);
		let root = tree.root();

		// Test branch for each leaf
		for i in 0..8 {
			let branch = tree.branch(i, 0);
			assert_eq!(branch.len(), 3); // log2(8) = 3

			// Verify inclusion
			assert!(verify_inclusion(&leaves[i], i, &branch, &root));

			// Wrong leaf should fail
			let mut wrong_leaf = leaves[i];
			wrong_leaf[0] ^= 1;
			assert!(!verify_inclusion(&wrong_leaf, i, &branch, &root));
		}
	}

	#[test]
	fn test_branch_to_layer() {
		let leaves = test_leaves(16);
		let tree = MerkleTree::build(&leaves);

		// Get layer 2 (4 nodes)
		let layer2 = tree.layer(2);

		// Test branch from leaf 5 to layer 2
		let branch = tree.branch(5, 2);
		assert_eq!(branch.len(), 2); // 4 - 2 = 2 levels

		assert!(verify_branch_to_layer(&leaves[5], 5, &branch, 2, layer2));
	}

	#[test]
	fn test_verify_layer() {
		let leaves = test_leaves(8);
		let tree = MerkleTree::build(&leaves);
		let root = tree.root();

		// Verify each layer
		for depth in 0..=3 {
			let layer = tree.layer(depth);
			assert!(verify_layer(&root, depth, layer));
		}

		// Wrong layer should fail
		let mut wrong_layer = tree.layer(2).to_vec();
		wrong_layer[0][0] ^= 1;
		assert!(!verify_layer(&root, 2, &wrong_layer));
	}

	#[test]
	#[should_panic(expected = "Cannot build tree from empty leaves")]
	fn test_empty_leaves_panic() {
		MerkleTree::build(&[]);
	}

	#[test]
	#[should_panic(expected = "Number of leaves must be power of two")]
	fn test_non_power_of_two_panic() {
		let leaves = test_leaves(3);
		MerkleTree::build(&leaves);
	}

	#[test]
	#[should_panic(expected = "Layer depth exceeds tree depth")]
	fn test_layer_depth_out_of_range() {
		let leaves = test_leaves(4);
		let tree = MerkleTree::build(&leaves);
		tree.layer(3); // log_len is 2, so max depth is 2
	}

	#[test]
	#[should_panic(expected = "Index out of range")]
	fn test_branch_index_out_of_range() {
		let leaves = test_leaves(4);
		let tree = MerkleTree::build(&leaves);
		tree.branch(4, 0); // Only indices 0-3 are valid
	}

	#[test]
	fn test_large_tree() {
		let leaves = test_leaves(256);
		let tree = MerkleTree::build(&leaves);

		assert_eq!(tree.log_len, 8);

		// Verify a few random branches
		for i in [0, 42, 127, 255] {
			let branch = tree.branch(i, 0);
			assert_eq!(branch.len(), 8);
			assert!(verify_inclusion(&leaves[i], i, &branch, &tree.root()));
		}
	}
}

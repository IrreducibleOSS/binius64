//! Reference implementation of ECDSA Semaphore protocol for testing.
//!
//! This module provides a pure Rust implementation of the ECDSA Semaphore protocol
//! that serves as the ground truth for circuit testing.

use k256::{
	ProjectivePoint, Scalar,
	elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use sha3::{Digest, Keccak256};

/// Computes secp256k1 public key coordinates.
/// Takes LE scalar bytes, converts to BE for k256, then returns LE coordinate bytes.
fn compute_public_key_coords(secret_scalar: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
	// Validate non-zero scalar to avoid point at infinity
	assert!(secret_scalar.iter().any(|&b| b != 0), "Secret scalar must be non-zero");

	// secret_scalar is LE from circuit, but k256 needs BE
	let mut scalar_be = *secret_scalar;
	scalar_be.reverse();

	let scalar = Scalar::from_repr(scalar_be.into()).expect("Invalid scalar");
	let public_key_point = ProjectivePoint::GENERATOR * scalar;
	let affine_point = public_key_point.to_affine();
	let encoded = affine_point.to_encoded_point(false);

	if let k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } = encoded.coordinates() {
		let mut x_coord: [u8; 32] = (*x).into();
		let mut y_coord: [u8; 32] = (*y).into();

		// k256 returns BE, but circuit expects LE
		x_coord.reverse();
		y_coord.reverse();

		(x_coord, y_coord)
	} else {
		panic!("Expected uncompressed coordinates");
	}
}

/// ECDSA identity using secp256k1 private key
pub struct IdentityECDSA {
	pub secret_scalar: [u8; 32],
}

impl IdentityECDSA {
	pub fn new(secret_scalar: [u8; 32]) -> Self {
		Self { secret_scalar }
	}

	pub fn commitment(&self) -> [u8; 32] {
		let (x_coord, y_coord) = compute_public_key_coords(&self.secret_scalar);

		// Direct byte concatenation - coordinates are already in correct LE format
		let mut message_bytes = Vec::with_capacity(64);
		message_bytes.extend_from_slice(&x_coord);
		message_bytes.extend_from_slice(&y_coord);

		let mut hasher = Keccak256::new();
		hasher.update(&message_bytes);
		hasher.finalize().into()
	}

	pub fn nullifier(&self, scope: &[u8]) -> [u8; 32] {
		let mut hasher = Keccak256::new();
		hasher.update(scope);
		hasher.update(self.secret_scalar);
		hasher.finalize().into()
	}
}

/// Merkle tree for group membership.
pub struct MerkleTree {
	/// Tree height (depth)
	pub height: usize,
	/// Leaf nodes (identity commitments)
	pub leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
	/// Creates a new Merkle tree with the given height.
	pub fn new(height: usize) -> Self {
		Self {
			height,
			leaves: Vec::new(),
		}
	}

	/// Adds a leaf (identity commitment) to the tree.
	pub fn add_leaf(&mut self, leaf: [u8; 32]) {
		self.leaves.push(leaf);
	}

	/// Computes the root of the Merkle tree.
	pub fn root(&self) -> [u8; 32] {
		if self.leaves.is_empty() {
			return [0u8; 32];
		}

		// Start with leaves, padding with zeros if needed
		let mut level = self.leaves.clone();
		let max_leaves = 1 << self.height;
		level.resize(max_leaves, [0u8; 32]);

		// Build tree bottom-up
		while level.len() > 1 {
			let mut next_level = Vec::new();
			for i in (0..level.len()).step_by(2) {
				let left = level[i];
				let right = if i + 1 < level.len() {
					level[i + 1]
				} else {
					[0u8; 32]
				};

				let mut hasher = Keccak256::new();
				hasher.update(left);
				hasher.update(right);
				next_level.push(hasher.finalize().into());
			}
			level = next_level;
		}

		level[0]
	}

	/// Generates a Merkle proof for a leaf at the given index.
	pub fn proof(&self, leaf_index: usize) -> MerkleProof {
		assert!(leaf_index < self.leaves.len(), "Leaf index out of bounds");

		let mut siblings = Vec::new();
		let mut level = self.leaves.clone();
		let max_leaves = 1 << self.height;
		level.resize(max_leaves, [0u8; 32]);

		let mut current_index = leaf_index;

		// Collect siblings at each level
		for _ in 0..self.height {
			let sibling_index = current_index ^ 1; // XOR with 1 to get sibling
			let sibling = if sibling_index < level.len() {
				level[sibling_index]
			} else {
				[0u8; 32]
			};
			siblings.push(sibling);

			// Compute next level
			let mut next_level = Vec::new();
			for i in (0..level.len()).step_by(2) {
				let left = level[i];
				let right = if i + 1 < level.len() {
					level[i + 1]
				} else {
					[0u8; 32]
				};

				let mut hasher = Keccak256::new();
				hasher.update(left);
				hasher.update(right);
				next_level.push(hasher.finalize().into());
			}

			level = next_level;
			current_index /= 2;
		}

		MerkleProof {
			leaf: self.leaves[leaf_index],
			leaf_index,
			siblings,
			root: level[0],
		}
	}
}

/// Merkle proof for a specific leaf.
#[derive(Debug, Clone)]
pub struct MerkleProof {
	/// The leaf value being proved
	pub leaf: [u8; 32],
	/// Index of the leaf in the tree
	pub leaf_index: usize,
	/// Sibling nodes needed to compute the root
	pub siblings: Vec<[u8; 32]>,
	/// The computed root
	pub root: [u8; 32],
}

impl MerkleProof {
	/// Verifies that this proof is valid for the given root.
	pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
		let mut current = self.leaf;
		let mut index = self.leaf_index;

		for sibling in &self.siblings {
			let (left, right) = if index % 2 == 0 {
				(current, *sibling)
			} else {
				(*sibling, current)
			};

			let mut hasher = Keccak256::new();
			hasher.update(left);
			hasher.update(right);
			current = hasher.finalize().into();

			index /= 2;
		}

		current == *expected_root
	}
}

/// Reference implementation of Semaphore proof with ECDSA
pub struct SemaphoreProofECDSA {
	pub message: Vec<u8>,
	pub scope: Vec<u8>,
	pub nullifier: [u8; 32],
	pub merkle_proof: MerkleProof,
}

impl SemaphoreProofECDSA {
	/// Generates a proof for the given identity and parameters
	pub fn generate(
		identity: &IdentityECDSA,
		tree: &MerkleTree,
		leaf_index: usize,
		message: &[u8],
		scope: &[u8],
	) -> Self {
		let nullifier = identity.nullifier(scope);
		let merkle_proof = tree.proof(leaf_index);

		Self {
			message: message.to_vec(),
			scope: scope.to_vec(),
			nullifier,
			merkle_proof,
		}
	}

	/// Verifies the proof against the expected Merkle root
	pub fn verify(&self, merkle_root: &[u8; 32]) -> bool {
		self.merkle_proof.verify(merkle_root)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ecdsa_identity_commitment() {
		let identity = IdentityECDSA::new([42u8; 32]);
		let commitment = identity.commitment();

		// Commitment should be deterministic
		let commitment2 = identity.commitment();
		assert_eq!(commitment, commitment2);

		// Different identity should have different commitment
		let identity2 = IdentityECDSA::new([43u8; 32]);
		assert_ne!(commitment, identity2.commitment());
	}

	#[test]
	fn test_ecdsa_nullifier_generation() {
		let identity = IdentityECDSA::new([42u8; 32]);

		// Same scope produces same nullifier
		let null1 = identity.nullifier(b"scope1");
		let null2 = identity.nullifier(b"scope1");
		assert_eq!(null1, null2);

		// Different scopes produce different nullifiers
		let null3 = identity.nullifier(b"scope2");
		assert_ne!(null1, null3);
	}

	#[test]
	fn test_merkle_tree_single_leaf() {
		let mut tree = MerkleTree::new(1);
		let identity = IdentityECDSA::new([42u8; 32]);
		tree.add_leaf(identity.commitment());

		let root = tree.root();
		let proof = tree.proof(0);

		assert_eq!(proof.leaf, identity.commitment());
		assert_eq!(proof.root, root);
		assert!(proof.verify(&root));
	}

	#[test]
	fn test_merkle_tree_multiple_leaves() {
		let mut tree = MerkleTree::new(3);

		for i in 0..5 {
			let identity = IdentityECDSA::new([(i + 1) as u8; 32]);
			tree.add_leaf(identity.commitment());
		}

		let root = tree.root();

		// Verify proof for each leaf
		for i in 0..5 {
			let proof = tree.proof(i);
			assert!(proof.verify(&root));
		}
	}

	#[test]
	fn test_semaphore_proof_generation_and_verification() {
		// Setup
		let identity1 = IdentityECDSA::new([1u8; 32]);
		let identity2 = IdentityECDSA::new([2u8; 32]);
		let identity3 = IdentityECDSA::new([3u8; 32]);

		let mut tree = MerkleTree::new(2);
		tree.add_leaf(identity1.commitment());
		tree.add_leaf(identity2.commitment());
		tree.add_leaf(identity3.commitment());

		let root = tree.root();

		// Generate proof for identity2
		let message = b"vote yes";
		let scope = b"proposal1";
		let proof = SemaphoreProofECDSA::generate(&identity2, &tree, 1, message, scope);

		// Verify proof
		assert!(proof.verify(&root));
		assert_eq!(proof.nullifier, identity2.nullifier(scope));
		assert_eq!(proof.message, message);
		assert_eq!(proof.scope, scope);

		// Different scope should produce different nullifier
		let proof2 = SemaphoreProofECDSA::generate(&identity2, &tree, 1, message, b"proposal2");
		assert_ne!(proof.nullifier, proof2.nullifier);
	}
}

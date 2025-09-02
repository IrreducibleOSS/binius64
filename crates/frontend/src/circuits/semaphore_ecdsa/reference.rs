//! Reference implementation of Semaphore protocol for testing.
//!
//! This module provides a pure Rust implementation of the Semaphore protocol
//! that serves as the ground truth for circuit testing. It uses Keccak-256 as the
//! hash function and can be easily adapted to use Poseidon later.

use sha3::{Keccak256, Digest};

/// Represents a Semaphore identity with secret components.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Secret trapdoor value (256 bits)
    pub trapdoor: [u8; 32],
    /// Secret nullifier value (256 bits)
    pub nullifier: [u8; 32],
}

impl Identity {
    /// Creates a new identity with the given secrets.
    pub fn new(trapdoor: [u8; 32], nullifier: [u8; 32]) -> Self {
        Self { trapdoor, nullifier }
    }
    
    /// Computes the identity commitment.
    /// 
    /// commitment = Keccak256(trapdoor || nullifier)
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(self.trapdoor);
        hasher.update(self.nullifier);
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
    
    /// Adds an identity commitment to the tree.
    pub fn add_leaf(&mut self, commitment: [u8; 32]) {
        let max_leaves = 1 << self.height;
        assert!(self.leaves.len() < max_leaves, "Tree is full");
        self.leaves.push(commitment);
    }
    
    /// Computes the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        
        // Pad with zeros to next power of 2
        let mut nodes = self.leaves.clone();
        let target_size = 1 << self.height;
        nodes.resize(target_size, [0u8; 32]);
        
        // Build tree level by level
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let left = &nodes[i];
                let right = if i + 1 < nodes.len() {
                    &nodes[i + 1]
                } else {
                    &[0u8; 32]
                };
                next_level.push(hash_merkle_node(left, right));
            }
            nodes = next_level;
        }
        
        nodes[0]
    }
    
    /// Generates a Merkle proof for a leaf at the given index.
    pub fn proof(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.leaves.len(), "Leaf index out of bounds");
        
        let mut siblings = Vec::new();
        let mut nodes = self.leaves.clone();
        let target_size = 1 << self.height;
        nodes.resize(target_size, [0u8; 32]);
        
        let mut index = leaf_index;
        
        // Collect siblings at each level
        while nodes.len() > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = if sibling_index < nodes.len() {
                nodes[sibling_index]
            } else {
                [0u8; 32]
            };
            siblings.push(sibling);
            
            // Move to next level
            let mut next_level = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let left = &nodes[i];
                let right = if i + 1 < nodes.len() {
                    &nodes[i + 1]
                } else {
                    &[0u8; 32]
                };
                next_level.push(hash_merkle_node(left, right));
            }
            nodes = next_level;
            index /= 2;
        }
        
        MerkleProof {
            leaf: self.leaves[leaf_index],
            leaf_index,
            siblings,
            root: nodes[0],
        }
    }
}

/// Merkle proof for group membership.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf value being proved
    pub leaf: [u8; 32],
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Sibling hashes along the path to root
    pub siblings: Vec<[u8; 32]>,
    /// Expected root hash
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verifies the Merkle proof.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf;
        let mut index = self.leaf_index;
        
        for sibling in &self.siblings {
            current = if index % 2 == 0 {
                hash_merkle_node(&current, sibling)
            } else {
                hash_merkle_node(sibling, &current)
            };
            index /= 2;
        }
        
        current == self.root
    }
}

/// Hashes two Merkle tree nodes.
fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Generates a nullifier for a given scope and identity.
///
/// nullifier = Keccak256(scope || identity_nullifier)
pub fn generate_nullifier(scope: &[u8], identity_nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(scope);
    hasher.update(identity_nullifier);
    hasher.finalize().into()
}

/// Complete Semaphore proof generation.
pub struct SemaphoreProof {
    /// The message being signaled
    pub message: Vec<u8>,
    /// The scope for this signal
    pub scope: Vec<u8>,
    /// The Merkle root of the group
    pub merkle_root: [u8; 32],
    /// The nullifier (prevents double-signaling)
    pub nullifier: [u8; 32],
}

impl SemaphoreProof {
    /// Generates a Semaphore proof.
    pub fn generate(
        identity: &Identity,
        merkle_proof: &MerkleProof,
        message: Vec<u8>,
        scope: Vec<u8>,
    ) -> Self {
        // Verify the identity is in the group
        assert_eq!(identity.commitment(), merkle_proof.leaf);
        assert!(merkle_proof.verify());
        
        // Generate nullifier
        let nullifier = generate_nullifier(&scope, &identity.nullifier);
        
        Self {
            message,
            scope,
            merkle_root: merkle_proof.root,
            nullifier,
        }
    }
    
    /// Verifies a Semaphore proof (without the ZK part).
    /// In the actual circuit, this verification happens inside the ZK proof.
    pub fn verify(&self, merkle_proof: &MerkleProof, identity: &Identity) -> bool {
        // Check identity commitment matches leaf
        if identity.commitment() != merkle_proof.leaf {
            return false;
        }
        
        // Check Merkle proof
        if !merkle_proof.verify() {
            return false;
        }
        
        // Check Merkle root matches
        if merkle_proof.root != self.merkle_root {
            return false;
        }
        
        // Check nullifier is correct
        let expected_nullifier = generate_nullifier(&self.scope, &identity.nullifier);
        if expected_nullifier != self.nullifier {
            return false;
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_commitment() {
        let identity = Identity::new([1u8; 32], [2u8; 32]);
        let commitment = identity.commitment();
        
        // Commitment should be deterministic
        let commitment2 = identity.commitment();
        assert_eq!(commitment, commitment2);
        
        // Different identity should have different commitment
        let identity2 = Identity::new([3u8; 32], [4u8; 32]);
        assert_ne!(commitment, identity2.commitment());
    }
    
    #[test]
    fn test_merkle_tree_single_leaf() {
        let mut tree = MerkleTree::new(1);
        let identity = Identity::new([1u8; 32], [2u8; 32]);
        tree.add_leaf(identity.commitment());
        
        let root = tree.root();
        let proof = tree.proof(0);
        
        assert!(proof.verify());
        assert_eq!(proof.root, root);
    }
    
    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let mut tree = MerkleTree::new(3); // Height 3 = up to 8 leaves
        
        // Add 5 identities
        for i in 0..5 {
            let identity = Identity::new([i as u8; 32], [(i + 100) as u8; 32]);
            tree.add_leaf(identity.commitment());
        }
        
        let root = tree.root();
        
        // Verify proof for each leaf
        for i in 0..5 {
            let proof = tree.proof(i);
            assert!(proof.verify());
            assert_eq!(proof.root, root);
        }
    }
    
    #[test]
    fn test_nullifier_generation() {
        let identity = Identity::new([1u8; 32], [2u8; 32]);
        let scope1 = b"voting_event_1";
        let scope2 = b"voting_event_2";
        
        let nullifier1 = generate_nullifier(scope1, &identity.nullifier);
        let nullifier2 = generate_nullifier(scope2, &identity.nullifier);
        
        // Same scope should produce same nullifier
        let nullifier1_again = generate_nullifier(scope1, &identity.nullifier);
        assert_eq!(nullifier1, nullifier1_again);
        
        // Different scopes should produce different nullifiers
        assert_ne!(nullifier1, nullifier2);
    }
    
    #[test]
    fn test_semaphore_proof_generation_and_verification() {
        // Setup: Create a group with 3 members
        let mut tree = MerkleTree::new(2);
        
        let identity1 = Identity::new([1u8; 32], [101u8; 32]);
        let identity2 = Identity::new([2u8; 32], [102u8; 32]);
        let identity3 = Identity::new([3u8; 32], [103u8; 32]);
        
        tree.add_leaf(identity1.commitment());
        tree.add_leaf(identity2.commitment());
        tree.add_leaf(identity3.commitment());
        
        // Member 2 generates a proof
        let merkle_proof = tree.proof(1); // Index 1 = identity2
        let message = b"I vote YES".to_vec();
        let scope = b"proposal_42".to_vec();
        
        let proof = SemaphoreProof::generate(
            &identity2,
            &merkle_proof,
            message.clone(),
            scope.clone(),
        );
        
        // Verify the proof
        assert!(proof.verify(&merkle_proof, &identity2));
        
        // Verify nullifier prevents double-signaling
        let nullifier1 = proof.nullifier;
        let proof2 = SemaphoreProof::generate(
            &identity2,
            &merkle_proof,
            b"I vote NO".to_vec(), // Different message
            scope.clone(), // Same scope
        );
        assert_eq!(nullifier1, proof2.nullifier); // Same nullifier!
    }
    
    #[test]
    fn test_different_scopes_allow_multiple_signals() {
        let mut tree = MerkleTree::new(1);
        let identity = Identity::new([1u8; 32], [2u8; 32]);
        tree.add_leaf(identity.commitment());
        
        let merkle_proof = tree.proof(0);
        
        // Same user, different scopes
        let proof1 = SemaphoreProof::generate(
            &identity,
            &merkle_proof,
            b"vote1".to_vec(),
            b"proposal_1".to_vec(),
        );
        
        let proof2 = SemaphoreProof::generate(
            &identity,
            &merkle_proof,
            b"vote2".to_vec(),
            b"proposal_2".to_vec(),
        );
        
        // Different scopes = different nullifiers
        assert_ne!(proof1.nullifier, proof2.nullifier);
    }
}
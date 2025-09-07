//! Tests for Semaphore with ECDSA key derivation

#[cfg(test)]
mod test_semaphore_ecdsa {
	use crate::{
		circuits::semaphore_ecdsa::{
			circuit::SemaphoreProofECDSA,
			reference::{IdentityECDSA, MerkleTree},
		},
		compiler::CircuitBuilder,
	};

	/// Helper to create a Merkle tree with ECDSA identities
	fn create_tree_with_ecdsa_identities(identities: &[IdentityECDSA]) -> MerkleTree {
		let height = if identities.is_empty() {
			0
		} else {
			std::cmp::max(1, (identities.len() as f64).log2().ceil() as usize)
		};

		let mut tree = MerkleTree::new(height);

		for identity in identities {
			tree.add_leaf(identity.commitment());
		}

		tree
	}

	#[test]
	fn test_ecdsa_identity_commitment() {
		// Test that identity commitments are deterministic
		let identity1 = IdentityECDSA::new([42u8; 32]);
		let identity2 = IdentityECDSA::new([42u8; 32]);

		assert_eq!(
			identity1.commitment(),
			identity2.commitment(),
			"Same secret should produce same commitment"
		);

		// Different secrets produce different commitments
		let identity3 = IdentityECDSA::new([43u8; 32]);
		assert_ne!(
			identity1.commitment(),
			identity3.commitment(),
			"Different secrets should produce different commitments"
		);
	}

	#[test]
	fn test_ecdsa_nullifier_generation() {
		let identity = IdentityECDSA::new([1u8; 32]);

		// Same scope produces same nullifier
		let null1 = identity.nullifier(b"scope1");
		let null2 = identity.nullifier(b"scope1");
		assert_eq!(null1, null2, "Same scope should produce same nullifier");

		// Different scopes produce different nullifiers
		let null3 = identity.nullifier(b"scope2");
		assert_ne!(null1, null3, "Different scopes should produce different nullifiers");
	}

	#[test]
	fn test_ecdsa_circuit_structure() {
		// Test that the circuit builds correctly
		let builder = CircuitBuilder::new();
		let _circuit = SemaphoreProofECDSA::new(
			&builder, 2,  // tree height
			16, // message length
			16, // scope length
		);

		let compiled = builder.build();
		let cs = compiled.constraint_system();

		// Verify we have constraints (circuit is non-trivial)
		assert!(!cs.and_constraints.is_empty(), "Should have AND constraints");
		assert!(!cs.mul_constraints.is_empty(), "Should have MUL constraints from EC operations");

		// ECDSA should add significant MUL constraints
		assert!(
			cs.mul_constraints.len() > 1000,
			"ECDSA scalar multiplication should add many MUL constraints"
		);
	}

	#[test]
	fn test_ecdsa_constraint_scaling() {
		for tree_height in [1, 2, 4, 8, 12, 16] {
			let builder = CircuitBuilder::new();
			let _circuit = SemaphoreProofECDSA::new(
				&builder,
				tree_height,
				32, // message length
				16, // scope length
			);

			let compiled = builder.build();
			let cs = compiled.constraint_system();
			let total = cs.and_constraints.len() + cs.mul_constraints.len();

			// Verify constraints scale as expected
			assert!(total > 0, "Should have constraints");
			if tree_height > 1 {
				// Constraints should increase with tree height
				assert!(cs.and_constraints.len() > 1000, "Should have AND constraints for tree");
			}
		}
	}

	#[test]
	fn test_multiple_ecdsa_identities() {
		// Test with multiple ECDSA identities in a group
		let identities = vec![
			IdentityECDSA::new([1u8; 32]),
			IdentityECDSA::new([2u8; 32]),
			IdentityECDSA::new([3u8; 32]),
			IdentityECDSA::new([4u8; 32]),
		];

		let tree = create_tree_with_ecdsa_identities(&identities);

		// Verify all identities have unique commitments
		let commitments: Vec<_> = identities.iter().map(|id| id.commitment()).collect();

		for i in 0..commitments.len() {
			for j in i + 1..commitments.len() {
				assert_ne!(
					commitments[i], commitments[j],
					"Different identities should have different commitments"
				);
			}
		}

		// Verify tree was built correctly
		assert_eq!(tree.leaves.len(), 4, "Tree should have 4 members");
	}

	#[test]
	fn test_ecdsa_nullifier_properties() {
		let identity = IdentityECDSA::new([99u8; 32]);

		// Test nullifier determinism
		let scope = b"voting_2024";
		let null1 = identity.nullifier(scope);
		let null2 = identity.nullifier(scope);
		assert_eq!(null1, null2, "Nullifiers must be deterministic");

		// Test nullifier uniqueness across scopes
		let scopes: [&[u8]; 5] = [
			b"vote_1",
			b"vote_2",
			b"vote_3",
			b"proposal_A",
			b"proposal_B",
		];

		let nullifiers: Vec<_> = scopes.iter().map(|s| identity.nullifier(s)).collect();

		// All nullifiers should be unique
		for i in 0..nullifiers.len() {
			for j in i + 1..nullifiers.len() {
				assert_ne!(
					nullifiers[i], nullifiers[j],
					"Different scopes must produce different nullifiers"
				);
			}
		}
	}
}

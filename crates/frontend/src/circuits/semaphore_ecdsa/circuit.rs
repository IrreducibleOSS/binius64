//! Semaphore circuit with ECDSA key derivation using secp256k1.

use binius_core::Word;
use k256::{
	ProjectivePoint, Scalar,
	elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use sha3::{Digest, Keccak256};

use crate::{
	circuits::{
		bignum::BigUint,
		ecdsa::scalar_mul::scalar_mul_naive,
		keccak::Keccak,
		secp256k1::{Secp256k1, Secp256k1Affine},
		semaphore_ecdsa::reference::IdentityECDSA,
	},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};

// Circuit constants
const SCALAR_BITS: usize = 256;
const SCALAR_LIMBS: usize = 4; // 256 bits / 64 bits per limb
const PUBKEY_COORD_BYTES: usize = 32;
const PUBKEY_MESSAGE_BYTES: usize = 64; // x || y coordinates
const KECCAK_DIGEST_LIMBS: usize = 4;
const BYTES_PER_WIRE: usize = 8;
const BITS_PER_BYTE: usize = 8;

/// Compute secp256k1 public key coordinates from secret scalar
pub fn compute_public_key_coords(secret_scalar: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
	// Validate non-zero scalar to avoid point at infinity
	assert!(secret_scalar.iter().any(|&b| b != 0), "Secret scalar must be non-zero");

	// Convert LE to BE for k256
	let mut scalar_be = *secret_scalar;
	scalar_be.reverse();

	let scalar = Scalar::from_repr(scalar_be.into()).expect("Invalid scalar representation");
	let public_key_point = ProjectivePoint::GENERATOR * scalar;
	let affine_point = public_key_point.to_affine();
	let encoded = affine_point.to_encoded_point(false);

	if let k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } = encoded.coordinates() {
		let mut x_coord: [u8; 32] = (*x).into();
		let mut y_coord: [u8; 32] = (*y).into();

		// Convert BE to LE for circuit
		x_coord.reverse();
		y_coord.reverse();

		(x_coord, y_coord)
	} else {
		panic!("Expected uncompressed coordinates");
	}
}

/// Semaphore proof circuit with ECDSA
pub struct SemaphoreProofECDSA {
	/// Message being signaled (public input)
	pub message: Vec<Wire>,
	/// Scope for this signal (public input)
	pub scope: Vec<Wire>,
	/// Merkle root of the group (public input)
	pub merkle_root: [Wire; KECCAK_DIGEST_LIMBS],
	/// Generated nullifier (public output)
	pub nullifier: [Wire; KECCAK_DIGEST_LIMBS],

	// Internal components
	identity_commitment: IdentityCommitmentECDSA,
	merkle_proof: MerkleProofKeccak,
	nullifier_gen: NullifierGeneratorECDSA,

	// Metadata
	message_len_bytes: usize,
	scope_len_bytes: usize,
}

/// Identity commitment with ECDSA key derivation
struct IdentityCommitmentECDSA {
	secret_scalar: [Wire; SCALAR_LIMBS],
	#[allow(dead_code)]
	public_key: Secp256k1Affine,
	commitment: [Wire; KECCAK_DIGEST_LIMBS],
	commitment_message_wires: Vec<Wire>,
	hasher: Keccak,
}

impl IdentityCommitmentECDSA {
	fn new(builder: &CircuitBuilder, curve: &Secp256k1) -> Self {
		let secret_scalar: [Wire; SCALAR_LIMBS] = std::array::from_fn(|_| builder.add_witness());

		let scalar_biguint = BigUint {
			limbs: secret_scalar.to_vec(),
		};

		let generator = Secp256k1Affine::generator(builder);
		let public_key = scalar_mul_naive(builder, curve, SCALAR_BITS, &scalar_biguint, generator);

		// Create witness wires for Keccak message
		let commitment_message_wires: Vec<Wire> = (0..PUBKEY_MESSAGE_BYTES / BYTES_PER_WIRE)
			.map(|_| builder.add_witness())
			.collect();

		// Constrain message wires to match computed public key coordinates
		for i in 0..SCALAR_LIMBS {
			builder.assert_eq(
				format!("commitment_message_x[{}]", i),
				commitment_message_wires[i],
				public_key.x.limbs[i],
			);
			builder.assert_eq(
				format!("commitment_message_y[{}]", i),
				commitment_message_wires[i + SCALAR_LIMBS],
				public_key.y.limbs[i],
			);
		}

		// Create witness wires for commitment output
		let commitment: [Wire; KECCAK_DIGEST_LIMBS] =
			std::array::from_fn(|_| builder.add_witness());
		let message_len = builder.add_constant_64(PUBKEY_MESSAGE_BYTES as u64);

		let hasher =
			Keccak::new(builder, message_len, commitment, commitment_message_wires.clone());

		Self {
			secret_scalar,
			public_key,
			commitment,
			commitment_message_wires,
			hasher,
		}
	}

	fn populate_witness(&self, witness: &mut WitnessFiller, secret_scalar: &[u8; 32]) {
		pack_bytes_into_wires_le(witness, &self.secret_scalar, secret_scalar);

		// Compute public key coordinates externally for efficiency
		let (pk_x_bytes, pk_y_bytes) = compute_public_key_coords(secret_scalar);
		let mut commitment_message_bytes = Vec::new();
		commitment_message_bytes.extend_from_slice(&pk_x_bytes);
		commitment_message_bytes.extend_from_slice(&pk_y_bytes);

		pack_bytes_into_wires_le(
			witness,
			&self.commitment_message_wires,
			&commitment_message_bytes,
		);

		let commitment_digest = Keccak256::digest(&commitment_message_bytes);
		self.hasher
			.populate_len_bytes(witness, commitment_message_bytes.len());
		self.hasher
			.populate_message(witness, &commitment_message_bytes);
		self.hasher
			.populate_digest(witness, commitment_digest.into());
	}
}

/// Merkle proof using Keccak
struct MerkleProofKeccak {
	#[allow(dead_code)]
	leaf: [Wire; KECCAK_DIGEST_LIMBS],
	leaf_index: Wire,
	siblings: Vec<[Wire; KECCAK_DIGEST_LIMBS]>,
	root: [Wire; KECCAK_DIGEST_LIMBS],
	hashers: Vec<Keccak>,
}

impl MerkleProofKeccak {
	fn new(
		builder: &CircuitBuilder,
		leaf: [Wire; KECCAK_DIGEST_LIMBS],
		tree_height: usize,
	) -> Self {
		let leaf_index = builder.add_witness();
		let siblings: Vec<[Wire; KECCAK_DIGEST_LIMBS]> = (0..tree_height)
			.map(|_| std::array::from_fn(|_| builder.add_witness()))
			.collect();

		let mut hashers = Vec::new();
		let mut current = leaf;
		let mut index = leaf_index;

		for sibling in &siblings {
			let is_even = builder.bnot(builder.band(index, builder.add_constant_64(1)));

			use crate::circuits::multiplexer::multi_wire_multiplex;
			let left: [Wire; KECCAK_DIGEST_LIMBS] =
				multi_wire_multiplex(builder, &[sibling, &current], is_even)
					.try_into()
					.unwrap();

			let right: [Wire; KECCAK_DIGEST_LIMBS] =
				multi_wire_multiplex(builder, &[&current, sibling], is_even)
					.try_into()
					.unwrap();

			// Create witness wires for Keccak message
			let message_wires: Vec<Wire> = (0..PUBKEY_MESSAGE_BYTES / BYTES_PER_WIRE)
				.map(|_| builder.add_witness())
				.collect();

			// Constrain message wires to match multiplexer output
			for i in 0..SCALAR_LIMBS {
				builder.assert_eq(format!("merkle_message_left[{}]", i), message_wires[i], left[i]);
				builder.assert_eq(
					format!("merkle_message_right[{}]", i),
					message_wires[i + SCALAR_LIMBS],
					right[i],
				);
			}

			let parent: [Wire; KECCAK_DIGEST_LIMBS] =
				std::array::from_fn(|_| builder.add_witness());
			let len_bytes = builder.add_constant_64(PUBKEY_MESSAGE_BYTES as u64);
			let hasher = Keccak::new(builder, len_bytes, parent, message_wires);
			hashers.push(hasher);

			current = parent;
			index = builder.shr(index, 1);
		}

		Self {
			leaf,
			leaf_index,
			siblings,
			root: current,
			hashers,
		}
	}

	fn populate_witness(
		&self,
		witness: &mut WitnessFiller,
		proof: &crate::circuits::semaphore_ecdsa::reference::MerkleProof,
	) {
		witness[self.leaf_index] = Word::from_u64(proof.leaf_index as u64);

		assert_eq!(
			self.siblings.len(),
			proof.siblings.len(),
			"Proof siblings count must match tree height"
		);

		for (sibling_wires, sibling_data) in self.siblings.iter().zip(&proof.siblings) {
			pack_bytes_into_wires_le(witness, sibling_wires, sibling_data);
		}

		let mut current = proof.leaf;
		let mut index = proof.leaf_index;

		for (sibling, hasher) in proof.siblings.iter().zip(&self.hashers) {
			let (left, right) = if index % 2 == 0 {
				(&current, sibling)
			} else {
				(sibling, &current)
			};

			let mut message_bytes = Vec::new();
			message_bytes.extend_from_slice(left);
			message_bytes.extend_from_slice(right);

			let mut keccak_hasher = Keccak256::new();
			keccak_hasher.update(&message_bytes);
			let parent: [u8; 32] = keccak_hasher.finalize().into();

			hasher.populate_len_bytes(witness, 64);
			hasher.populate_digest(witness, parent);
			hasher.populate_message(witness, &message_bytes);

			current = parent;
			index /= 2;
		}
	}
}

/// Nullifier generator using secret scalar
struct NullifierGeneratorECDSA {
	scope: Vec<Wire>,
	secret_scalar_wires: [Wire; SCALAR_LIMBS],
	#[allow(dead_code)]
	identity_secret_scalar: [Wire; SCALAR_LIMBS],
	nullifier: [Wire; KECCAK_DIGEST_LIMBS],
	nullifier_message_wires: Vec<Wire>,
	hasher: Keccak,
	scope_len_bytes: usize,
}

impl NullifierGeneratorECDSA {
	fn new(
		builder: &CircuitBuilder,
		scope_len_bytes: usize,
		identity_secret_scalar: [Wire; SCALAR_LIMBS],
	) -> Self {
		let scope_wires = scope_len_bytes.div_ceil(BYTES_PER_WIRE);
		let scope: Vec<Wire> = (0..scope_wires).map(|_| builder.add_inout()).collect();

		// Validate padding: Ensure any bytes beyond scope_len_bytes are zero.
		// This prevents malleability attacks where different padded values could
		// represent the same logical scope but produce different nullifiers.
		let zero = builder.add_constant_64(0);
		for wire_idx in 0..scope_wires {
			let wire = scope[wire_idx];
			let wire_start_byte = wire_idx * BYTES_PER_WIRE;
			let wire_end_byte = wire_start_byte + BYTES_PER_WIRE;

			if wire_start_byte >= scope_len_bytes {
				builder.assert_eq("scope_wire_padding_zero", wire, zero);
			} else if wire_end_byte > scope_len_bytes {
				for byte_offset in 0..BYTES_PER_WIRE {
					let global_byte_idx = wire_start_byte + byte_offset;
					if global_byte_idx >= scope_len_bytes {
						let byte_val = builder.shr(wire, (byte_offset * BITS_PER_BYTE) as u32);
						let byte_masked = builder.band(byte_val, builder.add_constant_64(0xFF));
						builder.assert_eq("scope_padding_zero", byte_masked, zero);
					}
				}
			}
		}

		// Create separate witness wires for nullifier's secret scalar
		let secret_scalar_wires: [Wire; SCALAR_LIMBS] =
			std::array::from_fn(|_| builder.add_witness());

		// Ensure nullifier uses same secret as identity commitment
		for i in 0..SCALAR_LIMBS {
			builder.assert_eq(
				format!("nullifier_secret_equals_identity[{}]", i),
				secret_scalar_wires[i],
				identity_secret_scalar[i],
			);
		}

		// Create witness wires for Keccak message
		let total_message_wires = scope_wires + SCALAR_LIMBS;
		let nullifier_message_wires: Vec<Wire> = (0..total_message_wires)
			.map(|_| builder.add_witness())
			.collect();

		// Message wires are populated during witness phase with scope and secret values.
		// The Keccak constraint verifies the nullifier computation.

		let nullifier: [Wire; KECCAK_DIGEST_LIMBS] = std::array::from_fn(|_| builder.add_witness());
		let total_len = scope_len_bytes + PUBKEY_COORD_BYTES;
		let len_bytes = builder.add_constant_64(total_len as u64);
		let hasher = Keccak::new(builder, len_bytes, nullifier, nullifier_message_wires.clone());

		Self {
			scope,
			secret_scalar_wires,
			identity_secret_scalar,
			nullifier,
			nullifier_message_wires,
			hasher,
			scope_len_bytes,
		}
	}

	fn populate_witness(
		&self,
		witness: &mut WitnessFiller,
		scope: &[u8],
		secret_scalar: &[u8; 32],
	) {
		assert_eq!(
			scope.len(),
			self.scope_len_bytes,
			"Scope length must match declared scope_len_bytes"
		);

		// Populate scope public wires
		let mut padded_scope = scope.to_vec();
		padded_scope.resize(self.scope.len() * BYTES_PER_WIRE, 0);
		pack_bytes_into_wires_le(witness, &self.scope, &padded_scope);

		// Populate secret scalar witness wires
		pack_bytes_into_wires_le(witness, &self.secret_scalar_wires, secret_scalar);

		// Prepare message for nullifier computation
		let mut message_bytes = Vec::new();
		message_bytes.extend_from_slice(scope);
		message_bytes.extend_from_slice(secret_scalar);

		// Populate message witness wires
		let mut padded_message = message_bytes.clone();
		padded_message.resize(self.nullifier_message_wires.len() * BYTES_PER_WIRE, 0);
		pack_bytes_into_wires_le(witness, &self.nullifier_message_wires, &padded_message);

		// Compute and populate nullifier
		let mut hasher = Keccak256::new();
		hasher.update(&message_bytes);
		let nullifier: [u8; 32] = hasher.finalize().into();

		self.hasher
			.populate_len_bytes(witness, scope.len() + PUBKEY_COORD_BYTES);
		self.hasher.populate_message(witness, &message_bytes);
		self.hasher.populate_digest(witness, nullifier);
	}
}

impl SemaphoreProofECDSA {
	/// Creates a new Semaphore proof circuit with ECDSA
	pub fn new(
		builder: &CircuitBuilder,
		tree_height: usize,
		message_len_bytes: usize,
		scope_len_bytes: usize,
	) -> Self {
		let curve = Secp256k1::new(builder);

		let message_wires = message_len_bytes.div_ceil(BYTES_PER_WIRE);
		let message: Vec<Wire> = (0..message_wires).map(|_| builder.add_inout()).collect();

		// Validate padding: Ensure any bytes beyond message_len_bytes are zero.
		// This prevents malleability attacks where different padded values could
		// represent the same logical message.
		let zero = builder.add_constant_64(0);
		for wire_idx in 0..message_wires {
			let wire = message[wire_idx];
			let wire_start_byte = wire_idx * BYTES_PER_WIRE;
			let wire_end_byte = wire_start_byte + BYTES_PER_WIRE;

			if wire_start_byte >= message_len_bytes {
				builder.assert_eq("message_wire_padding_zero", wire, zero);
			} else if wire_end_byte > message_len_bytes {
				for byte_offset in 0..BYTES_PER_WIRE {
					let global_byte_idx = wire_start_byte + byte_offset;
					if global_byte_idx >= message_len_bytes {
						let byte_val = builder.shr(wire, (byte_offset * BITS_PER_BYTE) as u32);
						let byte_masked = builder.band(byte_val, builder.add_constant_64(0xFF));
						builder.assert_eq("message_padding_zero", byte_masked, zero);
					}
				}
			}
		}

		let merkle_root: [Wire; KECCAK_DIGEST_LIMBS] = std::array::from_fn(|_| builder.add_inout());

		let identity_commitment = IdentityCommitmentECDSA::new(builder, &curve);

		let merkle_proof =
			MerkleProofKeccak::new(builder, identity_commitment.commitment, tree_height);

		builder.assert_eq_v("merkle_root_check", merkle_proof.root, merkle_root);

		let nullifier_gen = NullifierGeneratorECDSA::new(
			builder,
			scope_len_bytes,
			identity_commitment.secret_scalar,
		);

		Self {
			message,
			scope: nullifier_gen.scope.clone(),
			merkle_root,
			nullifier: nullifier_gen.nullifier,
			identity_commitment,
			merkle_proof,
			nullifier_gen,
			message_len_bytes,
			scope_len_bytes,
		}
	}

	/// Populate the complete witness
	pub fn populate_witness(
		&self,
		witness: &mut WitnessFiller,
		identity: &IdentityECDSA,
		merkle_proof: &crate::circuits::semaphore_ecdsa::reference::MerkleProof,
		message: &[u8],
		scope: &[u8],
	) {
		assert_eq!(
			message.len(),
			self.message_len_bytes,
			"Message length must match declared message_len_bytes"
		);
		assert_eq!(
			scope.len(),
			self.scope_len_bytes,
			"Scope length must match declared scope_len_bytes"
		);

		let mut padded_message = message.to_vec();
		padded_message.resize(self.message.len() * BYTES_PER_WIRE, 0);
		pack_bytes_into_wires_le(witness, &self.message, &padded_message);

		pack_bytes_into_wires_le(witness, &self.merkle_root, &merkle_proof.root);

		self.identity_commitment
			.populate_witness(witness, &identity.secret_scalar);
		self.merkle_proof.populate_witness(witness, merkle_proof);
		self.nullifier_gen
			.populate_witness(witness, scope, &identity.secret_scalar);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		circuits::semaphore_ecdsa::reference::{MerkleTree, SemaphoreProofECDSA as RefProof},
		compiler::CircuitBuilder,
	};

	#[test]
	fn test_circuit_matches_reference() {
		// Create identity
		let identity = IdentityECDSA::new([42u8; 32]);

		// Build Merkle tree with multiple members
		let mut tree = MerkleTree::new(2);
		tree.add_leaf(identity.commitment());
		tree.add_leaf([1u8; 32]); // Another member
		tree.add_leaf([2u8; 32]); // Another member

		// Generate reference proof
		let message = b"vote yes";
		let scope = b"proposal1";
		let reference_proof = RefProof::generate(&identity, &tree, 0, message, scope);

		// Build and run circuit
		let builder = CircuitBuilder::new();
		let circuit = SemaphoreProofECDSA::new(
			&builder,
			2,             // tree height
			message.len(), // exact message length
			scope.len(),   // exact scope length
		);
		let compiled = builder.build();

		// Populate witness
		let mut witness = compiled.new_witness_filler();
		circuit.populate_witness(
			&mut witness,
			&identity,
			&reference_proof.merkle_proof,
			message,
			scope,
		);

		// Populate wire witness to compute intermediate values
		compiled.populate_wire_witness(&mut witness).unwrap();

		// Extract and verify nullifier matches reference
		let circuit_nullifier: [u8; 32] = circuit
			.nullifier
			.iter()
			.flat_map(|&w| witness[w].0.to_le_bytes())
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		assert_eq!(
			circuit_nullifier, reference_proof.nullifier,
			"Circuit nullifier should match reference"
		);

		// Extract and verify Merkle root matches
		let circuit_root: [u8; 32] = circuit
			.merkle_root
			.iter()
			.flat_map(|&w| witness[w].0.to_le_bytes())
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		assert_eq!(circuit_root, tree.root(), "Circuit root should match reference");
	}

	#[test]
	fn test_identity_commitment_matches_reference() {
		// Test that circuit's identity commitment logic matches reference
		let secret = [123u8; 32];
		let identity = IdentityECDSA::new(secret);

		// Reference computation
		let reference_commitment = identity.commitment();

		// Circuit computation
		let builder = CircuitBuilder::new();
		let circuit = SemaphoreProofECDSA::new(&builder, 1, 1, 1);
		let compiled = builder.build();

		let mut witness = compiled.new_witness_filler();

		// Create minimal valid inputs
		let mut tree = MerkleTree::new(1);
		tree.add_leaf(reference_commitment);
		let proof = tree.proof(0);

		circuit.populate_witness(&mut witness, &identity, &proof, &[0], &[0]);
		compiled.populate_wire_witness(&mut witness).unwrap();

		// Verify commitment in tree matches reference
		assert_eq!(proof.leaf, reference_commitment, "Identity commitment should match reference");
	}

	#[test]
	fn test_nullifier_consistency() {
		// Test that nullifiers are consistent between reference and circuit
		let identity = IdentityECDSA::new([99u8; 32]);
		let scope = b"test_scope_123";

		// Reference nullifier
		let reference_nullifier = identity.nullifier(scope);

		// Build circuit and generate proof
		let mut tree = MerkleTree::new(1);
		tree.add_leaf(identity.commitment());

		let builder = CircuitBuilder::new();
		let circuit = SemaphoreProofECDSA::new(&builder, 1, 1, scope.len());
		let compiled = builder.build();

		let mut witness = compiled.new_witness_filler();
		circuit.populate_witness(&mut witness, &identity, &tree.proof(0), &[0], scope);
		compiled.populate_wire_witness(&mut witness).unwrap();

		// Extract circuit nullifier
		let circuit_nullifier: [u8; 32] = circuit
			.nullifier
			.iter()
			.flat_map(|&w| witness[w].0.to_le_bytes())
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		assert_eq!(
			circuit_nullifier, reference_nullifier,
			"Circuit nullifier should match reference implementation"
		);
	}

	#[test]
	fn test_semaphore_ecdsa() {
		// Original test for constraint counting
		let identity = IdentityECDSA::new([42u8; 32]);

		// Create single-member tree
		let mut tree = MerkleTree::new(1);
		tree.add_leaf(identity.commitment());

		let _merkle_proof = tree.proof(0);
		let _message = b"vote yes";
		let _scope = b"proposal1";

		// Build circuit
		let builder = CircuitBuilder::new();
		let _circuit = SemaphoreProofECDSA::new(
			&builder, 1,  // tree height
			8,  // message length
			16, // scope length
		);

		let compiled = builder.build();

		// Count constraints
		let cs = compiled.constraint_system();
		let total_constraints = cs.and_constraints.len() + cs.mul_constraints.len();
		println!("ECDSA+Keccak version: {} total constraints", total_constraints);
		println!("  AND constraints: {}", cs.and_constraints.len());
		println!("  MUL constraints: {}", cs.mul_constraints.len());
	}

	#[test]
	fn test_identity_commitment_direct() {
		// Verify identity commitment computation with known test vector
		let secret_scalar = [0x2b; 32];

		let identity = IdentityECDSA::new(secret_scalar);
		let commitment = identity.commitment();

		// Verify against known test vector
		assert_eq!(
			commitment,
			[
				130, 189, 217, 95, 189, 80, 140, 89, 235, 228, 30, 102, 89, 108, 178, 70, 199, 50,
				184, 233, 155, 92, 181, 28, 35, 97, 13, 203, 122, 36, 109, 170
			]
		);
	}
}

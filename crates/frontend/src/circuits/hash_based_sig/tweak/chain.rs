use super::base::verify_tweaked_keccak;
use crate::{
	circuits::{concat::Term, keccak::Keccak},
	compiler::{CircuitBuilder, Wire},
};

pub const CHAIN_TWEAK: u8 = 0x00;

/// Fixed overhead in the message beyond the parameter length:
/// - 1 byte: tweak_byte
/// - 32 bytes: hash value
/// - 8 bytes: chain_index
/// - 8 bytes: position
pub const FIXED_MESSAGE_OVERHEAD: usize = 1 + 32 + 8 + 8;

/// A circuit that verifies a chain-tweaked Keccak-256 computation.
///
/// This circuit verifies Keccak-256 of a message that's been tweaked with
/// chain-specific parameters: `Keccak256(param || 0x00 || hash || chain_index || position)`
///
/// # Arguments
///
/// * `builder` - Circuit builder for constructing constraints
/// * `param_wires` - The cryptographic parameter wires, where each wire holds 8 bytes as a 64-bit
///   LE-packed value
/// * `param_len` - The actual parameter length in bytes
/// * `hash` - The hash value to be tweaked (32 bytes as 4x64-bit LE-packed wires)
/// * `chain_index` - Index of this chain (as 64-bit LE-packed value in wire)
/// * `position` - Position within the chain (as 64-bit LE-packed value in wire)
/// * `digest` - Output: The computed Keccak-256 digest (32 bytes as 4x64-bit LE-packed wires)
///
/// # Returns
///
/// A `Keccak` circuit that needs to be populated with the tweaked message and digest
pub fn verify_chain_tweak(
	builder: &CircuitBuilder,
	param_wires: Vec<Wire>,
	param_len: usize,
	hash: [Wire; 4],
	chain_index: Wire,
	position: Wire,
	digest: [Wire; 4],
) -> Keccak {
	let message_len = param_len + FIXED_MESSAGE_OVERHEAD;
	assert_eq!(param_wires.len(), param_len.div_ceil(8));

	// Build additional terms for hash, chain_index, and position
	let mut additional_terms = Vec::new();

	let hash_term = Term {
		len: builder.add_constant_64(32),
		data: hash.to_vec(),
		max_len: 32,
	};
	additional_terms.push(hash_term);

	let chain_index_term = Term {
		len: builder.add_constant_64(8),
		data: vec![chain_index],
		max_len: 8,
	};
	additional_terms.push(chain_index_term);

	let position_term = Term {
		len: builder.add_constant_64(8),
		data: vec![position],
		max_len: 8,
	};
	additional_terms.push(position_term);

	verify_tweaked_keccak(
		builder,
		param_wires,
		param_len,
		CHAIN_TWEAK,
		additional_terms,
		message_len,
		digest,
	)
}

/// Build the tweaked message from components.
///
/// Constructs the complete message for Keccak-256 hashing by concatenating:
/// `param || 0x00 || hash || chain_index || position`
///
/// This function is typically used when populating witness data for the
/// `verify_chain_tweak` circuit.
///
/// # Arguments
///
/// * `param_bytes` - The cryptographic parameter bytes
/// * `hash_bytes` - The 32-byte hash value to be tweaked
/// * `chain_index_value` - The chain index as a u64 (will be encoded as little-endian)
/// * `position_value` - The position within the chain as a u64 (will be encoded as little-endian)
///
/// # Returns
///
/// A vector containing the complete tweaked message ready for hashing
pub fn build_chain_tweak(
	param_bytes: &[u8],
	hash_bytes: &[u8; 32],
	chain_index_value: u64,
	position_value: u64,
) -> Vec<u8> {
	let mut message = Vec::new();
	message.extend_from_slice(param_bytes);
	message.push(CHAIN_TWEAK);
	message.extend_from_slice(hash_bytes);
	message.extend_from_slice(&chain_index_value.to_le_bytes());
	message.extend_from_slice(&position_value.to_le_bytes());
	message
}

#[cfg(test)]
mod tests {
	use binius_core::Word;
	use proptest::prelude::*;
	use sha3::{Digest, Keccak256};

	use super::*;
	use crate::{
		compiler::{CircuitBuilder, circuit::Circuit},
		constraint_verifier::verify_constraints,
		util::pack_bytes_into_wires_le,
	};

	/// Helper struct for ChainTweak testing
	struct ChainTestCircuit {
		circuit: Circuit,
		keccak: Keccak,
		param_wires: Vec<Wire>,
		param_len: usize,
		hash: [Wire; 4],
		chain_index: Wire,
		position: Wire,
	}

	impl ChainTestCircuit {
		fn new(param_len: usize) -> Self {
			let builder = CircuitBuilder::new();

			let hash: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());
			let chain_index = builder.add_inout();
			let position = builder.add_inout();
			let digest: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());

			let num_param_wires = param_len.div_ceil(8);
			let param_wires: Vec<Wire> =
				(0..num_param_wires).map(|_| builder.add_inout()).collect();

			let keccak = verify_chain_tweak(
				&builder,
				param_wires.clone(),
				param_len,
				hash,
				chain_index,
				position,
				digest,
			);

			let circuit = builder.build();

			Self {
				circuit,
				keccak,
				param_wires,
				param_len,
				hash,
				chain_index,
				position,
			}
		}

		/// Populate witness and verify constraints with given test data
		fn populate_and_verify(
			&self,
			param_bytes: &[u8],
			hash_bytes: &[u8; 32],
			chain_index_val: u64,
			position_val: u64,
			message: &[u8],
			digest: [u8; 32],
		) -> Result<(), Box<dyn std::error::Error>> {
			let mut w = self.circuit.new_witness_filler();

			// Populate param
			assert_eq!(param_bytes.len(), self.param_len);
			pack_bytes_into_wires_le(&mut w, &self.param_wires, param_bytes);

			// Populate hash, chain_index, position
			pack_bytes_into_wires_le(&mut w, &self.hash, hash_bytes);
			w[self.chain_index] = Word::from_u64(chain_index_val);
			w[self.position] = Word::from_u64(position_val);

			// Populate message for Keccak
			let expected_len = self.param_len + FIXED_MESSAGE_OVERHEAD;
			assert_eq!(
				message.len(),
				expected_len,
				"Message length {} doesn't match expected length {}",
				message.len(),
				expected_len
			);
			self.keccak.populate_message(&mut w, message);

			// Populate digest
			self.keccak.populate_digest(&mut w, digest);

			self.circuit.populate_wire_witness(&mut w)?;
			let cs = self.circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec())?;
			Ok(())
		}
	}

	#[test]
	fn test_chain_tweak_basic() {
		let test_circuit = ChainTestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message = build_chain_tweak(param_bytes, hash_bytes, chain_index_val, position_val);

		let expected_digest = Keccak256::digest(&message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				hash_bytes,
				chain_index_val,
				position_val,
				&message,
				expected_digest.into(),
			)
			.unwrap();
	}

	#[test]
	fn test_chain_tweak_with_18_byte_param() {
		// Test with 18-byte param as per SPEC_1 and SPEC_2
		let test_circuit = ChainTestCircuit::new(18);

		let param_bytes: &[u8; 18] = b"test_param_18bytes";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message = build_chain_tweak(param_bytes, hash_bytes, chain_index_val, position_val);

		let expected_digest = Keccak256::digest(&message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				hash_bytes,
				chain_index_val,
				position_val,
				&message,
				expected_digest.into(),
			)
			.unwrap();
	}

	#[test]
	fn test_chain_tweak_wrong_digest() {
		let test_circuit = ChainTestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message = build_chain_tweak(param_bytes, hash_bytes, chain_index_val, position_val);

		// Populate with WRONG digest - this should cause verification to fail
		let wrong_digest = [0u8; 32];

		let result = test_circuit.populate_and_verify(
			param_bytes,
			hash_bytes,
			chain_index_val,
			position_val,
			&message,
			wrong_digest,
		);

		assert!(result.is_err(), "Expected error for wrong digest");
	}

	#[test]
	fn test_chain_tweak_wrong_param() {
		let test_circuit = ChainTestCircuit::new(32);

		let correct_param_bytes = b"correct_parameter_32_bytes!!!!!!";
		let wrong_param_bytes = b"wrong___parameter_32_bytes!!!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		// Message built with correct param
		let message =
			build_chain_tweak(correct_param_bytes, hash_bytes, chain_index_val, position_val);

		let expected_digest = Keccak256::digest(&message);

		// Populate with WRONG param but correct digest
		let result = test_circuit.populate_and_verify(
			wrong_param_bytes,
			hash_bytes,
			chain_index_val,
			position_val,
			&message,
			expected_digest.into(),
		);

		assert!(result.is_err(), "Expected error for mismatched param");
	}

	#[test]
	fn test_chain_tweak_wrong_chain_index() {
		let test_circuit = ChainTestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let correct_chain_index = 123u64;
		let wrong_chain_index = 999u64;
		let position_val = 456u64;

		// Message built with correct chain_index
		let message = build_chain_tweak(param_bytes, hash_bytes, correct_chain_index, position_val);

		let expected_digest = Keccak256::digest(&message);

		// Populate with WRONG chain_index but correct digest
		let result = test_circuit.populate_and_verify(
			param_bytes,
			hash_bytes,
			wrong_chain_index,
			position_val,
			&message,
			expected_digest.into(),
		);

		assert!(result.is_err(), "Expected error for mismatched chain_index");
	}

	proptest! {
		#[test]
		fn test_chain_tweak_property_based(
			param_len in 1usize..=100,
			chain_index in 0u64..=1000,
			position in 0u64..=1000,
		) {
			use rand::SeedableRng;
			use rand::prelude::StdRng;

			let mut rng = StdRng::seed_from_u64(0);

			// Generate random param bytes
			let mut param_bytes = vec![0u8; param_len];
			rng.fill_bytes(&mut param_bytes);

			// Generate random hash
			let mut hash_bytes = [0u8; 32];
			rng.fill_bytes(&mut hash_bytes);

			// Create circuit
			let test_circuit = ChainTestCircuit::new(param_len);

			// Build message and compute digest
			let message = build_chain_tweak(
				&param_bytes,
				&hash_bytes,
				chain_index,
				position,
			);

			// Verify message structure
			prop_assert_eq!(message.len(), param_len + FIXED_MESSAGE_OVERHEAD);
			prop_assert_eq!(message[param_len], CHAIN_TWEAK);

			let expected_digest: [u8; 32] = Keccak256::digest(&message).into();

			// Verify circuit
			test_circuit
				.populate_and_verify(
					&param_bytes,
					&hash_bytes,
					chain_index,
					position,
					&message,
					expected_digest,
				)
				.unwrap();
		}
	}
}

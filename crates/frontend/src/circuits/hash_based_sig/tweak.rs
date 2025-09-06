use binius_core::Word;
use binius_core::verify::verify_constraints;

use crate::{
	circuits::{
		concat::{Concat, Term},
		keccak::Keccak,
	},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};

/// A circuit to verify chain-specific Keccak-256 tweaking for hash-based
/// signatures.
///
/// This circuit computes Keccak-256 of a message that's been tweaked with
/// chain-specific parameters: `Keccak256(param || 0x00 || hash || chain_index || position)`
pub struct ChainTweak {
	/// The Keccak-256 hasher that computes the final digest
	pub keccak: Keccak,
	/// The cryptographic parameter wires (padded to multiple of 8 bytes)
	pub param_wires: Vec<Wire>,
	/// The actual parameter length in bytes (before padding)
	pub param_len: usize,
	/// The hash value to be tweaked (32 bytes as 4x64-bit LE-packed wires)
	pub hash: [Wire; 4],
	/// Index of this chain (as 64-bit value in wire)
	pub chain_index: Wire,
	/// Position within the chain (as 64-bit value in wire)
	pub position: Wire,
	/// The tweaked Keccak-256 digest (32 bytes as 4x64-bit wires)
	pub digest: [Wire; 4],
}

/// Fixed overhead in the message beyond the parameter length:
/// - 1 byte: tweak_byte
/// - 32 bytes: hash value
/// - 8 bytes: chain_index
/// - 8 bytes: position
const FIXED_MESSAGE_OVERHEAD: usize = 1 + 32 + 8 + 8;

const CHAIN_TWEAK: u8 = 0x00;

impl ChainTweak {
	/// Creates a new chain-tweaked Keccak-256 circuit.
	///
	/// # Arguments
	///
	/// * `builder` - Circuit builder for constructing constraints
	/// * `param_wires` - The cryptographic parameter wires
	/// * `param_len` - The actual parameter length in bytes
	/// * `hash` - The hash value to be tweaked (32 bytes as 4x64-bit LE-packed wires)
	/// * `chain_index` - Index of this chain (as 64-bit value in wire)
	/// * `position` - Position within the chain (as 64-bit value in wire)
	/// * `digest` - Output: The computed Keccak-256 digest (32 bytes as 4x64-bit wires)
	///
	/// # Returns
	///
	/// A `ChainTweak` instance that verifies the tweaked hash.
	pub fn new(
		builder: &CircuitBuilder,
		param_wires: Vec<Wire>,
		param_len: usize,
		hash: [Wire; 4],
		chain_index: Wire,
		position: Wire,
		digest: [Wire; 4],
	) -> Self {
		let message_len = param_len + FIXED_MESSAGE_OVERHEAD;
		let tweak_byte = builder.add_constant_64(CHAIN_TWEAK as u64);
		assert_eq!(param_wires.len(), param_len.div_ceil(8));

		// Create the message wires for Keccak (LE-packed)
		let n_message_words = message_len.div_ceil(8);
		let message_le: Vec<Wire> = (0..n_message_words)
			.map(|_| builder.add_witness())
			.collect();
		let len_bytes = builder.add_witness();

		let keccak = Keccak::new(builder, len_bytes, digest, message_le.clone());

		let mut terms = Vec::new();

		let param_term = Term {
			len_bytes: builder.add_constant_64(param_len as u64),
			data: param_wires.clone(),
		};
		terms.push(param_term);

		let tweak_term = Term {
			len_bytes: builder.add_constant_64(1),
			data: vec![tweak_byte],
		};
		terms.push(tweak_term);

		let hash_term = Term {
			len_bytes: builder.add_constant_64(32),
			data: hash.to_vec(),
		};
		terms.push(hash_term);

		let chain_index_term = Term {
			len_bytes: builder.add_constant_64(8),
			data: vec![chain_index],
		};
		terms.push(chain_index_term);

		let position_term = Term {
			len_bytes: builder.add_constant_64(8),
			data: vec![position],
		};
		terms.push(position_term);

		// Create the concatenation circuit to verify message structure
		// message = param || tweak_byte || hash || chain_index || position
		let _message_structure_verifier = Concat::new(builder, len_bytes, message_le, terms);

		ChainTweak {
			keccak,
			param_wires,
			param_len,
			hash,
			chain_index,
			position,
			digest,
		}
	}

	/// Populate the parameter wires.
	pub fn populate_param(&self, w: &mut WitnessFiller, param_bytes: &[u8]) {
		assert_eq!(param_bytes.len(), self.param_len);
		pack_bytes_into_wires_le(w, &self.param_wires, param_bytes);
	}

	/// Populate the hash wires (32 bytes as 4x64-bit LE-packed).
	pub fn populate_hash(&self, w: &mut WitnessFiller, hash_bytes: &[u8; 32]) {
		for (i, bytes) in hash_bytes.chunks(8).enumerate() {
			let word = u64::from_le_bytes(bytes.try_into().unwrap());
			w[self.hash[i]] = Word::from_u64(word);
		}
	}

	/// Populate the chain index wire.
	pub fn populate_chain_index(&self, w: &mut WitnessFiller, chain_index: u64) {
		w[self.chain_index] = Word::from_u64(chain_index);
	}

	/// Populate the position wire.
	pub fn populate_position(&self, w: &mut WitnessFiller, position: u64) {
		w[self.position] = Word::from_u64(position);
	}

	/// Populate the message wires with the complete concatenated message.
	pub fn populate_message(&self, w: &mut WitnessFiller, message_bytes: &[u8]) {
		let expected_len_bytes = self.param_len + FIXED_MESSAGE_OVERHEAD;
		assert_eq!(
			message_bytes.len(),
			expected_len_bytes,
			"Message length {} doesn't match expected length {}",
			message_bytes.len(),
			expected_len_bytes
		);
		// this populates both the message wires (shared with Concat) and the
		// padded_message wires (Keccak-specific padding)
		self.keccak.populate_message(w, message_bytes);
		self.keccak.populate_len_bytes(w, expected_len_bytes);
	}

	/// Populate the digest wires.
	pub fn populate_digest(&self, w: &mut WitnessFiller, digest: [u8; 32]) {
		self.keccak.populate_digest(w, digest);
	}

	/// Build the tweaked message from components.
	pub fn build_message(
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
}

#[cfg(test)]
mod tests {
	use sha3::{Digest, Keccak256};

	use super::*;
	use crate::{
		compiler::{CircuitBuilder, circuit::Circuit},
		binius_core::verify::verify_constraints,
	};

	/// Helper struct to encapsulate test circuit setup
	struct TestCircuit {
		circuit: Circuit,
		tweaked_keccak: ChainTweak,
	}

	impl TestCircuit {
		/// Create a new test circuit with specified param length
		fn new(param_len: usize) -> Self {
			let builder = CircuitBuilder::new();

			let hash: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());
			let chain_index = builder.add_inout();
			let position = builder.add_inout();
			let digest: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());

			let num_param_wires = param_len.div_ceil(8);
			let param_wires: Vec<Wire> =
				(0..num_param_wires).map(|_| builder.add_inout()).collect();

			let tweaked_keccak = ChainTweak::new(
				&builder,
				param_wires,
				param_len,
				hash,
				chain_index,
				position,
				digest,
			);

			let circuit = builder.build();

			Self {
				circuit,
				tweaked_keccak,
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

			self.tweaked_keccak.populate_param(&mut w, param_bytes);
			self.tweaked_keccak.populate_hash(&mut w, hash_bytes);
			self.tweaked_keccak
				.populate_chain_index(&mut w, chain_index_val);
			self.tweaked_keccak.populate_position(&mut w, position_val);
			self.tweaked_keccak.populate_message(&mut w, message);
			self.tweaked_keccak.populate_digest(&mut w, digest);

			self.circuit.populate_wire_witness(&mut w)?;
			let cs = self.circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec())?;
			Ok(())
		}
	}

	#[test]
	fn test_chain_tweak_basic() {
		let test_circuit = TestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message =
			ChainTweak::build_message(param_bytes, hash_bytes, chain_index_val, position_val);

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
		let test_circuit = TestCircuit::new(18);

		let param_bytes: &[u8; 18] = b"test_param_18bytes";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message =
			ChainTweak::build_message(param_bytes, hash_bytes, chain_index_val, position_val);

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
		let test_circuit = TestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		let message =
			ChainTweak::build_message(param_bytes, hash_bytes, chain_index_val, position_val);

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
		let test_circuit = TestCircuit::new(32);

		let correct_param_bytes = b"correct_parameter_32_bytes!!!!!!";
		let wrong_param_bytes = b"wrong___parameter_32_bytes!!!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let chain_index_val = 123u64;
		let position_val = 456u64;

		// Message built with correct param
		let message = ChainTweak::build_message(
			correct_param_bytes,
			hash_bytes,
			chain_index_val,
			position_val,
		);

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
		let test_circuit = TestCircuit::new(32);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let hash_bytes = b"hash_value_32_bytes_long!!!!!!!!";
		let correct_chain_index = 123u64;
		let wrong_chain_index = 999u64;
		let position_val = 456u64;

		// Message built with correct chain_index
		let message =
			ChainTweak::build_message(param_bytes, hash_bytes, correct_chain_index, position_val);

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
}

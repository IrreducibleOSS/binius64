use super::base::verify_tweaked_keccak;
use crate::{
	circuits::{concat::Term, keccak::Keccak},
	compiler::{CircuitBuilder, Wire},
};

pub const MESSAGE_TWEAK: u8 = 0x02;

/// A circuit that verifies a message-tweaked Keccak-256 computation.
///
/// This circuit verifies Keccak-256 of a message that's been tweaked with
/// message-specific parameters: `Keccak256(param || 0x02 || nonce || message)`
///
/// # Arguments
///
/// * `builder` - Circuit builder for constructing constraints
/// * `param_wires` - The cryptographic parameter wires (typically public key material), where each
///   wire holds 8 bytes as a 64-bit LE-packed value
/// * `param_len` - The actual parameter length in bytes
/// * `nonce_wires` - Random nonce wires to ensure uniqueness, where each wire holds 8 bytes as a
///   64-bit LE-packed value
/// * `nonce_len` - The actual nonce length in bytes
/// * `message_wires` - The message content wires, where each wire holds 8 bytes as a 64-bit
///   LE-packed value
/// * `message_len` - The actual message length in bytes
/// * `digest` - Output: The computed Keccak-256 digest (32 bytes as 4x64-bit LE-packed wires)
///
/// # Returns
///
/// A `Keccak` circuit that needs to be populated with the tweaked message and digest
#[allow(clippy::too_many_arguments)]
pub fn verify_message_tweak(
	builder: &CircuitBuilder,
	param_wires: Vec<Wire>,
	param_len: usize,
	nonce_wires: Vec<Wire>,
	nonce_len: usize,
	message_wires: Vec<Wire>,
	message_len: usize,
	digest: [Wire; 4],
) -> Keccak {
	let total_message_len = param_len + 1 + nonce_len + message_len; // +1 for tweak byte

	let mut additional_terms = Vec::new();

	let nonce_term = Term {
		len: builder.add_constant_64(nonce_len as u64),
		data: nonce_wires.clone(),
		max_len: nonce_wires.len() * 8,
	};
	additional_terms.push(nonce_term);

	let message_term = Term {
		len: builder.add_constant_64(message_len as u64),
		data: message_wires.clone(),
		max_len: message_wires.len() * 8,
	};
	additional_terms.push(message_term);

	verify_tweaked_keccak(
		builder,
		param_wires,
		param_len,
		MESSAGE_TWEAK,
		additional_terms,
		total_message_len,
		digest,
	)
}

/// Build the tweaked message from components.
///
/// Constructs the complete message for Keccak-256 hashing by concatenating:
/// `param || 0x02 || nonce || message`
///
/// This function is typically used when populating witness data for the
/// `verify_message_tweak` circuit.
///
/// # Arguments
///
/// * `param_bytes` - The cryptographic parameter bytes
/// * `nonce_bytes` - The random nonce bytes
/// * `message_bytes` - The message content bytes
///
/// # Returns
///
/// A vector containing the complete tweaked message ready for hashing
pub fn build_message_tweak(
	param_bytes: &[u8],
	nonce_bytes: &[u8],
	message_bytes: &[u8],
) -> Vec<u8> {
	let mut message = Vec::new();
	message.extend_from_slice(param_bytes);
	message.push(MESSAGE_TWEAK); // TWEAK_MESSAGE
	message.extend_from_slice(nonce_bytes);
	message.extend_from_slice(message_bytes);
	message
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;
	use sha3::{Digest, Keccak256};

	use super::*;
	use crate::{
		compiler::{CircuitBuilder, circuit::Circuit},
		constraint_verifier::verify_constraints,
		util::{pack_bytes_into_wires_le, pack_bytes_into_wires_le_padded},
	};

	/// Helper struct for MessageTweak testing
	struct MessageTestCircuit {
		circuit: Circuit,
		keccak: Keccak,
		param_wires: Vec<Wire>,
		param_len: usize,
		nonce_wires: Vec<Wire>,
		nonce_len: usize,
		message_wires: Vec<Wire>,
		message_len: usize,
	}

	impl MessageTestCircuit {
		fn new(param_len: usize, nonce_len: usize, message_len: usize) -> Self {
			let builder = CircuitBuilder::new();

			let num_param_wires = param_len.div_ceil(8);
			let param_wires: Vec<Wire> =
				(0..num_param_wires).map(|_| builder.add_inout()).collect();

			let num_nonce_wires = nonce_len.div_ceil(8);
			let nonce_wires: Vec<Wire> = (0..num_nonce_wires)
				.map(|_| builder.add_witness())
				.collect();

			let num_message_wires = message_len.div_ceil(8);
			let message_wires: Vec<Wire> = (0..num_message_wires)
				.map(|_| builder.add_witness())
				.collect();

			let digest: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());

			let keccak = verify_message_tweak(
				&builder,
				param_wires.clone(),
				param_len,
				nonce_wires.clone(),
				nonce_len,
				message_wires.clone(),
				message_len,
				digest,
			);

			let circuit = builder.build();

			Self {
				circuit,
				keccak,
				param_wires,
				param_len,
				nonce_wires,
				nonce_len,
				message_wires,
				message_len,
			}
		}

		/// Populate witness and verify constraints with given test data
		fn populate_and_verify(
			&self,
			param_bytes: &[u8],
			nonce_bytes: &[u8],
			message_bytes: &[u8],
			full_message: &[u8],
			digest: [u8; 32],
		) -> Result<(), Box<dyn std::error::Error>> {
			let mut w = self.circuit.new_witness_filler();

			assert_eq!(param_bytes.len(), self.param_len);
			pack_bytes_into_wires_le(&mut w, &self.param_wires, param_bytes);

			assert_eq!(nonce_bytes.len(), self.nonce_len);
			pack_bytes_into_wires_le_padded(&mut w, &self.nonce_wires, nonce_bytes);

			assert_eq!(message_bytes.len(), self.message_len);
			pack_bytes_into_wires_le_padded(&mut w, &self.message_wires, message_bytes);

			self.keccak.populate_message(&mut w, full_message);
			self.keccak.populate_digest(&mut w, digest);

			self.circuit.populate_wire_witness(&mut w)?;
			let cs = self.circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec())?;
			Ok(())
		}
	}

	#[test]
	fn test_message_tweak_basic() {
		let test_circuit = MessageTestCircuit::new(32, 16, 64);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let nonce_bytes = b"random_nonce_16b";
		let message_bytes = b"This is a test message that is exactly 64 bytes long!!!!!!!!!!!."; // 64 bytes

		let full_message = build_message_tweak(param_bytes, nonce_bytes, message_bytes);

		let expected_digest = Keccak256::digest(&full_message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				nonce_bytes,
				message_bytes,
				&full_message,
				expected_digest.into(),
			)
			.unwrap();
	}

	#[test]
	fn test_message_tweak_with_18_byte_param() {
		// Test with 18-byte param as commonly used in XMSS
		let test_circuit = MessageTestCircuit::new(18, 8, 32);

		let param_bytes: &[u8; 18] = b"test_param_18bytes";
		let nonce_bytes = b"nonce_8b";
		let message_bytes = b"message_that_is_32_bytes_long!!!";

		let full_message = build_message_tweak(param_bytes, nonce_bytes, message_bytes);

		let expected_digest = Keccak256::digest(&full_message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				nonce_bytes,
				message_bytes,
				&full_message,
				expected_digest.into(),
			)
			.unwrap();
	}

	#[test]
	fn test_message_tweak_variable_lengths() {
		// Test with various non-aligned lengths
		let test_circuit = MessageTestCircuit::new(13, 7, 29);

		let param_bytes = b"param_13bytes";
		let nonce_bytes = b"nonce7b";
		let message_bytes = b"msg_that_is_29_bytes_long!!!!";

		let full_message = build_message_tweak(param_bytes, nonce_bytes, message_bytes);

		let expected_digest = Keccak256::digest(&full_message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				nonce_bytes,
				message_bytes,
				&full_message,
				expected_digest.into(),
			)
			.unwrap();
	}

	#[test]
	fn test_message_tweak_wrong_digest() {
		let test_circuit = MessageTestCircuit::new(32, 16, 64);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let nonce_bytes = b"random_nonce_16b";
		let message_bytes = b"This is a test message that is exactly 64 bytes long!!!!!!!!!!!."; // 64 bytes

		let full_message = build_message_tweak(param_bytes, nonce_bytes, message_bytes);

		// Populate with WRONG digest - this should cause verification to fail
		let wrong_digest = [0u8; 32];

		let result = test_circuit.populate_and_verify(
			param_bytes,
			nonce_bytes,
			message_bytes,
			&full_message,
			wrong_digest,
		);

		assert!(result.is_err(), "Expected error for wrong digest");
	}

	#[test]
	fn test_message_tweak_wrong_param() {
		let test_circuit = MessageTestCircuit::new(32, 16, 64);

		let correct_param_bytes = b"correct_parameter_32_bytes!!!!!!";
		let wrong_param_bytes = b"wrong___parameter_32_bytes!!!!!!";
		let nonce_bytes = b"random_nonce_16b";
		let message_bytes = b"This is a test message that is exactly 64 bytes long!!!!!!!!!!!."; // 64 bytes

		// Build message with correct param
		let full_message = build_message_tweak(correct_param_bytes, nonce_bytes, message_bytes);

		let expected_digest = Keccak256::digest(&full_message);

		// Populate with WRONG param but correct digest
		let result = test_circuit.populate_and_verify(
			wrong_param_bytes,
			nonce_bytes,
			message_bytes,
			&full_message,
			expected_digest.into(),
		);

		assert!(result.is_err(), "Expected error for mismatched param");
	}

	#[test]
	fn test_message_tweak_wrong_nonce() {
		let test_circuit = MessageTestCircuit::new(32, 16, 64);

		let param_bytes = b"test_parameter_32_bytes_long!!!!";
		let correct_nonce = b"correct_nonce16b";
		let wrong_nonce = b"wrong___nonce16b";
		let message_bytes = b"This is a test message that is exactly 64 bytes long!!!!!!!!!!!."; // 64 bytes

		// Build message with correct nonce
		let full_message = build_message_tweak(param_bytes, correct_nonce, message_bytes);

		let expected_digest = Keccak256::digest(&full_message);

		// Populate with WRONG nonce but correct digest
		let result = test_circuit.populate_and_verify(
			param_bytes,
			wrong_nonce,
			message_bytes,
			&full_message,
			expected_digest.into(),
		);

		assert!(result.is_err(), "Expected error for mismatched nonce");
	}

	#[test]
	fn test_message_tweak_ensures_tweak_byte() {
		// This test verifies that the MESSAGE_TWEAK byte (0x02) is correctly inserted
		let test_circuit = MessageTestCircuit::new(8, 8, 16);

		let param_bytes = b"param_8b";
		let nonce_bytes = b"nonce_8b";
		let message_bytes = b"message_16_bytes";

		let full_message = build_message_tweak(param_bytes, nonce_bytes, message_bytes);

		// Verify the tweak byte is at the correct position
		assert_eq!(full_message[8], MESSAGE_TWEAK);
		assert_eq!(full_message.len(), 8 + 1 + 8 + 16); // param + tweak + nonce + message

		let expected_digest = Keccak256::digest(&full_message);

		test_circuit
			.populate_and_verify(
				param_bytes,
				nonce_bytes,
				message_bytes,
				&full_message,
				expected_digest.into(),
			)
			.unwrap();
	}

	proptest! {
		#[test]
		fn test_message_tweak_property_based(
			param_len in 1usize..=100,
			nonce_len in 1usize..=50,
			message_len in 1usize..=200,
		) {
			use rand::SeedableRng;
			use rand::prelude::StdRng;

			let mut rng = StdRng::seed_from_u64(0);

			// Generate random data of specified lengths
			let mut param_bytes = vec![0u8; param_len];
			rng.fill_bytes(&mut param_bytes);

			let mut nonce_bytes = vec![0u8; nonce_len];
			rng.fill_bytes(&mut nonce_bytes);

			let mut message_bytes = vec![0u8; message_len];
			rng.fill_bytes(&mut message_bytes);

			// Create circuit
			let test_circuit = MessageTestCircuit::new(param_len, nonce_len, message_len);

			// Build full message and compute digest
			let full_message =
				build_message_tweak(&param_bytes, &nonce_bytes, &message_bytes);

			// Verify message structure
			prop_assert_eq!(full_message.len(), param_len + 1 + nonce_len + message_len);
			prop_assert_eq!(full_message[param_len], MESSAGE_TWEAK);

			let expected_digest: [u8; 32] = Keccak256::digest(&full_message).into();

			// Verify circuit
			test_circuit
				.populate_and_verify(
					&param_bytes,
					&nonce_bytes,
					&message_bytes,
					&full_message,
					expected_digest,
				)
				.unwrap();
		}
	}
}

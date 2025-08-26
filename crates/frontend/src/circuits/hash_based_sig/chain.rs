use binius_core::Word;

use super::tweak::verify_chain_tweak;
use crate::{
	circuits::{keccak::Keccak, multiplexer::multi_wire_multiplex},
	compiler::{CircuitBuilder, Wire},
};

/// Verifies a hash chain for hash-based signature schemes using Keccak-256.
///
/// This function iteratively hashes a signature chunk a specified number of times
/// and verifies that the final result matches an expected end hash.
///
/// # Hash Chain Structure
///
/// A hash chain is a sequence of values where each value is computed by hashing the previous one:
/// ```text
/// start → H(start) → H(H(start)) → ... → end
/// ```
///
/// # Circuit Operation
///
/// The circuit performs `coordinate` iterations of hashing, where each iteration:
/// 1. Takes the current hash value
/// 2. Applies Keccak-256 with appropriate tweaking parameters
/// 3. Uses the result as input for the next iteration
///
/// After all iterations, it verifies the final hash equals `end_hash`.
///
/// # Arguments
///
/// * `builder` - Circuit builder for constructing constraints
/// * `param` - Cryptographic parameter as 64-bit packed wires (LE format)
/// * `param_len` - Actual byte length of the parameter (must be less than or equal to param.len() *
///   8)
/// * `chain_index` - Index of this chain in the signature structure
/// * `signature_chunk` - Starting hash value (32 bytes as 4x64-bit LE wires)
/// * `coordinate` - Number of hash iterations to perform (from codeword)
/// * `max_chain_len` - Maximum chain length
/// * `end_hash` - Expected final hash value (32 bytes as 4x64-bit LE wires)
///
/// # Returns
///
/// A vector of `Keccak` hashers that need to be populated with witness values.
/// The number of hashers equals the maximum chain length supported.
#[allow(clippy::too_many_arguments)]
pub fn verify_chain(
	builder: &CircuitBuilder,
	param: &[Wire],
	param_len: usize,
	chain_index: Wire,
	signature_chunk: [Wire; 4],
	coordinate: Wire,
	max_chain_len: u64,
	end_hash: [Wire; 4],
) -> Vec<Keccak> {
	assert!(
		param_len <= param.len() * 8,
		"param_len {} exceeds maximum capacity {} of param wires",
		param_len,
		param.len() * 8
	);
	let mut hashers = Vec::with_capacity(max_chain_len as usize);
	let mut current_hash = signature_chunk;

	let one = builder.add_constant(Word::ONE);
	let zero = builder.add_constant(Word::ZERO);
	let max_chain_len_wire = builder.add_constant_64(max_chain_len);

	// Build the hash chain
	for step in 0..max_chain_len {
		let step_wire = builder.add_constant_64(step);
		let (position, _) = builder.iadd_cin_cout(step_wire, coordinate, zero);
		let (position_plus_one, _) = builder.iadd_cin_cout(position, one, zero);

		let next_hash = std::array::from_fn(|_| builder.add_witness());
		let keccak = verify_chain_tweak(
			builder,
			param.to_vec(),
			param_len,
			current_hash,
			chain_index,
			position_plus_one,
			next_hash,
		);

		hashers.push(keccak);

		// Conditionally select the hash based on whether position + 1 < max_chain_len
		// If position + 1 < max_chain_len, use next_hash, otherwise keep current_hash
		let position_lt_max_chain_len = builder.icmp_ult(position_plus_one, max_chain_len_wire);
		current_hash =
			multi_wire_multiplex(builder, &[&current_hash, &next_hash], position_lt_max_chain_len)
				.try_into()
				.expect("multi_wire_multiplex should return 4 wires");
	}

	// Assert that the final hash matches the expected end_hash
	builder.assert_eq_v("hash_chain_end_check", current_hash, end_hash);
	hashers
}

#[cfg(test)]
mod tests {
	use binius_core::Word;
	use proptest::{prelude::*, strategy::Just};
	use sha3::{Digest, Keccak256};

	use super::{super::tweak::build_chain_tweak, *};
	use crate::{constraint_verifier::verify_constraints, util::pack_bytes_into_wires_le};

	proptest! {
		#[test]
		fn test_verify_chain(
			(coordinate_val, max_chain_len) in (0u64..10).prop_flat_map(|coord| {
				// max_chain_len must be > coordinate_val for any hashing to occur
				// Generate max_chain_len in range [coord + 1, coord + 8]
				(Just(coord), (coord + 1)..=(coord + 8))
			}),
			chain_index_val in 0u64..100,
			param_bytes in prop::collection::vec(any::<u8>(), 1..120), // Variable length param (1-119 bytes)
			signature_chunk_bytes in prop::array::uniform32(any::<u8>()),
		) {
			let builder = CircuitBuilder::new();

			let param_wire_count = param_bytes.len().div_ceil(8);
			let param: Vec<Wire> = (0..param_wire_count).map(|_| builder.add_inout()).collect();
			let chain_index = builder.add_inout();
			let signature_chunk: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());
			let coordinate = builder.add_inout();
			let end_hash: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());

			let hashers = verify_chain(
				&builder,
				&param,
				param_bytes.len(),
				chain_index,
				signature_chunk,
				coordinate,
				max_chain_len,
				end_hash,
			);

			let circuit = builder.build();
			let mut w = circuit.new_witness_filler();

			w[chain_index] = Word::from_u64(chain_index_val);
			w[coordinate] = Word::from_u64(coordinate_val);

			// Populate param wires (they're reused for all hashers)
			pack_bytes_into_wires_le(&mut w, &param, &param_bytes);

			// Track current hash through the chain
			let mut current_hash: [u8; 32] = signature_chunk_bytes;

			for (step, keccak) in hashers.iter().enumerate() {
				// Calculate position for this step
				let position = step as u64 + coordinate_val;
				let position_plus_one = position + 1;

				// Build the message for this hash using current_hash
				let message = build_chain_tweak(
					&param_bytes,
					&current_hash,
					chain_index_val,
					position_plus_one,
				);

				// Populate the Keccak circuit
				keccak.populate_message(&mut w, &message);

				// Compute the hash
				let digest: [u8; 32] = Keccak256::digest(&message).into();
				keccak.populate_digest(&mut w, digest);

				// Update current_hash for next iteration if this hash is selected
				// The multiplexer in the circuit selects next_hash when position_plus_one < max_chain_len
				if position_plus_one < max_chain_len {
					current_hash = digest;
				}
			}

			pack_bytes_into_wires_le(&mut w, &end_hash, &current_hash);
			pack_bytes_into_wires_le(&mut w, &signature_chunk, &signature_chunk_bytes);
			circuit.populate_wire_witness(&mut w).unwrap();

			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}
}

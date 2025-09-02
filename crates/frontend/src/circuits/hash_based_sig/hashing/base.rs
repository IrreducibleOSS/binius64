use crate::{
	circuits::{
		concat::{Concat, Term},
		keccak::Keccak,
	},
	compiler::{CircuitBuilder, Wire},
};

/// Verify a tweaked Keccak-256 circuit with custom terms.
///
/// This function provides the common setup for both message and chain tweaking,
/// which both follow the pattern: `Keccak256(domain_param || tweak_byte || additional_data)`
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `domain_param_wires` - The cryptographic domain parameter wires
/// * `domain_param_len` - The actual domain parameter length in bytes
/// * `tweak_byte` - The tweak byte value (MESSAGE_TWEAK or CHAIN_TWEAK)
/// * `additional_terms` - Additional concatenation terms after param and tweak
/// * `total_message_len` - Total length of the concatenated message
/// * `digest` - Output digest wires
///
/// # Returns
/// A `Keccak` instance that computes the tweaked hash
pub(super) fn circuit_tweaked_keccak(
	builder: &CircuitBuilder,
	domain_param_wires: Vec<Wire>,
	domain_param_len: usize,
	tweak_byte: u8,
	additional_terms: Vec<Term>,
	total_message_len: usize,
	digest: [Wire; 4],
) -> Keccak {
	// Create the message wires for Keccak (LE-packed)
	let n_message_words = total_message_len.div_ceil(8);
	let message_le: Vec<Wire> = (0..n_message_words)
		.map(|_| builder.add_witness())
		.collect();
	let len = builder.add_constant_64(total_message_len as u64);

	let keccak = Keccak::new(builder, len, digest, message_le.clone());

	let mut terms = Vec::new();
	let domain_param_term = Term {
		len_bytes: builder.add_constant_64(domain_param_len as u64),
		data: domain_param_wires,
	};
	terms.push(domain_param_term);

	let tweak_wire = builder.add_constant_64(tweak_byte as u64);
	let tweak_term = Term {
		len_bytes: builder.add_constant_64(1),
		data: vec![tweak_wire],
	};
	terms.push(tweak_term);
	terms.extend(additional_terms);

	let _message_structure_verifier = Concat::new(builder, len, message_le, terms);
	keccak
}

/// Verify a tweaked Keccak-256 circuit using the build_circuit API.
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `domain_param_len` - The actual domain parameter length in bytes
/// * `tweak_byte` - The tweak byte value (MESSAGE_TWEAK or CHAIN_TWEAK)
/// * `total_message_len` - Total length of the concatenated message
/// * `domain_param_wires` - The cryptographic domain parameter wires
/// * `additional_terms` - Additional concatenation terms after param and tweak
/// * `digest` - Output digest wires
/// * `message_le` - Message wires (LE-packed, must have capacity for total_message_len)
/// * `padded_message` - Padded message wires (must be sized for Keccak padding requirements)
#[allow(dead_code)]
pub(super) fn circuit_build_tweaked_keccak(
	builder: &CircuitBuilder,
	domain_param_len: usize,
	tweak_byte: u8,
	total_message_len: usize,
	domain_param_wires: Vec<Wire>,
	additional_terms: Vec<Term>,
	digest: [Wire; 4],
	message_le: &[Wire],
	padded_message: &[Wire],
) {
	let len = builder.add_constant_64(total_message_len as u64);

	Keccak::build_circuit(builder, len, digest, message_le, padded_message);

	let mut terms = Vec::new();
	let domain_param_term = Term {
		len_bytes: builder.add_constant_64(domain_param_len as u64),
		data: domain_param_wires,
	};
	terms.push(domain_param_term);

	let tweak_wire = builder.add_constant_64(tweak_byte as u64);
	let tweak_term = Term {
		len_bytes: builder.add_constant_64(1),
		data: vec![tweak_wire],
	};
	terms.push(tweak_term);
	terms.extend(additional_terms);

	let _message_structure_verifier = Concat::new(builder, len, message_le.to_vec(), terms);
}

#[cfg(test)]
mod tests {
	use sha3::{Digest, Keccak256};

	use super::*;
	use crate::{
		circuits::keccak::{N_WORDS_PER_BLOCK, RATE_BYTES, populate_message_and_padded},
		constraint_verifier::verify_constraints,
		util::pack_bytes_into_wires_le,
	};

	/// Test the circuit_tweaked_keccak_build_only function with additional data
	#[test]
	fn test_tweaked_keccak_build_only() {
		let domain_param = b"test_domain";
		let tweak_byte = 0x42u8;
		let additional_data = b"additional_test_data";
		let total_len = domain_param.len() + 1 + additional_data.len();

		let builder = CircuitBuilder::new();

		// Create domain param wires
		let domain_param_wires: Vec<Wire> = (0..domain_param.len().div_ceil(8))
			.map(|_| builder.add_witness())
			.collect();

		// Create additional term
		let additional_data_wires: Vec<Wire> = (0..additional_data.len().div_ceil(8))
			.map(|_| builder.add_witness())
			.collect();
		let additional_term = Term {
			len_bytes: builder.add_constant_64(additional_data.len() as u64),
			data: additional_data_wires.clone(),
		};

		let digest: [Wire; 4] = std::array::from_fn(|_| builder.add_inout());

		// Create message and padded_message wires
		let n_message_words = total_len.div_ceil(8);
		let message_wires: Vec<Wire> = (0..n_message_words)
			.map(|_| builder.add_witness())
			.collect();

		// Calculate number of blocks for padded_message
		let max_len_bytes = n_message_words * 8;
		let n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES);
		let padded_wires: Vec<Wire> = (0..n_blocks * N_WORDS_PER_BLOCK)
			.map(|_| builder.add_witness())
			.collect();

		circuit_build_tweaked_keccak(
			&builder,
			domain_param.len(),
			tweak_byte,
			total_len,
			domain_param_wires.clone(),
			vec![additional_term],
			digest,
			&message_wires,
			&padded_wires,
		);

		let circuit = builder.build();
		let mut w = circuit.new_witness_filler();

		pack_bytes_into_wires_le(&mut w, &domain_param_wires, domain_param);
		pack_bytes_into_wires_le(&mut w, &additional_data_wires, additional_data);

		let mut hasher = Keccak256::new();
		hasher.update(domain_param);
		hasher.update(&[tweak_byte]);
		hasher.update(additional_data);
		let expected_digest: [u8; 32] = hasher.finalize().into();

		let mut full_message = Vec::new();
		full_message.extend_from_slice(domain_param);
		full_message.push(tweak_byte);
		full_message.extend_from_slice(additional_data);
		populate_message_and_padded(
			&mut w,
			&full_message,
			&message_wires,
			&padded_wires,
			max_len_bytes,
			n_blocks,
		);

		pack_bytes_into_wires_le(&mut w, &digest, &expected_digest);

		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}
}

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
/// which both follow the pattern: `Keccak256(param || tweak_byte || additional_data)`
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `param_wires` - The cryptographic parameter wires
/// * `param_len` - The actual parameter length in bytes
/// * `tweak_byte` - The tweak byte value (MESSAGE_TWEAK or CHAIN_TWEAK)
/// * `additional_terms` - Additional concatenation terms after param and tweak
/// * `total_message_len` - Total length of the concatenated message
/// * `digest` - Output digest wires
///
/// # Returns
/// A `Keccak` instance that computes the tweaked hash
pub(super) fn verify_tweaked_keccak(
	builder: &CircuitBuilder,
	param_wires: Vec<Wire>,
	param_len: usize,
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

	// Keccak digest is 25 words (full state), but we only use first 4 for 256-bit output
	let keccak_digest: [Wire; 25] = std::array::from_fn(|i| {
		if i < 4 {
			digest[i]
		} else {
			builder.add_witness()
		}
	});

	let keccak = Keccak::new(builder, total_message_len, len, keccak_digest, message_le.clone());

	let mut terms = Vec::new();
	let param_term = Term {
		len: builder.add_constant_64(param_len as u64),
		data: param_wires,
		max_len: param_len.div_ceil(8) * 8,
	};
	terms.push(param_term);

	let tweak_wire = builder.add_constant_64(tweak_byte as u64);
	let tweak_term = Term {
		len: builder.add_constant_64(1),
		data: vec![tweak_wire],
		max_len: 8,
	};
	terms.push(tweak_term);
	terms.extend(additional_terms);

	let _message_structure_verifier =
		Concat::new(builder, total_message_len.next_multiple_of(8), len, message_le, terms);
	keccak
}

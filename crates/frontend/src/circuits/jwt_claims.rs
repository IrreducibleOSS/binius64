use binius_core::word::Word;

use crate::{
	circuits::slice::Slice,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};

/// Represents a single JWT attribute to verify
pub struct Attribute {
	pub name: &'static str,
	/// The actual length of the expected value in bytes.
	pub len_value: Wire,
	pub value: Vec<Wire>,
}

impl Attribute {
	/// Populate the actual value length
	pub fn populate_len_value(&self, w: &mut WitnessFiller, len_value: usize) {
		w[self.len_value] = Word(len_value as u64);
	}

	/// Populate the expected value from bytes
	///
	/// # Panics
	/// Panics if value.len() > max_value_size (determined by self.value.len() * 8)
	pub fn populate_value(&self, w: &mut WitnessFiller, value: &[u8]) {
		pack_bytes_into_wires_le(w, &self.value, value);
	}
}

/// Verifies that a JSON string contains specific attribute values.
///
/// This circuit validates that the JSON contains each specified attribute
/// with exactly the expected string value.
///
/// This circuit makes some strong assumptions, in particular:
///
/// 1. The input is a valid JSON object. No effort is put into checking that or any other properties
///    such as duplicate keys.
/// 2. No whitespace handling.
/// 3. The attributes of interest are strings only. Matching arrays or objects as values is not
///    supported.
///
/// ❗️ At this point, the circuit does not check that it did not get multiple attributes. For
/// example, imagine there are two attributes "sub" and "nonce" where one is right next to the
/// other. A prover can get away with providing the attribute "sub" but the end quote of the nonce.
pub struct JwtClaims {
	/// The actual length of the JSON string in bytes.
	pub len_json: Wire,
	pub json: Vec<Wire>,
	pub attributes: Vec<Attribute>,
}

impl JwtClaims {
	/// Creates a new JWT claims verifier circuit. See the struct documentation for more details.
	///
	/// # Arguments
	/// * `b` - Circuit builder
	/// * `max_len_json` - Maximum JSON size in bytes (must be multiple of 8)
	/// * `len_json` - Wire for actual JSON size in bytes
	/// * `json` - JSON input array packed as words (8 bytes per word)
	/// * `attributes` - List of attributes to verify with their value wires
	///
	/// # Panics
	/// * If max_len_json is not a multiple of 8
	/// * If json.len() != max_len_json / 8
	/// * If any attribute value array has wrong length for its max size
	pub fn new(
		b: &CircuitBuilder,
		max_len_json: usize,
		len_json: Wire,
		json: Vec<Wire>,
		attributes: Vec<Attribute>,
	) -> Self {
		assert_eq!(max_len_json % 8, 0, "max_len_json must be multiple of 8");
		assert_eq!(json.len(), max_len_json / 8, "json.len() must equal max_len_json / 8");

		// For each attribute, we need to:
		// 1. Find the pattern "name":" in the JSON
		// 2. Extract the string value between the quotes
		// 3. Verify it matches the expected value

		for (attr_idx, attr) in attributes.iter().enumerate() {
			let b = b.subcircuit(format!("attr[ix={}, name={}]", attr_idx, attr.name));

			// Build the search pattern: "name":"
			let pattern = format!("\"{}\":\"", attr.name);
			let pattern_bytes = pattern.as_bytes();
			let pattern_len = pattern_bytes.len();

			// ---- Pattern matching algorithm
			//
			// We search for the pattern "name":" in the JSON by checking every possible
			// starting position. Since we can't break out of loops in circuits, we check
			// all positions and use masking to track where we found matches.
			//
			// Variables:
			// - found_position: the position where we found the pattern (0 if not found yet)
			// - any_found: becomes all-1s when we find the pattern anywhere
			let zero = b.add_constant(Word::ZERO);
			let one = b.add_constant(Word::ONE);
			let all_ones = b.add_constant(Word::ALL_ONE);
			let mut found_position = zero;
			let mut any_found = zero;

			// Check each possible starting position
			for start_pos in 0..max_len_json.saturating_sub(pattern_len) {
				let b = b.subcircuit(format!("start_pos[{start_pos}]"));

				// Check if this position could contain the full pattern
				let start_wire = b.add_constant(Word(start_pos as u64));
				let end_wire = b.add_constant(Word((start_pos + pattern_len) as u64));

				// Verify position is within JSON bounds
				let within_bounds = b.icmp_ult(end_wire, len_json);
				let mut matches_here = within_bounds;

				// Check each byte of the pattern
				for (i, &expected_byte) in pattern_bytes.iter().enumerate() {
					let byte_pos = start_pos + i;
					let word_idx = byte_pos / 8;
					let byte_offset = byte_pos % 8;

					if word_idx < json.len() {
						let actual_byte = b.extract_byte(json[word_idx], byte_offset as u32);
						let expected = b.add_constant(Word(expected_byte as u64));
						let byte_matches = b.icmp_eq(actual_byte, expected);
						matches_here = b.band(matches_here, byte_matches);
					} else {
						matches_here = zero;
					}
				}

				// If we found a match here, remember this position
				// When matches_here is all-1s, include start_wire in found_position
				// When matches_here is all-0s, masked_position is 0 and OR leaves found_position
				// unchanged
				let masked_position = b.band(start_wire, matches_here);
				found_position = b.bor(found_position, masked_position);

				// Update any_found flag (using OR to accumulate any matches)
				any_found = b.bor(any_found, matches_here);
			}

			// Assert that we found the pattern (any_found should be all-1s)
			b.assert_eq("attr_found".to_string(), any_found, all_ones);

			// Now find the value start position (after the pattern)
			let value_start = b.iadd_32(found_position, b.add_constant(Word(pattern_len as u64)));

			// ---- Find value terminator
			//
			// Search for the terminator that marks the end of the attribute value.
			// Valid terminators are: " (closing quote), , (comma), or } (closing brace)
			// We scan all positions starting from value_start and use masking to
			// remember where we found a terminator.
			let mut value_end = zero;
			let mut found_end = zero;
			let quote = b.add_constant_zx_8(b'"');
			let comma = b.add_constant_zx_8(b',');
			let close_brace = b.add_constant_zx_8(b'}');

			for pos in 0..max_len_json {
				let b = b.subcircuit(format!("find_terminator[{pos}]"));

				let pos_wire = b.add_constant(Word(pos as u64));

				// Check if this position is at or after value_start
				// For empty strings, the closing quote is at value_start
				let at_start = b.icmp_eq(value_start, pos_wire);
				let after_start = b.icmp_ult(value_start, pos_wire);
				let at_or_after = b.bor(at_start, after_start);
				// Check if within bounds
				let within_bounds = b.icmp_ult(pos_wire, len_json);
				// Check if we haven't found the end yet (using NOT found_end)
				// found_end is all-0s initially, becomes all-1s when found
				let not_found_yet = b.bxor(found_end, all_ones);

				let mut should_check = b.band(at_or_after, within_bounds);
				should_check = b.band(should_check, not_found_yet);

				// Extract byte at this position
				let word_idx = pos / 8;
				let byte_offset = pos % 8;

				if word_idx < json.len() {
					let byte_at_pos = b.extract_byte(json[word_idx], byte_offset as u32);

					// Check if this byte is any of the valid terminators
					let is_quote = b.icmp_eq(byte_at_pos, quote);
					let is_comma = b.icmp_eq(byte_at_pos, comma);
					let is_close_brace = b.icmp_eq(byte_at_pos, close_brace);

					// It's a terminator if it's any of the three
					let is_terminator = b.bor(is_quote, is_comma);
					let is_terminator = b.bor(is_terminator, is_close_brace);

					let found_here = b.band(should_check, is_terminator);

					// If we found a terminator here, remember this position
					// When found_here is all-1s, include pos_wire in value_end
					// When found_here is all-0s, masked_pos is 0 and OR leaves value_end unchanged
					let masked_pos = b.band(pos_wire, found_here);
					value_end = b.bor(value_end, masked_pos);

					// Update found flag
					found_end = b.bor(found_end, found_here);
				}
			}

			// Assert that we found a terminator (found_end should be all-1s)
			b.assert_eq("attr_terminator_found".to_string(), found_end, all_ones);

			// Calculate value length: value_end - value_start
			// Since circuits don't have a subtraction operation, we use two's complement:
			// a - b = a + (~b + 1), where ~b is bitwise NOT of b
			let neg_start = b.bnot(value_start);
			let neg_start_plus_one = b.iadd_32(neg_start, one);
			let value_length = b.iadd_32(value_end, neg_start_plus_one);

			// Verify the length matches expected
			b.assert_eq("attr_length".to_string(), value_length, attr.len_value);

			// Use Slice to verify the value content
			let max_value_size = attr.value.len() * 8;
			let _slice = Slice::new(
				&b,
				max_len_json,
				max_value_size,
				len_json,
				value_length,
				json.clone(),
				attr.value.clone(),
				value_start,
			);
		}

		JwtClaims {
			len_json,
			json,
			attributes,
		}
	}

	/// Populate the len_json wire with the actual JSON size in bytes
	pub fn populate_len_json(&self, w: &mut WitnessFiller, len_json: usize) {
		w[self.len_json] = Word(len_json as u64);
	}

	/// Populate the JSON array from a byte slice
	///
	/// # Panics
	/// Panics if json.len() > max_len_json (the maximum size specified during construction)
	pub fn populate_json(&self, w: &mut WitnessFiller, json: &[u8]) {
		pack_bytes_into_wires_le(w, &self.json, json);
	}
}

#[cfg(test)]
mod tests {
	use super::{Attribute, JwtClaims, Wire};
	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	#[test]
	fn test_single_attribute() {
		let b = CircuitBuilder::new();

		let max_len_json = 256;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![Attribute {
			name: "sub",
			len_value: b.add_inout(),
			value: (0..16 / 8).map(|_| b.add_inout()).collect(),
		}];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		let json_str = r#"{"sub":"1234567890","iss":"google.com"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected value
		jwt_claims.attributes[0].populate_len_value(&mut filler, 10);
		jwt_claims.attributes[0].populate_value(&mut filler, b"1234567890");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_multiple_attributes() {
		let b = CircuitBuilder::new();

		let max_len_json = 256;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![
			Attribute {
				name: "sub",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
			Attribute {
				name: "iss",
				len_value: b.add_inout(),
				value: (0..32 / 8).map(|_| b.add_inout()).collect(),
			},
			Attribute {
				name: "aud",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
		];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Test JSON with all attributes
		let json_str =
			r#"{"sub":"1234567890","iss":"google.com","aud":"4074087","iat":1676415809}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected values
		jwt_claims.attributes[0].populate_len_value(&mut filler, 10);
		jwt_claims.attributes[0].populate_value(&mut filler, b"1234567890");

		jwt_claims.attributes[1].populate_len_value(&mut filler, 10);
		jwt_claims.attributes[1].populate_value(&mut filler, b"google.com");

		jwt_claims.attributes[2].populate_len_value(&mut filler, 7);
		jwt_claims.attributes[2].populate_value(&mut filler, b"4074087");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_attribute_not_found() {
		let b = CircuitBuilder::new();

		let max_len_json = 128;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![Attribute {
			name: "missing",
			len_value: b.add_inout(),
			value: (0..16 / 8).map(|_| b.add_inout()).collect(),
		}];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// JSON without the required attribute
		let json_str = r#"{"sub":"1234567890","iss":"google.com"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected value (won't be found)
		jwt_claims.attributes[0].populate_len_value(&mut filler, 5);
		jwt_claims.attributes[0].populate_value(&mut filler, b"value");

		// This should fail because "missing" attribute is not in the JSON
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err());
	}

	#[test]
	fn test_wrong_value() {
		let b = CircuitBuilder::new();

		let max_len_json = 128;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![Attribute {
			name: "sub",
			len_value: b.add_inout(),
			value: (0..16 / 8).map(|_| b.add_inout()).collect(),
		}];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Test JSON
		let json_str = r#"{"sub":"1234567890","iss":"google.com"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate wrong expected value
		jwt_claims.attributes[0].populate_len_value(&mut filler, 10);
		jwt_claims.attributes[0].populate_value(&mut filler, b"9876543210");

		// This should fail because the value doesn't match
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err());
	}

	#[test]
	fn test_attributes_in_different_order() {
		let b = CircuitBuilder::new();

		let max_len_json = 256;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![
			Attribute {
				name: "aud",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
			Attribute {
				name: "sub",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
		];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// JSON with attributes in different order
		let json_str =
			r#"{"iss":"google.com","sub":"1234567890","email":"test@example.com","aud":"4074087"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected values
		jwt_claims.attributes[0].populate_len_value(&mut filler, 7);
		jwt_claims.attributes[0].populate_value(&mut filler, b"4074087");

		jwt_claims.attributes[1].populate_len_value(&mut filler, 10);
		jwt_claims.attributes[1].populate_value(&mut filler, b"1234567890");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_empty_string_value() {
		let b = CircuitBuilder::new();

		let max_len_json = 128;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![Attribute {
			name: "empty",
			len_value: b.add_inout(),
			value: (0..8 / 8).map(|_| b.add_inout()).collect(),
		}];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// JSON with empty string value
		let json_str = r#"{"empty":"","sub":"123"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected empty value
		jwt_claims.attributes[0].populate_len_value(&mut filler, 0);
		jwt_claims.attributes[0].populate_value(&mut filler, b"");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_special_characters() {
		let b = CircuitBuilder::new();

		let max_len_json = 256;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![
			Attribute {
				name: "email",
				len_value: b.add_inout(),
				value: (0..32 / 8).map(|_| b.add_inout()).collect(),
			},
			Attribute {
				name: "nonce",
				len_value: b.add_inout(),
				value: (0..32 / 8).map(|_| b.add_inout()).collect(),
			},
		];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// JSON with special characters
		let json_str = r#"{"email":"john.doe@gmail.com","nonce":"7-VU9fuWeWtgDLHmVJ2UtRrine8"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected values
		jwt_claims.attributes[0].populate_len_value(&mut filler, 18);
		jwt_claims.attributes[0].populate_value(&mut filler, b"john.doe@gmail.com");

		jwt_claims.attributes[1].populate_len_value(&mut filler, 27);
		jwt_claims.attributes[1].populate_value(&mut filler, b"7-VU9fuWeWtgDLHmVJ2UtRrine8");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_last_attribute_no_comma() {
		let b = CircuitBuilder::new();

		let max_len_json = 128;
		let len_json = b.add_witness();
		let json: Vec<Wire> = (0..max_len_json / 8).map(|_| b.add_witness()).collect();

		let attributes = vec![
			Attribute {
				name: "iss",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
			Attribute {
				name: "last",
				len_value: b.add_inout(),
				value: (0..16 / 8).map(|_| b.add_inout()).collect(),
			},
		];

		let jwt_claims = JwtClaims::new(&b, max_len_json, len_json, json, attributes);

		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// JSON where the last attribute has no comma after it (terminated by })
		let json_str = r#"{"iss":"example.com","last":"value123"}"#;

		// Populate inputs
		jwt_claims.populate_len_json(&mut filler, json_str.len());
		jwt_claims.populate_json(&mut filler, json_str.as_bytes());

		// Populate expected values
		jwt_claims.attributes[0].populate_len_value(&mut filler, 11);
		jwt_claims.attributes[0].populate_value(&mut filler, b"example.com");

		jwt_claims.attributes[1].populate_len_value(&mut filler, 8);
		jwt_claims.attributes[1].populate_value(&mut filler, b"value123");

		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}
}

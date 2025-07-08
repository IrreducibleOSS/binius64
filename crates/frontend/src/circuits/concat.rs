use crate::{
	circuits::slice::Slice,
	compiler::{CircuitBuilder, Wire},
	word::Word,
};

/// A term in a concatenation - a variable-length byte string.
///
/// Each term represents a byte string where:
/// - `len` is the actual length in bytes
/// - `data` contains the bytes packed into 64-bit words (8 bytes per word)
pub struct Term {
	/// The actual length of this term in bytes
	pub len: Wire,
	/// The term's data as bytes packed into 64-bit words.
	/// Each Wire represents 8 bytes packed in little-endian order.
	pub data: Vec<Wire>,
}

impl Term {
	/// Populate the length wire with the actual term size in bytes
	pub fn populate_len(&self, w: &mut crate::compiler::WitnessFiller, len: usize) {
		w[self.len] = Word(len as u64);
	}

	/// Populate the term's data from a byte slice
	///
	/// # Panics
	/// Panics if data.len() > max_n_term (8 * self.data.len())
	pub fn populate_data(&self, w: &mut crate::compiler::WitnessFiller, data: &[u8]) {
		let max_n_term = self.data.len() * 8;
		assert!(
			data.len() <= max_n_term,
			"term data length {} exceeds maximum {}",
			data.len(),
			max_n_term
		);

		// Pack bytes into words
		for (i, chunk) in data.chunks(8).enumerate() {
			if i < self.data.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.data[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in data.len().div_ceil(8)..self.data.len() {
			w[self.data[i]] = Word::ZERO;
		}
	}
}

/// Verifies that a joined string is the concatenation of a list of terms.
///
/// This circuit validates that `joined` contains exactly the concatenation
/// of all provided terms in order.
pub struct Concat {
	pub len_joined: Wire,
	pub joined: Vec<Wire>,
	pub terms: Vec<Term>,
}

impl Concat {
	/// Creates a new concatenation verifier circuit.
	///
	/// # Arguments
	/// * `b` - Circuit builder
	/// * `max_n_joined` - Maximum joined size in bytes (must be multiple of 8)
	/// * `max_n_term` - Maximum size of any single term in bytes (must be multiple of 8)
	/// * `len_joined` - Actual joined size in bytes
	/// * `joined` - Joined array packed as words (8 bytes per word)
	/// * `terms` - Vector of terms to concatenate
	///
	/// # Panics
	/// * If max_n_joined is not a multiple of 8
	/// * If max_n_term is not a multiple of 8
	/// * If joined.len() != max_n_joined / 8
	/// * If any term's data.len() != max_n_term / 8
	pub fn new(
		b: &CircuitBuilder,
		max_n_joined: usize,
		max_n_term: usize,
		len_joined: Wire,
		joined: Vec<Wire>,
		terms: Vec<Term>,
	) -> Self {
		assert_eq!(max_n_joined % 8, 0, "max_n_joined must be multiple of 8");
		assert_eq!(max_n_term % 8, 0, "max_n_term must be multiple of 8");
		assert_eq!(joined.len(), max_n_joined / 8, "joined.len() must equal max_n_joined / 8");

		for (i, term) in terms.iter().enumerate() {
			assert_eq!(
				term.data.len(),
				max_n_term / 8,
				"term[{i}].data.len() must equal max_n_term / 8"
			);
		}

		// We maintain a wire that tracks the current `offset`. Each term increments `offset` by
		// it's length.
		//
		// Then, for each term we verify that the below expression holds
		//
		//     joined[offset..offset + term.len] == term.data
		//
		// This is done with the `Slice` gadget.
		let mut offset = b.add_constant(Word::ZERO);
		for (i, term) in terms.iter().enumerate() {
			let b = b.subcircuit(format!("term[{i}]"));
			let _slice = Slice::new(
				&b,
				max_n_joined,
				max_n_term,
				len_joined,
				term.len,
				joined.clone(),
				term.data.clone(),
				offset,
			);
			offset = b.iadd_32(offset, term.len);
		}

		// Verify that the final offset equals len_joined
		b.assert_eq("concat_length", offset, len_joined);

		Concat {
			len_joined,
			joined,
			terms,
		}
	}

	/// Populate the len_joined wire with the actual joined size in bytes
	pub fn populate_len_joined(&self, w: &mut crate::compiler::WitnessFiller, len_joined: usize) {
		w[self.len_joined] = Word(len_joined as u64);
	}

	/// Populate the joined array from a byte slice
	///
	/// # Panics
	/// Panics if joined.len() > max_n_joined (the maximum size specified during construction)
	pub fn populate_joined(&self, w: &mut crate::compiler::WitnessFiller, joined: &[u8]) {
		let max_n_joined = self.joined.len() * 8;
		assert!(
			joined.len() <= max_n_joined,
			"joined length {} exceeds maximum {}",
			joined.len(),
			max_n_joined
		);

		// Pack bytes into words
		for (i, chunk) in joined.chunks(8).enumerate() {
			if i < self.joined.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.joined[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in joined.len().div_ceil(8)..self.joined.len() {
			w[self.joined[i]] = Word::ZERO;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::compiler::CircuitBuilder;

	/// Helper to create a concat circuit with given parameters
	fn create_concat_circuit(
		max_n_joined: usize,
		max_n_terms: usize,
		max_n_term: usize,
	) -> (CircuitBuilder, Concat) {
		let b = CircuitBuilder::new();

		let len_joined = b.add_inout();
		let joined: Vec<Wire> = (0..max_n_joined / 8).map(|_| b.add_inout()).collect();

		let terms: Vec<Term> = (0..max_n_terms)
			.map(|_| Term {
				len: b.add_inout(),
				data: (0..max_n_term / 8).map(|_| b.add_inout()).collect(),
			})
			.collect();

		let concat = Concat::new(&b, max_n_joined, max_n_term, len_joined, joined, terms);

		(b, concat)
	}

	/// Helper to test a concatenation scenario
	fn test_concat(
		max_n_joined: usize,
		max_n_term: usize,
		expected_joined: &[u8],
		term_data: &[&[u8]],
	) -> Result<(), Box<dyn std::error::Error>> {
		let (b, concat) = create_concat_circuit(max_n_joined, term_data.len(), max_n_term);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Set the expected joined length
		concat.populate_len_joined(&mut filler, expected_joined.len());
		concat.populate_joined(&mut filler, expected_joined);

		// Set up each term
		for (i, data) in term_data.iter().enumerate() {
			concat.terms[i].populate_len(&mut filler, data.len());
			concat.terms[i].populate_data(&mut filler, data);
		}

		circuit.populate_wire_witness(&mut filler)?;
		Ok(())
	}

	#[test]
	fn test_two_terms_concat() {
		// "hello" + "world" = "helloworld"
		test_concat(16, 8, b"helloworld", &[b"hello", b"world"]).unwrap();
	}

	#[test]
	fn test_three_terms_concat() {
		// "foo" + "bar" + "baz" = "foobarbaz"
		test_concat(24, 8, b"foobarbaz", &[b"foo", b"bar", b"baz"]).unwrap();
	}

	#[test]
	fn test_empty_term() {
		// "hello" + "" + "world" = "helloworld"
		test_concat(16, 8, b"helloworld", &[b"hello", b"", b"world"]).unwrap();
	}

	#[test]
	fn test_unaligned_terms() {
		// "hello12" (7 bytes) + "world456" (8 bytes) = "hello12world456"
		test_concat(24, 16, b"hello12world456", &[b"hello12", b"world456"]).unwrap();
	}

	#[test]
	fn test_domain_concat() {
		// "api" + "." + "example" + "." + "com" = "api.example.com"
		test_concat(32, 16, b"api.example.com", &[b"api", b".", b"example", b".", b"com"]).unwrap();
	}

	#[test]
	fn test_all_terms_empty() {
		// "" + "" = ""
		test_concat(8, 8, b"", &[b"", b""]).unwrap();
	}

	#[test]
	fn test_single_term() {
		// "hello" = "hello"
		test_concat(8, 8, b"hello", &[b"hello"]).unwrap();
	}

	#[test]
	fn test_single_byte_terms() {
		// "a" + "b" + "c" + "d" + "e" = "abcde"
		test_concat(8, 8, b"abcde", &[b"a", b"b", b"c", b"d", b"e"]).unwrap();
	}

	#[test]
	fn test_length_mismatch() {
		// Test where claimed length doesn't match actual concatenation
		let (b, concat) = create_concat_circuit(16, 2, 8);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Claim joined is 8 bytes but terms sum to 10
		concat.populate_len_joined(&mut filler, 8);
		concat.populate_joined(&mut filler, b"helloworld");

		concat.terms[0].populate_len(&mut filler, 5);
		concat.terms[0].populate_data(&mut filler, b"hello");
		concat.terms[1].populate_len(&mut filler, 5);
		concat.terms[1].populate_data(&mut filler, b"world");

		// This should fail due to length mismatch
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err());
	}
}

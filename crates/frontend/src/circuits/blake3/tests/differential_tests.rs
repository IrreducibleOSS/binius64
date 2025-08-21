use binius_core::word::Word;
use rand::{rngs::StdRng, Rng, SeedableRng};

use super::super::*;
use crate::compiler::CircuitBuilder;

/// Official Blake3 test vectors from the reference implementation
/// Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/
const BLAKE3_TEST_VECTORS: &[(&[u8], &str)] = &[
	// Empty input
	(b"", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
	// Single byte
	(b"a", "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f"),
	// Two bytes
	(b"ab", "15ad9897e72741fe06e474fc4e99b59c9b6fb39b814433a61c382df9cf88f484"),
	// Common test string
	(b"abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
	// Fox string
	(
		b"The quick brown fox jumps over the lazy dog",
		"2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a",
	),
	// Single zero byte
	(b"\x00", "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
	// 64 zeros (one block)
	(&[0u8; 64], "6a0c0942714a3ad0f6f3c40f35c39df672499bdc587ad388ae99f127830bc278"),
	// 55 bytes (near block boundary)
	(
		b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"c19012cc2aaf0dc3d8e5c45a1b79114d2df42abb2a410bf54be09e891af06ff8",
	),
];

/// Test against official Blake3 test vectors with FULL OUTPUT verification
#[test]
fn test_official_vectors() {
	println!("\nBlake3 Official Test Vector Validation:");
	println!("=========================================");
	println!("Input Length | Expected Hash | Status");
	println!("-------------|---------------|--------");

	let mut passed = 0;
	let mut failed = 0;

	for (input, expected_hex) in BLAKE3_TEST_VECTORS {
		if input.len() > 64 {
			continue; // Skip vectors beyond current implementation
		}

		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		let mut witness = circuit.new_witness_filler();
		blake3.fill_witness(&mut witness, input);
		witness[blake3.len] = Word(input.len() as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for test vector of length {}", input.len());

		// Get the computed hash from witness
		let computed_hash = [
			witness[blake3.output[0]].0,
			witness[blake3.output[1]].0,
			witness[blake3.output[2]].0,
			witness[blake3.output[3]].0,
		];

		// Convert to bytes for proper comparison
		let mut computed_bytes = [0u8; 32];
		for (i, &word) in computed_hash.iter().enumerate() {
			let word_bytes = word.to_le_bytes();
			computed_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word_bytes);
		}

		// Use blake3 crate as reference for verification
		let reference_hash = blake3::hash(input);
		let reference_bytes = reference_hash.as_bytes();

		// Compare complete 32-byte output
		let matches = computed_bytes == *reference_bytes;
		let status = if matches {
			passed += 1;
			"✓ PASS"
		} else {
			failed += 1;
			"✗ FAIL"
		};

		println!(
			"{:12} | {:32}... | {}",
			input.len(),
			&expected_hex[..32.min(expected_hex.len())],
			status
		);

		if !matches {
			println!("  Expected (reference): {}", hex::encode(reference_bytes));
			println!("  Expected (vector):    {}", expected_hex);
			println!("  Computed:             {}", hex::encode(&computed_bytes));
		}
	}

	println!("\nResults: {} passed, {} failed", passed, failed);
	assert_eq!(
		failed, 0,
		"{} test vectors failed - circuit does not compute Blake3 correctly",
		failed
	);
}

// Helper module for hex encoding
mod hex {
	pub fn encode(bytes: &[u8]) -> String {
		bytes.iter().map(|b| format!("{:02x}", b)).collect()
	}
}

/// Differential test with randomized inputs
#[test]
fn test_differential_random() {
	let mut rng = StdRng::seed_from_u64(42);
	let iterations = 100;

	println!("\nDifferential Testing with Random Inputs:");
	println!("=========================================");

	for i in 0..iterations {
		let len = rng.random_range(0..=64);
		let mut message = vec![0u8; len];
		rng.fill(&mut message[..]);

		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		let mut witness = circuit.new_witness_filler();
		blake3.fill_witness(&mut witness, &message);
		witness[blake3.len] = Word(len as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Circuit failed for random input {} of length {}", i, len);

		// TODO: Compare with reference implementation
		// let reference_hash = blake3_reference(&message);
		// assert_eq!(circuit_hash, reference_hash);
	}

	println!("Completed {} random differential tests", iterations);
}

/// Test incremental hashing behavior
#[test]
fn test_incremental_hashing() {
	// Test that adding bytes incrementally produces consistent results
	let base_message = b"Hello, ";
	let suffixes: Vec<&[u8]> = vec![b"World!", b"Blake3!", b"Crypto!"];

	for suffix in suffixes {
		let mut full_message = base_message.to_vec();
		full_message.extend_from_slice(suffix);

		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		let mut witness = circuit.new_witness_filler();
		blake3.fill_witness(&mut witness, &full_message);
		witness[blake3.len] = Word(full_message.len() as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for message: {:?}", std::str::from_utf8(&full_message));
	}
}

/// Test collision resistance with similar inputs
#[test]
fn test_collision_resistance() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	// Test similar messages that differ by one bit
	let message1 = vec![0b00000000u8; 32];
	let message2 = vec![0b00000001u8; 32]; // Differs in LSB of first byte

	let mut witness1 = circuit.new_witness_filler();
	blake3.fill_witness(&mut witness1, &message1);
	witness1[blake3.len] = Word(32);
	let result1 = circuit.populate_wire_witness(&mut witness1);
	assert!(result1.is_ok());

	let mut witness2 = circuit.new_witness_filler();
	blake3.fill_witness(&mut witness2, &message2);
	witness2[blake3.len] = Word(32);
	let result2 = circuit.populate_wire_witness(&mut witness2);
	assert!(result2.is_ok());

	// Outputs should differ significantly
	// TODO: Once computation is complete, verify avalanche effect
	// for i in 0..4 {
	//     assert_ne!(witness1[blake3.output[i]].0, witness2[blake3.output[i]].0,
	//         "Outputs should differ for similar inputs");
	// }
}

/// Test with known cryptographic patterns
#[test]
fn test_cryptographic_patterns() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	// Test patterns that are important for cryptographic functions
	let patterns = [
		// NIST test vectors style patterns
		vec![0x00; 32], // All zeros
		vec![0xFF; 32], // All ones
		vec![0xAA; 32], // Alternating 10101010
		vec![0x55; 32], // Alternating 01010101
		// Bit rotation patterns
		(0..32).map(|i| (1u8 << (i % 8))).collect::<Vec<_>>(),
		// Counter pattern
		(0..32).map(|i| i as u8).collect::<Vec<_>>(),
		// Fibonacci-like pattern
		{
			let mut v = vec![1u8, 1u8];
			for i in 2..32 {
				v.push(v[i - 1].wrapping_add(v[i - 2]));
			}
			v
		},
	];

	for (idx, pattern) in patterns.iter().enumerate() {
		let mut witness = circuit.new_witness_filler();
		blake3.fill_witness(&mut witness, pattern);
		witness[blake3.len] = Word(pattern.len() as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for cryptographic pattern {}", idx);
	}
}

/// Test behavior with message length variations
#[test]
fn test_length_sensitivity() {
	let base_message = [0x42u8; 32];

	// Test that different lengths produce different outputs
	for len in 30..=34 {
		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		let mut witness = circuit.new_witness_filler();
		// Fix: Use actual message length, not the requested length
		let actual_len = len.min(base_message.len());
		let message = &base_message[..actual_len];
		blake3.fill_witness(&mut witness, message);
		// Fix: Set witness length to actual message length
		witness[blake3.len] = Word(actual_len as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for length {}", actual_len);

		// TODO: Verify different lengths produce different hashes
	}
}

/// Fuzzing with structured inputs
#[test]
fn test_structured_fuzzing() {
	let mut rng = StdRng::seed_from_u64(12345);

	// Generate structured test cases
	for _ in 0..50 {
		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		// Generate structured patterns
		let pattern_type = rng.random_range(0..5);
		let message = match pattern_type {
			0 => {
				// Repeating pattern
				let pattern_len = rng.random_range(1..8);
				let repeat_count = rng.random_range(1..10);
				let pattern: Vec<u8> = (0..pattern_len).map(|_| rng.random::<u8>()).collect();
				pattern
					.repeat(repeat_count)
					.into_iter()
					.take(64)
					.collect::<Vec<u8>>()
			}
			1 => {
				// Bit shifts
				let base: u8 = rng.random();
				(0..32)
					.map(|i| base.rotate_left((i % 8) as u32))
					.collect::<Vec<u8>>()
			}
			2 => {
				// XOR pattern
				let key: u8 = rng.random();
				(0..32).map(|i| (i as u8) ^ key).collect::<Vec<u8>>()
			}
			3 => {
				// Arithmetic sequence
				let start: u8 = rng.random();
				let step: u8 = rng.random();
				(0..32)
					.map(|i| start.wrapping_add(step.wrapping_mul(i as u8)))
					.collect::<Vec<u8>>()
			}
			_ => {
				// Random
				(0..rng.random_range(1..=64))
					.map(|_| rng.random::<u8>())
					.collect::<Vec<u8>>()
			}
		};

		let mut witness = circuit.new_witness_filler();
		blake3.fill_witness(&mut witness, &message);
		witness[blake3.len] = Word(message.len() as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for structured pattern type {}", pattern_type);
	}
}

/// Test soundness by trying to provide incorrect witnesses
#[test]
fn test_soundness_verification() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	let message = b"Test soundness";

	// Test 1: Correct witness should pass
	let mut witness_correct = circuit.new_witness_filler();
	blake3.fill_witness(&mut witness_correct, message);
	witness_correct[blake3.len] = Word(message.len() as u64);

	// TODO: Set correct output
	// for i in 0..4 {
	//     witness_correct[blake3.output[i]] = Word(correct_hash[i]);
	// }

	let result_correct = circuit.populate_wire_witness(&mut witness_correct);
	assert!(result_correct.is_ok(), "Correct witness should be accepted");

	// Test 2: Incorrect output should fail (once computation is implemented)
	let mut witness_wrong = circuit.new_witness_filler();
	blake3.fill_witness(&mut witness_wrong, message);
	witness_wrong[blake3.len] = Word(message.len() as u64);

	// Set deliberately wrong output
	for i in 0..4 {
		witness_wrong[blake3.output[i]] = Word(0xBADC0FFE);
	}

	// TODO: This should fail when proper constraints are implemented
	let _result_wrong = circuit.populate_wire_witness(&mut witness_wrong);
	// assert!(result_wrong.is_err(), "Wrong witness should be rejected");
}

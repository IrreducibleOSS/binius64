// Copyright 2025 Irreducible Inc.
//! Blake2s test vectors from RFC 7693 and additional edge cases
//!
//! This module contains test vectors for Blake2s verification, including
//! official vectors from RFC 7693 and additional edge cases to ensure
//! comprehensive testing of the circuit implementation.

use hex_literal::hex;

/// Test vector structure for Blake2s
pub struct TestVector {
	pub name: &'static str,
	pub message: &'static [u8],
	pub expected: [u8; 32],
}

/// Official Blake2s test vectors from RFC 7693 Appendix B
pub const RFC_TEST_VECTORS: &[TestVector] = &[
	TestVector {
		name: "RFC: Empty message",
		message: b"",
		expected: hex!("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
	},
	TestVector {
		name: "RFC: 'abc'",
		message: b"abc",
		expected: hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
	},
];

/// Edge case test vectors for boundary conditions
pub const EDGE_CASE_VECTORS: &[TestVector] = &[
	// Single byte tests
	TestVector {
		name: "Single null byte",
		message: &[0x00],
		expected: hex!("e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea"),
	},
	TestVector {
		name: "Single 0xFF byte",
		message: &[0xFF],
		expected: hex!("8a1ef126b4e286703744a80b2f414be700cc93023e7bfc8688b79b54931abd27"),
	},
	// Word boundary tests (32-bit)
	TestVector {
		name: "31 bytes (just under word)",
		message: &[0x00; 31],
		expected: hex!("4b69cb57765bf40d2689105232f35d0750013ac1d53991860d5443019884aa60"),
	},
	TestVector {
		name: "32 bytes (exactly one word)",
		message: &[0xFF; 32],
		expected: hex!("61d3efa051909b2a85c53114ce79cc023cd3adbfd8917aead7dd3086c83617ad"),
	},
	TestVector {
		name: "33 bytes (just over word)",
		message: &[0xAA; 33],
		expected: hex!("031cdbbdf5746d70a9087ecc5ddcde6ff3f2a21b31265b5d248f0886540dc723"),
	},
	// Block boundary tests (64-byte blocks)
	TestVector {
		name: "55 bytes",
		message: &[0x55; 55],
		expected: hex!("460eef4ff501fac37cac0ac84f4675308cc18b9c6019b5dbdc1650b5538d7475"),
	},
	TestVector {
		name: "56 bytes",
		message: &[0xAB; 56],
		expected: hex!("267877b8edbfba0e94d1d6ddf6a2cab23615327c532e7ddeb688dd44946eeb34"),
	},
	TestVector {
		name: "57 bytes",
		message: &[0xCD; 57],
		expected: hex!("5cf02680dabedb29b310cfa9acae82a381079c0e434b1c25fd3142fa56382b5f"),
	},
	TestVector {
		name: "63 bytes (just under block)",
		message: &[0x0F; 63],
		expected: hex!("ec808215497f89da7052d1ca691106a575d5799ca18519ac4f9d2c38623c9327"),
	},
	TestVector {
		name: "64 bytes (exactly one block)",
		message: &[0xF0; 64],
		expected: hex!("0e1750481c5f451ce1c101eaa1305de8c3a69f6415ceb8cb3b00e4e84576c310"),
	},
	TestVector {
		name: "65 bytes (just over block)",
		message: &[0x33; 65],
		expected: hex!("57cda2280e8298052dff5458dd1cb96d348f506a5b1a94483a88596838bf2b72"),
	},
	TestVector {
		name: "127 bytes (just under two blocks)",
		message: &[0xCC; 127],
		expected: hex!("fff1fc904f0f655002d89c358233446840fe2822dc8811aca7483247afee2f14"),
	},
	TestVector {
		name: "128 bytes (exactly two blocks)",
		message: &[0x5A; 128],
		expected: hex!("dbe9d41b42d8e74b86fcf882cfa2c21d33dc575c5e86650d38800e7c095e9e9f"),
	},
];

/// Well-known test patterns
pub const PATTERN_VECTORS: &[TestVector] = &[
	TestVector {
		name: "Classic: DEADBEEF pattern",
		message: &[0xDE, 0xAD, 0xBE, 0xEF],
		expected: hex!("2e746782fc5a2ada501c2e05a72c212d9d1b2219aa2ebd05dbd24b893fdb7c60"),
	},
	TestVector {
		name: "Classic: CAFEBABE pattern",
		message: &[0xCA, 0xFE, 0xBA, 0xBE],
		expected: hex!("19295e3cbc6347d837b4d707f3fd17822317c998359b3532f7d64cd4a2ebabb3"),
	},
	TestVector {
		name: "Hex counting pattern",
		message: &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
		expected: hex!("691838d60da3b595c94ca7746dd4f5229751ff264966cfd879b2a828f5ebdd85"),
	},
	TestVector {
		name: "Pangram: Quick brown fox",
		message: b"The quick brown fox jumps over the lazy dog",
		expected: hex!("606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"),
	},
	TestVector {
		name: "High bits pattern",
		message: &[0x80; 64],
		expected: hex!("6b380806ac15c4e415f6dd18dae37699271246019ba4fd12e8e9a3ccf45573bd"),
	},
	TestVector {
		name: "Low bits pattern",
		message: &[0x01; 64],
		expected: hex!("dc3c4c7e77f743a2625e771cf71247d0a74821553b38600d0943316d5ff6987f"),
	},
];

/// Generate test message of incrementing bytes
pub fn incrementing_bytes(len: usize) -> Vec<u8> {
	(0..len).map(|i| (i & 0xFF) as u8).collect()
}

/// Generate test message of decrementing bytes
pub fn decrementing_bytes(len: usize) -> Vec<u8> {
	(0..len).map(|i| ((255 - i) & 0xFF) as u8).collect()
}

/// All test vectors combined for comprehensive testing
pub fn all_test_vectors() -> Vec<TestVector> {
	let mut vectors = Vec::new();

	// Add RFC vectors
	for v in RFC_TEST_VECTORS {
		vectors.push(TestVector {
			name: v.name,
			message: v.message,
			expected: v.expected,
		});
	}

	// Add edge case vectors
	for v in EDGE_CASE_VECTORS {
		vectors.push(TestVector {
			name: v.name,
			message: v.message,
			expected: v.expected,
		});
	}

	// Add pattern vectors
	for v in PATTERN_VECTORS {
		vectors.push(TestVector {
			name: v.name,
			message: v.message,
			expected: v.expected,
		});
	}

	vectors
}

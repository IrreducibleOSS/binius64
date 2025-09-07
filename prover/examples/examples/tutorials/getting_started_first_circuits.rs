// Copyright 2025 Irreducible Inc.

//! First Circuits
//!
//! Apply the concepts from basics to build working circuits.
//!
//! Tutorial guide: https://www.binius.xyz/building/

use binius_circuits::sha256::Sha256;
use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{compiler::CircuitBuilder, stat::CircuitStat};
use sha2::{Digest, Sha256 as StdSha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("=== First Circuits Examples ===\n");

	println!("Example 1: Masked AND Circuit");
	println!("------------------------------");
	masked_and_example()?;
	println!();

	println!("Example 2: SHA256 Preimage Circuit");
	println!("-----------------------------------");
	sha256_preimage_example()?;

	Ok(())
}

fn masked_and_example() -> Result<(), Box<dyn std::error::Error>> {
	// Phase 1: Circuit Building
	let builder = CircuitBuilder::new();

	let mask = builder.add_constant_64(0xFF00);
	let private = builder.add_witness();
	let result = builder.band(private, mask);

	// Public output for verification
	let output = builder.add_inout();
	builder.assert_eq("masked_result", result, output);

	let circuit = builder.build();

	// Phase 2: Witness Generation
	let mut w = circuit.new_witness_filler();
	w[private] = Word(0x1234);
	w[output] = Word(0x1200);

	circuit.populate_wire_witness(&mut w)?;

	// Phase 3: Constraint Verification
	let cs = circuit.constraint_system();
	verify_constraints(cs, &w.into_value_vec())?;

	println!("✓ Proof verified: Someone knows a value that masks to 0x1200");
	let stat = CircuitStat::collect(&circuit);
	println!("  Circuit used {} AND constraints", stat.n_and_constraints);

	Ok(())
}

fn sha256_preimage_example() -> Result<(), Box<dyn std::error::Error>> {
	// Phase 1: Circuit Building
	let builder = CircuitBuilder::new();

	// 64-byte message (8 words)
	let message: Vec<_> = (0..8).map(|_| builder.add_witness()).collect();

	// Private message length
	let message_len = builder.add_witness();

	// SHA256 digest (4 words = 256 bits)
	let expected_digest: [_; 4] = core::array::from_fn(|_| builder.add_inout());

	// Create SHA256 circuit
	let sha256 = Sha256::new(&builder, message_len, expected_digest, message.clone());

	let circuit = builder.build();

	// Phase 2: Witness Generation
	let mut w = circuit.new_witness_filler();

	// Set the message length (private)
	w[message_len] = Word(64);

	// Message with nonce
	let mut message_bytes = vec![0u8; 64];
	let test_data = b"test message data";
	message_bytes[..test_data.len()].copy_from_slice(test_data);
	// Add nonce to remaining bytes
	let nonce = 0x123456789ABCDEF0u64.to_le_bytes();
	let nonce_start = test_data.len();
	message_bytes[nonce_start..nonce_start + 8].copy_from_slice(&nonce);

	// Populate message
	sha256.populate_message(&mut w, &message_bytes);

	// Compute expected digest using standard SHA256
	let hash = StdSha256::digest(&message_bytes);
	let mut digest_bytes = [0u8; 32];
	digest_bytes.copy_from_slice(&hash);

	// Populate digest
	sha256.populate_digest(&mut w, digest_bytes);

	circuit.populate_wire_witness(&mut w)?;

	// Phase 3: Constraint Verification
	let cs = circuit.constraint_system();
	verify_constraints(cs, &w.into_value_vec())?;

	println!("✓ SHA256 preimage verified without revealing the message or its length");
	let stat = CircuitStat::collect(&circuit);
	println!("  Circuit used {} AND constraints", stat.n_and_constraints);

	Ok(())
}

// Additional operations to explore:

fn _explore_operations(builder: &CircuitBuilder) {
	// Different data types from basics examples
	let a = builder.add_constant_64(0xFF00FF00);
	let b = builder.add_constant_64(0x00FF00FF);
	let _xor_result = builder.bxor(a, b);

	let x = builder.add_constant_64(100);
	let y = builder.add_constant_64(200);
	let zero = builder.add_constant_64(0);
	let (_sum, _) = builder.iadd_cin_cout(x, y, zero);

	let p = builder.add_constant_64(50);
	let q = builder.add_constant_64(100);
	let _cmp = builder.icmp_ult(p, q);

	// XOR packing optimization
	let values = [
		builder.add_constant_64(0x1111),
		builder.add_constant_64(0x2222),
		builder.add_constant_64(0x4444),
		builder.add_constant_64(0x8888),
	];
	let _packed_xor = builder.bxor_multi(&values); // Single constraint for all XORs

	// Public inputs with private computation
	let public_input = builder.add_inout();
	let secret = builder.add_witness();
	let (computed, _) = builder.iadd_cin_cout(public_input, secret, zero);
	let public_output = builder.add_inout();
	builder.assert_eq("verify", computed, public_output);

	// Non-deterministic hints
	let dividend = vec![builder.add_constant_64(100)];
	let divisor = vec![builder.add_constant_64(83)];
	let (_quotient, _remainder) = builder.biguint_divide_hint(&dividend, &divisor);
}

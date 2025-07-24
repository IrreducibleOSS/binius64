use num_bigint::BigUint;
use num_integer::Integer;

use super::fixed_byte_vec::FixedByteVec;
use crate::{
	circuits::{
		bignum::{BigNum, ModReduce, assert_eq, mul, square},
		sha256::Sha256,
	},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};

/// Convert a FixedByteVec with big-endian byte ordering to a BigNum.
///
/// This function converts a FixedByteVec containing a packed representation of
/// bytes with big-endian ordering (see `FixedByteVec::populate_bytes`) to a
/// BigNum that's compatible with BigNum arithmetic.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `byte_vec` - FixedByteVec containing bytes in big-endian order, with each wire containing 8
///   bytes packed in little-endian order
///
/// # Returns
/// A vector of 32 wires representing the corresponding BigNum
fn fixedbytevec_be_to_bignum(builder: &mut CircuitBuilder, byte_vec: &FixedByteVec) -> BigNum {
	let mut limbs = Vec::new();

	// Reverse wires to convert from big-endian to little-endian byte ordering.
	for packed_wire in byte_vec.data.clone().into_iter().rev() {
		let mut bytes = Vec::with_capacity(8);
		for i in 0..8 {
			bytes.push(builder.extract_byte(packed_wire, i));
		}

		// Combine the bytes of each wire to a 64-bit big-endian word to be
		// compatible with BigNum arithmetic
		let mut be_word = bytes[7];
		for i in 1..8 {
			let shifted = builder.shl(bytes[7 - i], (i * 8) as u32);
			be_word = builder.bor(be_word, shifted);
		}

		limbs.push(be_word);
	}

	BigNum { limbs }
}

/// RS256 signature verification circuit (internal implementation)
///
/// This circuit verifies a `signature` for a given `message` according to the
/// signature verification algorithm RSASSA-PKCS1-v1_5, using SHA-256 as a
/// hash.
///
/// This signature verification algorithm is used in JWT signatures which have
/// the "alg" header set to "RS256".
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-3.1>
pub struct Rs256Verify {
	/// The message to verify (packed as 64-bit words, 8 bytes per wire)
	pub message: FixedByteVec,
	/// The RSA signature as a FixedByteVec (the primary input interface)
	pub signature: FixedByteVec,
	/// The RSA modulus as a FixedByteVec (the primary input interface)
	pub modulus: FixedByteVec,
	/// Quotients for each of the 16 squaring operations
	pub square_quotients: Vec<BigNum>,
	/// Remainders for each of the 16 squaring operations
	pub square_remainders: Vec<BigNum>,
	/// Quotient for the final multiplication
	pub mul_quotient: BigNum,
	/// Remainder for the final multiplication (the EM - Encoded Message)
	pub mul_remainder: BigNum,
	/// SHA256 circuit for hashing the message
	pub sha256: Sha256,
}

impl Rs256Verify {
	/// Create a new RS256 verification circuit
	///
	/// RS256 uses the public exponent 2^16 + 1 (65537). The circuit verifies
	/// that the encoded message (EM) has the following properties:
	///
	/// - `EM = signature^65537 mod modulus`
	/// - `EM` has a valid PKCS#1 v1.5 prefix
	/// - The hash stored in `EM` is equal to the SHA-256 hash of the provided message.
	///
	/// Additional wires for quotients and remainders must be provided for the
	/// nested modular reduction circuits.
	///
	/// # Arguments
	/// * `builder` - Circuit builder
	/// * `message` - A FixedByteVec containing the plaintext message
	/// * `signature` - The RSA signature as a FixedByteVec (256 bytes for 2048-bit RSA). The
	///   signature should be in big-endian byte order (standard JWT/RSA format). Each wire in the
	///   FixedByteVec contains 8 bytes packed in little-endian order.
	/// * `modulus` - The RSA modulus as a FixedByteVec (256 bytes for 2048-bit RSA). The modulus
	///   should be in big-endian byte order (standard RSA format). Each wire in the FixedByteVec
	///   contains 8 bytes packed in little-endian order.
	/// * `square_quotients` - Quotients for the 16 squaring operations
	/// * `square_remainders` - Remainders for the 16 squaring operations
	/// * `mul_quotient` - Quotient for the final multiplication
	/// * `mul_remainder` - Remainder for the final multiplication, this is the EM (Encoded Message)
	///   specified in PKCS#1 v1.5.
	///
	/// # Panics
	/// * If signature_bytes does not have enough space for 256 bytes
	/// * If square_quotients or square_remainders are not length 16
	/// * If mul_remainder does not have 32 limbs
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		builder: &mut CircuitBuilder,
		message: FixedByteVec,
		signature: FixedByteVec,
		modulus: FixedByteVec,
		square_quotients: Vec<BigNum>,
		square_remainders: Vec<BigNum>,
		mul_quotient: BigNum,
		mul_remainder: BigNum,
	) -> Self {
		assert!(
			signature.max_len >= 256,
			"signature_bytes must have at least 256 bytes for 2048-bit RSA"
		);
		assert!(
			signature.max_len.is_multiple_of(8),
			"signature_bytes max_len must be multiple of 8"
		);
		assert!(
			modulus.max_len >= 256,
			"modulus_bytes must have at least 256 bytes for 2048-bit RSA"
		);
		assert!(modulus.max_len.is_multiple_of(8), "modulus_bytes max_len must be multiple of 8");
		assert_eq!(square_quotients.len(), 16, "must provide 16 square quotients");
		assert_eq!(square_remainders.len(), 16, "must provide 16 square remainders");
		assert_eq!(
			mul_remainder.limbs.len(),
			32,
			"mul_remainder must have 32 limbs to store the EM"
		);

		let signature_bignum = fixedbytevec_be_to_bignum(builder, &signature);
		builder.assert_eq("signature_bytes_len", signature.len, builder.add_constant_64(256));

		let modulus_bignum = fixedbytevec_be_to_bignum(builder, &modulus);
		builder.assert_eq("modulus_bytes_len", modulus.len, builder.add_constant_64(256));

		let mut sha256_builder = builder.subcircuit("sha256");
		let expected_hash_wires: [Wire; 4] = std::array::from_fn(|_| sha256_builder.add_witness());
		let sha256 = Sha256::new(
			&mut sha256_builder,
			message.max_len,
			message.len,
			expected_hash_wires,
			message.data.clone(),
		);
		let expected_hash = BigNum {
			limbs: expected_hash_wires.to_vec(),
		};

		modexp_65537_verify(
			builder,
			&signature_bignum,
			&modulus_bignum,
			&square_quotients,
			&square_remainders,
			&mul_quotient,
			&mul_remainder,
		);

		// Validate PKCS#1 v1.5 prefix structure
		// The EM (Encoded Message) has the following format (in big-endian):
		// Bytes 0-1: 0x00 0x01
		// Bytes 2-203: 0xFF padding (202 bytes)
		// Byte 204: 0x00 separator
		// Bytes 205-223: SHA-256 DigestInfo (19 bytes)
		// Bytes 224-255: SHA-256 hash (32 bytes)

		// When converted to little-endian limbs (as used in BigNum):
		// - Limbs 0-3: SHA-256 hash (bytes 224-255 in big-endian)
		// - Limbs 4-31: PKCS#1 v1.5 prefix (bytes 0-223 in big-endian)

		// Pre-computed expected limbs for PKCS#1 v1.5 prefix with SHA-256
		// These values represent the PKCS#1 v1.5 structure when converted from
		// big-endian bytes to little-endian u64 limbs as a 256-byte BigUint
		const EXPECTED_PREFIX_LIMBS: [u64; 28] = [
			// Limb 4-6: DigestInfo bytes
			0x0304020105000420,
			0x0d06096086480165,
			0xffffffff00303130,
			// Limbs 7-30: All padding (0xFF)
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			// Limb 31: Header bytes (0x00, 0x01) and padding
			0x0001ffffffffffff,
		];

		// Create expected EM (Encoded Message) by combining hash limbs and prefix constants
		let prefix_wires = EXPECTED_PREFIX_LIMBS.map(|l| builder.add_constant_64(l));
		// The hash limbs need to be reversed because:
		// - SHA256 outputs hash[0] = bytes 0-7, hash[1] = bytes 8-15, etc.
		// - But in the EM, these bytes appear at the end (bytes 224-255)
		// - When EM is converted to little-endian limbs, the byte order within limbs reverses
		let expected_em = BigNum {
			limbs: expected_hash
				.limbs
				.iter()
				.copied()
				.rev()
				.chain(prefix_wires)
				.collect(),
		};

		assert_eq(builder, "mul_remainder_expected_em", &mul_remainder, &expected_em);

		Self {
			message,
			signature,
			modulus,
			square_quotients,
			square_remainders,
			mul_quotient,
			mul_remainder,
			sha256,
		}
	}

	/// Populate the RSA signature
	///
	/// # Arguments
	/// * `w` - Witness filler
	/// * `signature_bytes` - The bytes of an RSA signature
	///
	/// # Panics
	/// Panics if signature_bytes.len() != 256
	pub fn populate_signature(&self, w: &mut WitnessFiller, signature_bytes: &[u8]) {
		assert_eq!(signature_bytes.len(), 256, "signature must be exactly 256 bytes");
		self.signature.populate_bytes(w, signature_bytes);
	}

	/// Populate the message length
	///
	/// # Panics
	/// Panics if message_len > message.len() * 8
	pub fn populate_message_len(&self, w: &mut WitnessFiller, message_len: usize) {
		self.sha256.populate_len(w, message_len);
	}

	/// Populate the message
	///
	/// # Panics
	/// Panics if message.len() > self.message.len() * 8
	pub fn populate_message(&self, w: &mut WitnessFiller, message: &[u8]) {
		self.sha256.populate_message(w, message);
	}

	/// Populate the RSA modulus
	///
	/// # Panics
	/// Panics if modulus_bytes.len() != 256
	pub fn populate_modulus(&self, w: &mut WitnessFiller, modulus_bytes: &[u8]) {
		assert_eq!(modulus_bytes.len(), 256, "modulus must be exactly 256 bytes");
		self.modulus.populate_bytes(w, modulus_bytes);
	}

	/// Populate the square quotients for the 16 squaring operations
	///
	/// # Panics
	/// Panics if square_quotient_limbs.len() != 16 or if any quotient doesn't have 32 limbs.
	pub fn populate_square_quotients(
		&self,
		w: &mut WitnessFiller,
		square_quotient_limbs: &[Vec<u64>],
	) {
		assert_eq!(square_quotient_limbs.len(), 16, "must provide 16 square quotients");
		for (i, q_limbs) in square_quotient_limbs.iter().enumerate() {
			assert_eq!(
				q_limbs.len(),
				self.square_quotients[i].limbs.len(),
				"square_quotient[{i}] must have {} limbs",
				self.square_quotients[i].limbs.len()
			);
			self.square_quotients[i].populate_limbs(w, q_limbs);
		}
	}

	/// Populate the square remainders for the 16 squaring operations
	///
	/// # Panics
	/// Panics if square_remainder_limbs.len() != 16 or if any remainder doesn't have 32 limbs
	pub fn populate_square_remainders(
		&self,
		w: &mut WitnessFiller,
		square_remainder_limbs: &[Vec<u64>],
	) {
		assert_eq!(square_remainder_limbs.len(), 16, "must provide 16 square remainders");
		for (i, r_limbs) in square_remainder_limbs.iter().enumerate() {
			assert_eq!(r_limbs.len(), 32, "square_remainder[{i}] must have 32 limbs");
			self.square_remainders[i].populate_limbs(w, r_limbs);
		}
	}

	/// Populate the multiplication quotient
	///
	/// # Panics
	/// Panics if mul_quotient_limbs.len() != 32
	pub fn populate_mul_quotient(&self, w: &mut WitnessFiller, mul_quotient_limbs: &[u64]) {
		assert_eq!(
			mul_quotient_limbs.len(),
			self.mul_quotient.limbs.len(),
			"mul_quotient must have {} limbs",
			self.mul_quotient.limbs.len()
		);
		self.mul_quotient.populate_limbs(w, mul_quotient_limbs);
	}

	/// Populate the multiplication remainder (the EM - Encoded Message)
	///
	/// # Panics
	/// Panics if mul_remainder_limbs.len() != 32
	pub fn populate_mul_remainder(&self, w: &mut WitnessFiller, mul_remainder_limbs: &[u64]) {
		assert_eq!(mul_remainder_limbs.len(), 32, "mul_remainder must have 32 limbs");
		self.mul_remainder.populate_limbs(w, mul_remainder_limbs);
	}
}

/// Verify base^65537 mod modulus using provided intermediate values
fn modexp_65537_verify(
	builder: &CircuitBuilder,
	base: &BigNum,
	modulus: &BigNum,
	square_quotients: &[BigNum],
	square_remainders: &[BigNum],
	mul_quotient: &BigNum,
	mul_remainder: &BigNum,
) {
	let mut result = base.clone();

	for i in 0..16 {
		let builder = builder.subcircuit(format!("square[{i}]"));
		let squared = square(&builder, &result);
		let circuit = ModReduce::new(
			&builder,
			squared,
			modulus.clone(),
			square_quotients[i].clone(),
			square_remainders[i].clone(),
		);
		result = circuit.remainder;
	}

	let builder = builder.subcircuit("final_multiply");
	let multiplied = mul(&builder, &result, base);
	let _mod_reduce_multiplied = ModReduce::new(
		&builder,
		multiplied,
		modulus.clone(),
		mul_quotient.clone(),
		mul_remainder.clone(),
	);
}

pub struct RsaIntermediates {
	/// 16 vectors of quotient limbs from squaring operations
	pub square_quotients: Vec<Vec<u64>>,
	/// 16 vectors of remainder limbs (each 32 limbs) from squaring operations
	pub square_remainders: Vec<Vec<u64>>,
	/// Quotient limbs from final multiplication
	pub mul_quotient: Vec<u64>,
	/// Remainder limbs (32 limbs) from final multiplication
	pub mul_remainder: Vec<u64>,
}

impl RsaIntermediates {
	/// Compute RSA intermediate values for RS256 verification
	///
	/// This function computes the quotients and remainders needed for verifying
	/// RSA signatures with public exponent 65537 (2^16 + 1).
	///
	/// # Arguments
	/// * `signature` - The bytes of a RSA signature
	/// * `modulus_limbs` - The bytes of a RSA modulus
	///
	/// # Returns
	/// The `RsaIntermediates` computed during signature verification.
	///
	/// # Panics
	/// * If signature.len() != 256
	/// * If modulus.len() != 256
	pub fn new(signature: &[u8], modulus: &[u8]) -> Self {
		assert_eq!(signature.len(), 256, "signature must be exactly 256 bytes");
		assert_eq!(modulus.len(), 256, "modulus must be exactly 256 bytes");

		let signature_value = BigUint::from_bytes_be(signature);
		let modulus_value = BigUint::from_bytes_be(modulus);

		let mut square_quotients = Vec::new();
		let mut square_remainders = Vec::new();

		let mut result = signature_value.clone();
		for _ in 0..16 {
			let squared = &result * &result;
			let (q, r) = squared.div_rem(&modulus_value);

			let mut q_limbs = q.to_u64_digits();
			q_limbs.resize(32, 0u64);
			square_quotients.push(q_limbs);

			let mut r_limbs = r.to_u64_digits();
			r_limbs.resize(32, 0u64);
			square_remainders.push(r_limbs);

			result = r;
		}

		// Final multiplication
		let multiplied = &result * &signature_value;
		let (mul_q, mul_r) = multiplied.div_rem(&modulus_value);

		let mut mul_quotient = mul_q.to_u64_digits();
		mul_quotient.resize(32, 0u64);

		let mut mul_remainder = mul_r.to_u64_digits();
		mul_remainder.resize(32, 0u64);

		RsaIntermediates {
			square_quotients,
			square_remainders,
			mul_quotient,
			mul_remainder,
		}
	}
}

#[cfg(test)]
mod tests {
	use num_bigint::BigUint;
	use rand::{SeedableRng, rngs::StdRng};
	use rsa::{
		RsaPrivateKey, RsaPublicKey,
		pkcs1v15::SigningKey,
		sha2::{Digest, Sha256},
		signature::{SignatureEncoding, Signer},
		traits::{PrivateKeyParts, PublicKeyParts},
	};

	use super::*;
	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	fn populate_circuit(
		circuit: &Rs256Verify,
		w: &mut WitnessFiller,
		signature: &[u8],
		message: &[u8],
		modulus: &[u8],
	) {
		let intermediates = RsaIntermediates::new(signature, modulus);
		let hash = Sha256::digest(message);

		circuit.populate_signature(w, signature);
		circuit.populate_message_len(w, message.len());
		circuit.populate_message(w, message);
		circuit.sha256.populate_digest(w, hash.into());
		circuit.populate_modulus(w, modulus);
		circuit.populate_square_quotients(w, &intermediates.square_quotients);
		circuit.populate_square_remainders(w, &intermediates.square_remainders);
		circuit.populate_mul_quotient(w, &intermediates.mul_quotient);
		circuit.populate_mul_remainder(w, &intermediates.mul_remainder);
	}

	fn setup_circuit(builder: &mut CircuitBuilder, max_message_len: usize) -> Rs256Verify {
		let signature_bytes = FixedByteVec::new_inout(builder, 256);
		let modulus_bytes = FixedByteVec::new_inout(builder, 256);
		let message = FixedByteVec::new_witness(builder, max_message_len);

		let mut square_quotients = Vec::new();
		let mut square_remainders = Vec::new();
		for _ in 0..16 {
			square_quotients.push(BigNum::new_witness(builder, 32));
			square_remainders.push(BigNum::new_witness(builder, 32));
		}
		let mul_quotient = BigNum::new_witness(builder, 32);
		let mul_remainder = BigNum::new_witness(builder, 32);

		Rs256Verify::new(
			builder,
			message,
			signature_bytes,
			modulus_bytes,
			square_quotients,
			square_remainders,
			mul_quotient,
			mul_remainder,
		)
	}

	#[test]
	fn test_real_rsa_signature_verification_with_message() {
		let mut builder = CircuitBuilder::new();
		let circuit = setup_circuit(&mut builder, 256);
		let cs = builder.build();

		// Generate a real RSA signature as it would appear in a JWT
		let mut rng = StdRng::seed_from_u64(42);
		let bits = 2048;
		let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
		let public_key = RsaPublicKey::from(&private_key);
		let message = b"Test message for RS256 verification";

		let signing_key = SigningKey::<Sha256>::new(private_key);
		let signature = signing_key.sign(message);
		let signature_bytes = signature.to_bytes();
		let modulus_bytes = public_key.n().to_be_bytes();

		let mut w = cs.new_witness_filler();
		populate_circuit(&circuit, &mut w, &signature_bytes, message, &modulus_bytes);

		cs.populate_wire_witness(&mut w).unwrap();
		verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_real_rsa_signature_with_invalid_prefix() {
		let mut builder = CircuitBuilder::new();
		let max_message_len = 256;
		let circuit = setup_circuit(&mut builder, max_message_len);
		let cs = builder.build();

		let mut rng = StdRng::seed_from_u64(42);
		let bits = 2048;
		let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
		let public_key = RsaPublicKey::from(&private_key);

		let message = b"Test message for RS256 verification with invalid prefix";

		// Compute signature that would produce a corrupted EM
		// signature = EM^d mod n
		let corrupted_em = BigUint::ZERO;
		let d_bytes = private_key.d().to_le_bytes();
		let n_bytes = private_key.n().to_le_bytes();
		let d = BigUint::from_bytes_le(&d_bytes);
		let n = BigUint::from_bytes_le(&n_bytes);
		let corrupted_signature = corrupted_em.modpow(&d, &n);

		let mut signature_bytes = corrupted_signature.to_bytes_be();
		signature_bytes.resize(256, 0u8);
		let modulus_bytes = public_key.n().to_be_bytes();

		let mut w = cs.new_witness_filler();
		populate_circuit(&circuit, &mut w, &signature_bytes, message, &modulus_bytes);

		let result = cs.populate_wire_witness(&mut w);
		assert!(result.is_err(), "Circuit should fail when PKCS#1 v1.5 prefix is corrupted");
	}

	#[test]
	fn test_real_rsa_signature_verification_with_wrong_message() {
		let mut builder = CircuitBuilder::new();
		let max_message_len = 256;
		let circuit = setup_circuit(&mut builder, max_message_len);
		let cs = builder.build();

		let mut rng = StdRng::seed_from_u64(42);
		let bits = 2048;
		let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
		let public_key = RsaPublicKey::from(&private_key);

		let message = b"Test message for RS256 verification with wrong message";
		let signing_key = SigningKey::<Sha256>::new(private_key);
		let signature_obj = signing_key.sign(message);
		let signature_bytes = signature_obj.to_bytes();

		let signature_bytes = BigUint::from_bytes_be(signature_bytes.as_ref()).to_bytes_be();
		let modulus_bytes = public_key.n().to_be_bytes();

		// Use a WRONG message
		let wrong_message = b"This is a completely different message!";

		let mut w = cs.new_witness_filler();
		populate_circuit(&circuit, &mut w, &signature_bytes, wrong_message, &modulus_bytes);

		let result = cs.populate_wire_witness(&mut w);
		assert!(result.is_err(), "Circuit should fail when message doesn't match signature");
	}
}

//! Core RSA-2048 signature verification specialized for e=65537 (2^16 + 1).

use crate::{
	circuits::bignum::{BigNum, compare, mod_reduce, mul, square},
	compiler::{CircuitBuilder, WitnessFiller},
	word::Word,
};

/// RSA-2048 verification circuit specialized for e=65537.
///
/// ## RSA Signature Verification Algorithm
///
/// 1. Inputs:
///    - `signature`: The RSA signature to verify (2048 bits)
///    - `expected_hash`: The expected message digest
///    - `modulus`: The RSA modulus
///
/// 2. Compute `result = signature^65537 mod modulus`
///
/// 3. Assert `result == expected_hash`
pub struct Rsa2048Verify {
	pub signature: BigNum,
	pub expected_hash: BigNum,
	pub modulus: BigNum,
	/// Result of signature^65537 mod modulus
	pub result: BigNum,
}

impl Rsa2048Verify {
	/// Create a new RSA-2048 verification circuit for e=65537
	pub fn new(
		builder: &CircuitBuilder,
		signature: BigNum,
		expected_hash: BigNum,
		modulus: BigNum,
	) -> Self {
		assert_eq!(signature.limbs.len(), 32, "signature must be 32 limbs (2048 bits)");
		assert_eq!(expected_hash.limbs.len(), 32, "expected_hash must be 32 limbs (2048 bits)");
		assert_eq!(modulus.limbs.len(), 32, "modulus must be 32 limbs (2048 bits)");

		let result = modexp_65537(builder, &signature, &modulus);
		let eq = compare(builder, &result, &expected_hash);
		let all_ones = builder.add_constant(crate::word::Word::ALL_ONE);
		builder.assert_eq("rsa2048_verify", eq, all_ones);

		Self {
			signature,
			expected_hash,
			modulus,
			result,
		}
	}

	fn populate_bignum(&self, w: &mut WitnessFiller, bignum: &BigNum, value: &[u64]) {
		assert!(value.len() == bignum.limbs.len());
		for (&wire, &v) in bignum.limbs.iter().zip(value.iter()) {
			w[wire] = Word::from_u64(v);
		}
	}

	pub fn populate_signature(&self, w: &mut WitnessFiller, signature: &[u64]) {
		self.populate_bignum(w, &self.signature, signature);
	}

	pub fn populate_expected_hash(&self, w: &mut WitnessFiller, expected_hash: &[u64]) {
		self.populate_bignum(w, &self.expected_hash, expected_hash);
	}

	pub fn populate_modulus(&self, w: &mut WitnessFiller, modulus: &[u64]) {
		self.populate_bignum(w, &self.modulus, modulus);
	}
}

/// Compute base^65537 mod modulus using optimized square-and-multiply
fn modexp_65537(builder: &CircuitBuilder, base: &BigNum, modulus: &BigNum) -> BigNum {
	let mut result = base.clone();

	for i in 0..16 {
		let builder = builder.subcircuit(format!("square[{i}]"));
		let squared = square(&builder, &result);
		let (_, remainder) = mod_reduce(&builder, &squared, modulus);
		result = remainder;
	}

	let multiplied = mul(builder, &result, base);
	let (_, remainder) = mod_reduce(builder, &multiplied, modulus);

	remainder
}

#[cfg(test)]
mod tests {
	use num_bigint::BigUint;
	use num_traits::Num;

	use super::*;
	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	fn hex_to_biguint(hex: &str) -> BigUint {
		BigUint::from_str_radix(hex, 16).unwrap()
	}

	fn populate_circuit(
		circuit: Rsa2048Verify,
		w: &mut WitnessFiller,
		signature: &BigUint,
		expected_hash: &BigUint,
		modulus: &BigUint,
	) {
		let mut sig_limbs = signature.to_u64_digits();
		sig_limbs.resize(32, 0u64);

		let mut expected_hash_limbs = expected_hash.to_u64_digits();
		expected_hash_limbs.resize(32, 0u64);

		let mut modulus_limbs = modulus.to_u64_digits();
		modulus_limbs.resize(32, 0u64);

		circuit.populate_signature(w, &sig_limbs);
		circuit.populate_expected_hash(w, &expected_hash_limbs);
		circuit.populate_modulus(w, &modulus_limbs);
	}

	#[test]
	fn test_rsa2048_simple_witness() {
		let builder = CircuitBuilder::new();

		let signature = BigNum::new_inout(&builder, 32);
		let expected_hash = BigNum::new_inout(&builder, 32);
		let modulus = BigNum::new_inout(&builder, 32);

		let circuit = Rsa2048Verify::new(&builder, signature, expected_hash, modulus);

		let cs = builder.build();

		let mut w = cs.new_witness_filler();

		populate_circuit(
			circuit,
			&mut w,
			&BigUint::from(5u64),
			&BigUint::from(135u64),
			&BigUint::from(143u64),
		);

		cs.populate_wire_witness(&mut w).unwrap();
		verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap()
	}

	#[test]
	fn test_rsa2048_with_real_modulus() {
		let builder = CircuitBuilder::new();

		let signature = BigNum::new_inout(&builder, 32);
		let expected_hash = BigNum::new_inout(&builder, 32);
		let modulus = BigNum::new_inout(&builder, 32);

		let circuit = Rsa2048Verify::new(&builder, signature, expected_hash, modulus);

		let cs = builder.build();

		let modulus = hex_to_biguint(
			"a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
		);

		let sig = BigUint::from(0x987654321u64);
		let expected = sig.modpow(&BigUint::from(65537u32), &modulus);
		let mut w = cs.new_witness_filler();

		populate_circuit(circuit, &mut w, &sig, &expected, &modulus);

		cs.populate_wire_witness(&mut w).unwrap();
		verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap()
	}

	#[test]
	fn test_rsa2048_invalid_signature() {
		let builder = CircuitBuilder::new();

		let signature = BigNum::new_inout(&builder, 32);
		let expected_hash = BigNum::new_inout(&builder, 32);
		let modulus = BigNum::new_inout(&builder, 32);

		let circuit = Rsa2048Verify::new(&builder, signature, expected_hash, modulus);

		let cs = builder.build();

		let mut w = cs.new_witness_filler();

		populate_circuit(
			circuit,
			&mut w,
			&BigUint::from(0u64),
			&BigUint::from(100u64),
			&BigUint::from(143u64),
		);
		let result = cs.populate_wire_witness(&mut w);
		assert!(result.is_err(), "Witness population should fail for invalid signature");
	}
}

//! GHASH multiplication circuit implementation.
//!
//! GHASH multiplication is used in AES-GCM for authentication. It performs
//! multiplication in GF(2^128) using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
//!
//! The multiplication consists of:
//! 1. 128-bit carryless multiplication (using four 64x64 carryless muls)
//! 2. Reduction modulo the GHASH irreducible polynomial

use binius_core::word::Word;

use crate::{
	circuits::carryless_word_mul::CarrylessMul,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};

/// GHASH multiplication circuit for 128-bit operands.
///
/// Performs multiplication in GF(2^128) using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
/// Input operands are represented as [low, high] where low is bits 0-63 and high is bits 64-127.
pub struct GhashMul {
	/// First operand: [a_lo, a_hi] representing 128-bit value a
	pub a: [Wire; 2],
	/// Second operand: [b_lo, b_hi] representing 128-bit value b  
	pub b: [Wire; 2],
	/// Result: [result_lo, result_hi] representing 128-bit product in GF(2^128)
	pub result: [Wire; 2],

	/// Internal carryless multiplication circuits
	carryless_muls: [CarrylessMul; 4],
}

impl GhashMul {
	/// Creates a new GHASH multiplication circuit.
	///
	/// Constrains that a * b = result in GF(2^128) with irreducible polynomial x^128 + x^7 + x^2 +
	/// x + 1.
	pub fn new(builder: &CircuitBuilder, a: [Wire; 2], b: [Wire; 2]) -> Self {
		let result = [builder.add_witness(), builder.add_witness()];

		// Perform 128x128 carryless multiplication using four 64x64 multiplications:
		// a = a_hi * 2^64 + a_lo
		// b = b_hi * 2^64 + b_lo
		// a * b = a_hi * b_hi * 2^128 + (a_hi * b_lo + a_lo * b_hi) * 2^64 + a_lo * b_lo

		let mul_lo_lo = CarrylessMul::new(builder, a[0], b[0]); // a_lo * b_lo
		let mul_lo_hi = CarrylessMul::new(builder, a[0], b[1]); // a_lo * b_hi
		let mul_hi_lo = CarrylessMul::new(builder, a[1], b[0]); // a_hi * b_lo
		let mul_hi_hi = CarrylessMul::new(builder, a[1], b[1]); // a_hi * b_hi

		let carryless_muls = [mul_lo_lo, mul_lo_hi, mul_hi_lo, mul_hi_hi];

		// Combine the partial products and reduce
		Self::constrain_ghash_reduction(builder, &carryless_muls, result);

		Self {
			a,
			b,
			result,
			carryless_muls,
		}
	}

	/// Constrains the GHASH reduction step after 128x128 carryless multiplication.
	fn constrain_ghash_reduction(
		builder: &CircuitBuilder,
		muls: &[CarrylessMul; 4],
		result: [Wire; 2],
	) {
		// Combine partial products into 256-bit intermediate result
		// prod = muls[3].hi:muls[3].lo:0:0 + 0:muls[2].hi:muls[2].lo:0 + 0:muls[1].hi:muls[1].lo:0
		// + 0:0:muls[0].hi:muls[0].lo      = muls[3] * 2^128 + (muls[2] + muls[1]) * 2^64 +
		// muls[0]

		// Word 0 (bits 0-63): muls[0].lo
		let word0 = muls[0].lo;

		// Word 1 (bits 64-127): muls[0].hi XOR muls[1].lo XOR muls[2].lo
		let word1 = builder.bxor(builder.bxor(muls[0].hi, muls[1].lo), muls[2].lo);

		// Word 2 (bits 128-191): muls[1].hi XOR muls[2].hi XOR muls[3].lo
		let word2 = builder.bxor(builder.bxor(muls[1].hi, muls[2].hi), muls[3].lo);

		// Word 3 (bits 192-255): muls[3].hi
		let word3 = muls[3].hi;

		// Reduce modulo x^128 + x^7 + x^2 + x + 1
		// For any term x^i where i >= 128, replace with x^(i-128) * (x^7 + x^2 + x + 1)
		Self::constrain_poly_reduction(builder, [word0, word1, word2, word3], result);
	}

	/// Reduces 256-bit polynomial modulo x^128 + x^7 + x^2 + x + 1.
	fn constrain_poly_reduction(
		builder: &CircuitBuilder,
		unreduced: [Wire; 4], // [w0, w1, w2, w3] representing sum_{i=0}^3 w_i * x^(64*i)
		result: [Wire; 2],
	) {
		// The irreducible polynomial is x^128 + x^7 + x^2 + x + 1
		// So x^128 ≡ x^7 + x^2 + x + 1 (mod irreducible)
		//
		// For reduction, any bit at position 128+k gets replaced by bits at positions k+7, k+2,
		// k+1, k We need to process words 2 and 3 (positions 128-255) and reduce them to affect
		// words 0 and 1

		// Start with the low 128 bits
		let mut result_lo = unreduced[0]; // bits 0-63
		let mut result_hi = unreduced[1]; // bits 64-127

		// Reduce word 2 (bits 128-191)
		// Each bit at position 128+k contributes to positions k+7, k+2, k+1, k
		for k in 0..64 {
			let bit_mask = builder.add_constant(Word(1u64 << k));
			let bit_value = builder.band(unreduced[2], bit_mask);
			let bit_is_one = builder.icmp_eq(bit_value, bit_mask);

			// Add contributions to result positions k+7, k+2, k+1, k
			for &offset in &[7, 2, 1, 0] {
				let target_pos = k + offset;
				if target_pos < 64 {
					// Affects result_lo
					let contribution_mask = builder.add_constant(Word(1u64 << target_pos));
					let contribution = builder.band(contribution_mask, bit_is_one);
					result_lo = builder.bxor(result_lo, contribution);
				} else if target_pos < 128 {
					// Affects result_hi
					let contribution_mask = builder.add_constant(Word(1u64 << (target_pos - 64)));
					let contribution = builder.band(contribution_mask, bit_is_one);
					result_hi = builder.bxor(result_hi, contribution);
				}
			}
		}

		// Reduce word 3 (bits 192-255)
		// Each bit at position 192+k = 128+(64+k) contributes to positions (64+k)+7, (64+k)+2,
		// (64+k)+1, (64+k)
		for k in 0..64 {
			let bit_mask = builder.add_constant(Word(1u64 << k));
			let bit_value = builder.band(unreduced[3], bit_mask);
			let bit_is_one = builder.icmp_eq(bit_value, bit_mask);

			// Add contributions to result positions (64+k)+7, (64+k)+2, (64+k)+1, (64+k)
			for &offset in &[7, 2, 1, 0] {
				let target_pos = 64 + k + offset;
				if target_pos < 64 {
					// This shouldn't happen for word 3, but keep for completeness
					let contribution_mask = builder.add_constant(Word(1u64 << target_pos));
					let contribution = builder.band(contribution_mask, bit_is_one);
					result_lo = builder.bxor(result_lo, contribution);
				} else if target_pos < 128 {
					// Affects result_hi
					let contribution_mask = builder.add_constant(Word(1u64 << (target_pos - 64)));
					let contribution = builder.band(contribution_mask, bit_is_one);
					result_hi = builder.bxor(result_hi, contribution);
				} else {
					// target_pos >= 128, need to reduce again
					// This creates x^(target_pos) ≡ x^(target_pos-128) * (x^7 + x^2 + x + 1)
					let reduced_pos = target_pos - 128;
					for &second_offset in &[7, 2, 1, 0] {
						let final_pos = reduced_pos + second_offset;
						if final_pos < 64 {
							let contribution_mask = builder.add_constant(Word(1u64 << final_pos));
							let contribution = builder.band(contribution_mask, bit_is_one);
							result_lo = builder.bxor(result_lo, contribution);
						} else if final_pos < 128 {
							let contribution_mask =
								builder.add_constant(Word(1u64 << (final_pos - 64)));
							let contribution = builder.band(contribution_mask, bit_is_one);
							result_hi = builder.bxor(result_hi, contribution);
						}
					}
				}
			}
		}

		// Assert final result
		builder.assert_eq("ghash_result_lo", result_lo, result[0]);
		builder.assert_eq("ghash_result_hi", result_hi, result[1]);
	}

	/// Populates the witness with input values and computes the GHASH multiplication result.
	pub fn populate(&mut self, w: &mut WitnessFiller, a_val: [u64; 2], b_val: [u64; 2]) {
		// Set inputs
		w[self.a[0]] = Word(a_val[0]);
		w[self.a[1]] = Word(a_val[1]);
		w[self.b[0]] = Word(b_val[0]);
		w[self.b[1]] = Word(b_val[1]);

		// Populate carryless multiplications
		self.carryless_muls[0].populate(w, a_val[0], b_val[0]); // a_lo * b_lo
		self.carryless_muls[1].populate(w, a_val[0], b_val[1]); // a_lo * b_hi
		self.carryless_muls[2].populate(w, a_val[1], b_val[0]); // a_hi * b_lo
		self.carryless_muls[3].populate(w, a_val[1], b_val[1]); // a_hi * b_hi

		// Compute GHASH multiplication result
		let result = ghash_mul_u128(a_val, b_val);
		w[self.result[0]] = Word(result[0]);
		w[self.result[1]] = Word(result[1]);
	}
}

/// Software implementation of GHASH multiplication in GF(2^128).
/// Uses the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
pub fn ghash_mul_u128(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
	// Perform 128x128 carryless multiplication to get 256-bit result
	let mut result = [0u64; 4];

	// a_lo * b_lo
	let (lo_lo_lo, lo_lo_hi) = carryless_mul_u64(a[0], b[0]);
	result[0] ^= lo_lo_lo;
	result[1] ^= lo_lo_hi;

	// a_lo * b_hi
	let (lo_hi_lo, lo_hi_hi) = carryless_mul_u64(a[0], b[1]);
	result[1] ^= lo_hi_lo;
	result[2] ^= lo_hi_hi;

	// a_hi * b_lo
	let (hi_lo_lo, hi_lo_hi) = carryless_mul_u64(a[1], b[0]);
	result[1] ^= hi_lo_lo;
	result[2] ^= hi_lo_hi;

	// a_hi * b_hi
	let (hi_hi_lo, hi_hi_hi) = carryless_mul_u64(a[1], b[1]);
	result[2] ^= hi_hi_lo;
	result[3] ^= hi_hi_hi;

	// Reduce modulo x^128 + x^7 + x^2 + x + 1
	ghash_reduce_256_to_128(result)
}

/// Software implementation of 64x64 carryless multiplication.
fn carryless_mul_u64(a: u64, b: u64) -> (u64, u64) {
	let mut lo = 0u64;
	let mut hi = 0u64;

	for i in 0..64 {
		if (b >> i) & 1 == 1 {
			lo ^= a << i;
			if i > 0 {
				hi ^= a >> (64 - i);
			}
		}
	}

	(lo, hi)
}

/// Reduces a 256-bit value modulo the GHASH irreducible polynomial x^128 + x^7 + x^2 + x + 1.
fn ghash_reduce_256_to_128(unreduced: [u64; 4]) -> [u64; 2] {
	let mut result = [unreduced[0], unreduced[1]];

	// Reduce words 2 and 3 (bits 128-255)
	// For each bit at position 128+k, add contributions at positions k+7, k+2, k+1, k
	for word_idx in 2..4 {
		let word = unreduced[word_idx];
		let base_bit_pos = 64 * (word_idx - 2); // 0 for word 2, 64 for word 3

		for k in 0..64 {
			if (word >> k) & 1 == 1 {
				// Bit is set at position 128 + base_bit_pos + k
				// Add contributions at positions base_bit_pos + k + offset for each offset
				for &offset in &[7, 2, 1, 0] {
					let target_pos = base_bit_pos + k + offset;
					if target_pos < 64 {
						result[0] ^= 1u64 << target_pos;
					} else if target_pos < 128 {
						result[1] ^= 1u64 << (target_pos - 64);
					} else {
						// Need second level reduction for positions >= 128
						let reduced_pos = target_pos - 128;
						for &second_offset in &[7, 2, 1, 0] {
							let final_pos = reduced_pos + second_offset;
							if final_pos < 64 {
								result[0] ^= 1u64 << final_pos;
							} else if final_pos < 128 {
								result[1] ^= 1u64 << (final_pos - 64);
							}
						}
					}
				}
			}
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_ghash_properties() {
		let mut rng = StdRng::seed_from_u64(0);
		let zero = [0u64, 0u64];
		let one = [1u64, 0u64];
		let a = [rng.random::<u64>(), rng.random::<u64>()];
		let b = [rng.random::<u64>(), rng.random::<u64>()];

		// Test field properties
		assert_eq!(ghash_mul_u128(a, zero), zero);
		assert_eq!(ghash_mul_u128(a, one), a);
		assert_eq!(ghash_mul_u128(a, b), ghash_mul_u128(b, a));
	}

	#[test]
	fn test_carryless_mul_correctness() {
		let mut rng = StdRng::seed_from_u64(0);
		let a = rng.random::<u64>();
		let b = rng.random::<u64>();
		let (lo, hi) = carryless_mul_u64(a, b);

		// Verify against reference implementation
		let mut expected = 0u128;
		for i in 0..64 {
			if (b >> i) & 1 == 1 {
				expected ^= (a as u128) << i;
			}
		}
		assert_eq!((lo, hi), (expected as u64, (expected >> 64) as u64));
	}

	#[test]
	fn test_ghash_reduction() {
		// Test x^192 reduction: x^192 ≡ x^71 + x^66 + x^65 + x^64
		let unreduced = [0u64, 0u64, 0u64, 1u64];
		let reduced = ghash_reduce_256_to_128(unreduced);
		let expected = [0u64, (1u64 << 7) ^ (1u64 << 2) ^ (1u64 << 1) ^ 1u64];
		assert_eq!(reduced, expected);
	}

	#[test]
	fn test_ghash_circuit() {
		let mut rng = StdRng::seed_from_u64(0);
		let builder = CircuitBuilder::new();
		let a = [builder.add_witness(), builder.add_witness()];
		let b = [builder.add_witness(), builder.add_witness()];
		let mut ghash_circuit = GhashMul::new(&builder, a, b);
		let circuit = builder.build();

		let a_val = [rng.random::<u64>(), rng.random::<u64>()];
		let b_val = [rng.random::<u64>(), rng.random::<u64>()];

		let mut witness = circuit.new_witness_filler();
		ghash_circuit.populate(&mut witness, a_val, b_val);
		circuit.populate_wire_witness(&mut witness).unwrap();

		verify_constraints(circuit.constraint_system(), &witness.into_value_vec()).unwrap();
	}
}

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
	circuits::carryless_word_mul::{carryless_mul, carryless_mul_u64},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::bool_to_mask,
};

/// Creates a GHASH multiplication circuit.
///
/// Performs multiplication in GF(2^128): a * b = result using irreducible polynomial x^128 + x^7 +
/// x^2 + x + 1. Input operands are represented as [low, high] where low is bits 0-63 and high is
/// bits 64-127.
///
/// # Parameters
/// * `builder` - Circuit builder for creating constraints
/// * `a` - First 128-bit operand as [a_lo, a_hi]
/// * `b` - Second 128-bit operand as [b_lo, b_hi]
///
/// # Returns
/// `result` - 128-bit result as [result_lo, result_hi]
pub fn ghash_mul(builder: &CircuitBuilder, a: [Wire; 2], b: [Wire; 2]) -> [Wire; 2] {
	// Perform 128x128 carryless multiplication using four 64x64 multiplications:
	// a = a_hi * 2^64 + a_lo
	// b = b_hi * 2^64 + b_lo
	// a * b = a_hi * b_hi * 2^128 + (a_hi * b_lo + a_lo * b_hi) * 2^64 + a_lo * b_lo

	let carryless_mul_outputs = [(0, 0), (0, 1), (1, 0), (1, 1)]
		.map(|(a_idx, b_idx)| carryless_mul(builder, a[a_idx], b[b_idx]));

	// Combine the partial products and reduce
	constrain_ghash_reduction(builder, &carryless_mul_outputs)
}

/// Constrains the GHASH reduction step after 128x128 carryless multiplication.
fn constrain_ghash_reduction(
	builder: &CircuitBuilder,
	muls: &[(Wire, Wire); 4], // [(lo, hi); 4]
) -> [Wire; 2] {
	// Combine 4x 128-bit partial products into 256-bit result
	// muls[i] = a[i] * b[j] where i,j ∈ {0,1}
	let word0 = muls[0].0; // a[0]*b[0] low
	let word1 = builder.bxor(builder.bxor(muls[0].1, muls[1].0), muls[2].0); // overlapping middle terms
	let word2 = builder.bxor(builder.bxor(muls[1].1, muls[2].1), muls[3].0); // overlapping high terms  
	let word3 = muls[3].1; // a[1]*b[1] high

	// Reduce modulo x^128 + x^7 + x^2 + x + 1
	// For any term x^i where i >= 128, replace with x^(i-128) * (x^7 + x^2 + x + 1)
	constrain_poly_reduction(builder, [word0, word1, word2, word3])
}

/// Reduces 256-bit polynomial modulo x^128 + x^7 + x^2 + x + 1.
fn constrain_poly_reduction(
	builder: &CircuitBuilder,
	unreduced: [Wire; 4], // [w0, w1, w2, w3] representing sum_{i=0}^3 w_i * x^(64*i)
) -> [Wire; 2] {
	// Reduce modulo x^128 + x^7 + x^2 + x + 1
	// Each bit at position 128+k becomes bits at positions k+7, k+2, k+1, k

	// Start with the low 128 bits
	let mut result_lo = unreduced[0]; // bits 0-63
	let mut result_hi = unreduced[1]; // bits 64-127

	// Reduce word 2 (bits 128-191)
	for k in 0..64 {
		let bit_is_one_mask = bool_to_mask(builder, builder.shl(unreduced[2], (63 - k) as u32));

		// Apply reduction: bit at 128+k → bits at k+7, k+2, k+1, k
		for &offset in &[7, 2, 1, 0] {
			let target_pos = k + offset;
			if target_pos < 64 {
				// Affects result_lo
				let contribution_mask = builder.add_constant(Word(1u64 << target_pos));
				let contribution = builder.band(contribution_mask, bit_is_one_mask);
				result_lo = builder.bxor(result_lo, contribution);
			} else if target_pos < 128 {
				// Affects result_hi
				let contribution_mask = builder.add_constant(Word(1u64 << (target_pos - 64)));
				let contribution = builder.band(contribution_mask, bit_is_one_mask);
				result_hi = builder.bxor(result_hi, contribution);
			}
		}
	}

	// Reduce word 3 (bits 192-255)
	for k in 0..64 {
		let bit_is_one_mask = bool_to_mask(builder, builder.shl(unreduced[3], (63 - k) as u32));

		// Apply reduction: bit at 192+k → bits at 64+k+7, 64+k+2, 64+k+1, 64+k
		for &offset in &[7, 2, 1, 0] {
			let target_pos = 64 + k + offset;
			if target_pos < 128 {
				// Affects result_hi
				let contribution_mask = builder.add_constant(Word(1u64 << (target_pos - 64)));
				let contribution = builder.band(contribution_mask, bit_is_one_mask);
				result_hi = builder.bxor(result_hi, contribution);
			} else {
				// Need second reduction for positions >= 128
				let reduced_pos = target_pos - 128;
				for &second_offset in &[7, 2, 1, 0] {
					let final_pos = reduced_pos + second_offset;
					if final_pos < 64 {
						let contribution_mask = builder.add_constant(Word(1u64 << final_pos));
						let contribution = builder.band(contribution_mask, bit_is_one_mask);
						result_lo = builder.bxor(result_lo, contribution);
					} else if final_pos < 128 {
						let contribution_mask =
							builder.add_constant(Word(1u64 << (final_pos - 64)));
						let contribution = builder.band(contribution_mask, bit_is_one_mask);
						result_hi = builder.bxor(result_hi, contribution);
					}
				}
			}
		}
	}

	[result_lo, result_hi]
}

/// Populates witness values for GHASH multiplication output wires.
///
/// # Parameters
/// * `w` - Witness filler to populate
/// * `result` - Result wires from `ghash_mul` (128-bit result as [result_lo, result_hi])
/// * `a_val` - Value for first operand [a_lo, a_hi]
/// * `b_val` - Value for second operand [b_lo, b_hi]
pub fn populate_ghash_mul_outputs(
	w: &mut WitnessFiller,
	result: [Wire; 2],
	a_val: [u64; 2],
	b_val: [u64; 2],
) {
	// Compute GHASH multiplication result
	let result_val = ghash_mul_u128(a_val, b_val);
	w[result[0]] = Word(result_val[0]);
	w[result[1]] = Word(result_val[1]);
}

/// Software implementation of GHASH multiplication in GF(2^128).
/// Uses the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
pub fn ghash_mul_u128(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
	// Perform 128x128 carryless multiplication to get 256-bit result
	let mut result = [0u64; 4];

	// Perform four 64x64 carryless multiplications and accumulate results
	for (a_idx, b_idx, lo_pos, hi_pos) in [(0, 0, 0, 1), (0, 1, 1, 2), (1, 0, 1, 2), (1, 1, 2, 3)] {
		let (lo, hi) = carryless_mul_u64(a[a_idx], b[b_idx]);
		result[lo_pos] ^= lo;
		result[hi_pos] ^= hi;
	}

	// Reduce modulo x^128 + x^7 + x^2 + x + 1
	ghash_reduce_256_to_128(result)
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
		let result = ghash_mul(&builder, a, b);
		let circuit = builder.build();

		let a_val = [rng.random::<u64>(), rng.random::<u64>()];
		let b_val = [rng.random::<u64>(), rng.random::<u64>()];

		let mut witness = circuit.new_witness_filler();
		witness[a[0]] = Word(a_val[0]);
		witness[a[1]] = Word(a_val[1]);
		witness[b[0]] = Word(b_val[0]);
		witness[b[1]] = Word(b_val[1]);

		populate_ghash_mul_outputs(&mut witness, result, a_val, b_val);
		circuit.populate_wire_witness(&mut witness).unwrap();

		verify_constraints(circuit.constraint_system(), &witness.into_value_vec()).unwrap();
	}
}

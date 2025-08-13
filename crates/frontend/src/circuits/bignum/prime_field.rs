use binius_core::{consts::WORD_SIZE_BITS, word::Word};

use super::{BigUint, PseudoMersenneModReduce, add, biguint_lt, mul, square, sub};
use crate::{compiler::CircuitBuilder, util::num_biguint_from_u64_limbs};

pub struct PseudoMersennePrimeField {
	modulus: BigUint,
	modulus_po2: usize,
	modulus_subtrahend: BigUint,
}

impl PseudoMersennePrimeField {
	pub fn new(b: &CircuitBuilder, modulus_po2: usize, modulus_subtrahend: &[u64]) -> Self {
		let modulus_subtrahend = num_biguint_from_u64_limbs(modulus_subtrahend);
		let po2 = num_bigint::BigUint::from(2usize).pow(modulus_po2 as u32);
		assert!(po2 > modulus_subtrahend, "2^modulus_po2 - modulus_subtrahend > 0");

		let modulus = BigUint::new_constant(b, &(po2 - &modulus_subtrahend));
		let modulus_subtrahend = BigUint::new_constant(b, &modulus_subtrahend);

		Self {
			modulus,
			modulus_po2,
			modulus_subtrahend,
		}
	}

	pub fn limbs_len(&self) -> usize {
		self.modulus.limbs.len()
	}

	pub fn add(&self, b: &CircuitBuilder, fe1: &BigUint, fe2: &BigUint) -> BigUint {
		let l = self.limbs_len();
		assert!(fe1.limbs.len() == l && fe2.limbs.len() == l);

		let zero = b.add_constant(Word::ZERO);

		let extra_limbs = if self.modulus_po2 + 1 > l * WORD_SIZE_BITS {
			1
		} else {
			0
		};

		let fe1 = fe1.pad_limbs_to(l + extra_limbs, zero);
		let fe2 = fe2.pad_limbs_to(l + extra_limbs, zero);
		let modulus = self.modulus.pad_limbs_to(l + extra_limbs, zero);

		let unreduced_sum = add(b, &fe1, &fe2);
		// TODO: consider nondeterminism
		let need_reduction = b.bnot(biguint_lt(b, &unreduced_sum, &modulus));
		let reduced = sub(b, &unreduced_sum, &modulus.mask(b, need_reduction));

		let (result, _) = reduced.split_at_limbs(l);
		result
	}

	pub fn sub(&self, b: &CircuitBuilder, fe1: &BigUint, fe2: &BigUint) -> BigUint {
		assert!(fe1.limbs.len() == self.limbs_len() && fe2.limbs.len() == self.limbs_len());
		let fe2_add_inv = sub(b, &self.modulus, fe2);
		self.add(b, fe1, &fe2_add_inv)
	}

	pub fn square(&self, b: &CircuitBuilder, fe: &BigUint) -> BigUint {
		assert!(fe.limbs.len() == self.limbs_len());
		self.reduce_product(b, square(b, fe))
	}

	pub fn mul(&self, b: &CircuitBuilder, fe1: &BigUint, fe2: &BigUint) -> BigUint {
		assert!(fe1.limbs.len() == self.limbs_len() && fe2.limbs.len() == self.limbs_len());
		self.reduce_product(b, mul(b, fe1, fe2))
	}

	fn reduce_product(&self, b: &CircuitBuilder, product: BigUint) -> BigUint {
		let (quotient, remainder) = b.biguint_divide_hint(&product.limbs, &self.modulus.limbs);

		let zero = b.add_constant(Word::ZERO);

		let quotient = BigUint { limbs: quotient };
		let remainder = BigUint { limbs: remainder }.pad_limbs_to(self.limbs_len(), zero);

		// TODO: replace with assert_true once available
		b.assert_0("remainder < modulus", b.bnot(biguint_lt(b, &remainder, &self.modulus)));

		let _ = PseudoMersenneModReduce::new(
			b,
			product,
			self.modulus_po2,
			self.modulus_subtrahend.clone(),
			quotient,
			remainder.clone(),
		);

		remainder
	}
}

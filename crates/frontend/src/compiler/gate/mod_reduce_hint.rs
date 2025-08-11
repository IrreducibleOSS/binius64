//! BigUint modular reduction
//!
//! Returns `dividend % modulus`, numbers represented by little-endian arrays of 64-bit limbs.
//!
//! Shape is determined by number of limbs in `dividend` and `modulus`.
//! There are `dividend.len() + modulus.len()` inputs and `modulus.len()` outputs.
//!
//! # Algorithm
//!
//! Performs the long division. Returns zero in case of division by zero.
//!
//! # Constraints
//!
//! No constraints are generated! This is a hint - a deterministic computation that happens only
//! on the prover side. The result should be additionally constrained by checking that
//! `remainder + modulus * divisor == dividend` using bignum circuits.

use binius_core::word::Word;

use crate::{
	compiler::{
		circuit,
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	util::num_biguint_from_wires,
};

pub fn shape(dimensions: &[usize]) -> OpcodeShape {
	let [dividend_limbs_len, modulus_limbs_len] = dimensions else {
		unreachable!()
	};
	OpcodeShape {
		const_in: &[],
		n_in: *dividend_limbs_len + *modulus_limbs_len,
		n_out: *modulus_limbs_len,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [dividend_limbs_len, modulus_limbs_len] = data.dimensions.as_slice() else {
		unreachable!()
	};
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	assert_eq!(inputs.len(), *dividend_limbs_len + *modulus_limbs_len);
	assert_eq!(outputs.len(), *modulus_limbs_len);

	let (dividend_limbs, modulus_limbs) = inputs.split_at(*dividend_limbs_len);

	let dividend = num_biguint_from_wires(w, dividend_limbs);
	let modulus = num_biguint_from_wires(w, modulus_limbs);

	let zero = num_bigint::BigUint::ZERO;
	let remainder = if modulus != zero {
		dividend % modulus
	} else {
		zero
	};
	let remainder_limbs = remainder.iter_u64_digits();

	for dest in &outputs[remainder_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for (dest, limb) in outputs.iter().zip(remainder_limbs) {
		w[*dest] = Word(limb);
	}
}

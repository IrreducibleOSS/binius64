//! BigUint modular inverse
//!
//! Given `base` and `modulus` represented by little-endian arrays of 64-bit limbs returns
//! `(quotient, inverse)` such as `base * inverse = 1 + quotient * modulus`.
//! If `base` and `modulus` are not coprime then both `quotient` and `inverse` are set to zero.
//!
//! Shape is determined by number of limbs in `base` and `modulus`.
//! There are `base.len() + modulus.len()` inputs and `2 * modulus.len()` outputs.
//!
//! # Algorithm
//!
//! Performs the extended Euclidean algorithm.
//!
//! # Constraints
//!
//! No constraints are generated! This is a hint - a deterministic computation that happens only
//! on the prover side. The result should be additionally constrained by checking that
//! `base * inverse = 1 + quotient * modulus` using bignum circuits.

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
	let [base_limbs_len, modulus_limbs_len] = dimensions else {
		unreachable!()
	};
	OpcodeShape {
		const_in: &[],
		n_in: *base_limbs_len + *modulus_limbs_len,
		n_out: 2 * *modulus_limbs_len,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [base_limbs_len, modulus_limbs_len] = data.dimensions.as_slice() else {
		unreachable!()
	};
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	assert_eq!(inputs.len(), *base_limbs_len + *modulus_limbs_len);
	assert_eq!(outputs.len(), 2 * *modulus_limbs_len);

	let (base_limbs, modulus_limbs) = inputs.split_at(*base_limbs_len);
	let (quotient_wires, inverse_wires) = outputs.split_at(*modulus_limbs_len);

	let base = num_biguint_from_wires(w, base_limbs);
	let modulus = num_biguint_from_wires(w, modulus_limbs);

	let zero = num_bigint::BigUint::ZERO;
	let (quotient, inverse) = if let Some(inverse) = base.modinv(&modulus) {
		let quotient = (base * &inverse - num_bigint::BigUint::from(1usize)) / &modulus;
		(quotient, inverse)
	} else {
		(zero.clone(), zero)
	};

	let quotient_limbs = quotient.iter_u64_digits();
	let inverse_limbs = inverse.iter_u64_digits();

	for dest in &inverse_wires[inverse_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for dest in &quotient_wires[quotient_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for (dest, limb) in inverse_wires.iter().zip(inverse_limbs) {
		w[*dest] = Word(limb);
	}

	for (dest, limb) in quotient_wires.iter().zip(quotient_limbs) {
		w[*dest] = Word(limb);
	}
}

//! BigUint modular inverse
//!
//! Given `base` and `modulus` represented by little-endian arrays of 64-bit limbs returns
//! `inverse` such as `base * inverse = 1 (mod modulus)`. If `base` and `modulus` are not coprime
//! then `inverse` is set to zero.
//!
//! Shape is determined by number of limbs in `base` and `modulus`.
//! There are `base.len() + modulus.len()` inputs and `modulus.len()` outputs.
//!
//! # Algorithm
//!
//! Performs the extended Euclidean algorithm. Returns zero when base and modulus are not coprime.
//!
//! # Constraints
//!
//! No constraints are generated! This is a hint - a deterministic computation that happens only
//! on the prover side. The result should be additionally constrained by checking that
//! `base * inverse = 1 (mod modulus)` using bignum circuits.

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
		n_out: *modulus_limbs_len,
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
	assert_eq!(outputs.len(), *modulus_limbs_len);

	let (base_limbs, modulus_limbs) = inputs.split_at(*base_limbs_len);

	let base = num_biguint_from_wires(w, base_limbs);
	let modulus = num_biguint_from_wires(w, modulus_limbs);

	let zero = num_bigint::BigUint::ZERO;
	let inverse = base.modinv(&modulus).unwrap_or(zero);
	let inverse_limbs = inverse.iter_u64_digits();

	for dest in &outputs[inverse_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for (dest, limb) in outputs.iter().zip(inverse_limbs) {
		w[*dest] = Word(limb);
	}
}

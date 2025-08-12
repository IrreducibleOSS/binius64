//! BigUint division.
//!
//! Given `dividend` and `divisor`, returns `(quotient, remainder)`, numbers represented
//! by little-endian arrays of 64-bit limbs. It holds that `quotient.len() == dividend.len()`
//! and `remainder.len() == divisor.len()`.
//!
//! Shape is determined by the number of limbs in `dividend` and `divisor`.
//! There are `dividend.len() + divisor.len()` inputs & outputs.
//!
//! # Algorithm
//!
//! Performs the long division. Returns zero quotient & remainder in case of division by zero.
//!
//! # Constraints
//!
//! No constraints are generated! This is a hint - a deterministic computation that happens only
//! on the prover side. The result should be additionally constrained by checking that
//! `remainder + divisor * quotient == dividend` using bignum circuits.

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
	let [dividend_limbs_len, divisor_limbs_len] = dimensions else {
		unreachable!()
	};
	OpcodeShape {
		const_in: &[],
		n_in: *dividend_limbs_len + *divisor_limbs_len,
		n_out: *dividend_limbs_len + *divisor_limbs_len,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [dividend_limbs_len, divisor_limbs_len] = data.dimensions.as_slice() else {
		unreachable!()
	};
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	assert_eq!(inputs.len(), *dividend_limbs_len + *divisor_limbs_len);
	assert_eq!(outputs.len(), *dividend_limbs_len + *divisor_limbs_len);

	let (dividend_limbs, divisor_limbs) = inputs.split_at(*dividend_limbs_len);
	let (quotient_wires, remainder_wires) = outputs.split_at(*dividend_limbs_len);

	let dividend = num_biguint_from_wires(w, dividend_limbs);
	let divisor = num_biguint_from_wires(w, divisor_limbs);

	let zero = num_bigint::BigUint::ZERO;
	let (quotient, remainder) = if divisor != zero {
		(&dividend / &divisor, dividend % divisor)
	} else {
		(zero.clone(), zero)
	};

	let quotient_limbs = quotient.iter_u64_digits();
	let remainder_limbs = remainder.iter_u64_digits();

	for dest in &remainder_wires[remainder_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for dest in &quotient_wires[quotient_limbs.len()..] {
		w[*dest] = Word::ZERO;
	}

	for (dest, limb) in remainder_wires.iter().zip(remainder_limbs) {
		w[*dest] = Word(limb);
	}

	for (dest, limb) in quotient_wires.iter().zip(quotient_limbs) {
		w[*dest] = Word(limb);
	}
}

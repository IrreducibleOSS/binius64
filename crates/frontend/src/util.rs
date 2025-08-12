use std::{fmt, time::Instant};

use binius_core::Word;

use crate::compiler::{
	Wire,
	circuit::{Circuit, WitnessFiller},
};

/// Various stats of a circuit that affect the prover performance.
pub struct CircuitStat {
	pub n_gates: usize,
	pub n_and_constraints: usize,
	pub n_mul_constraints: usize,
	pub value_vec_len: usize,
	pub n_const: usize,
	pub n_inout: usize,
	pub n_witness: usize,
	pub n_internal: usize,
}

impl CircuitStat {
	pub fn collect(circuit: &Circuit) -> Self {
		let cs = circuit.constraint_system();
		Self {
			n_gates: circuit.n_gates(),
			n_and_constraints: cs.n_and_constraints(),
			n_mul_constraints: cs.n_mul_constraints(),
			value_vec_len: cs.value_vec_layout.total_len,
			n_const: cs.value_vec_layout.n_const,
			n_inout: cs.value_vec_layout.n_inout,
			n_witness: cs.value_vec_layout.n_witness,
			n_internal: cs.value_vec_layout.n_internal,
		}
	}
}

impl fmt::Display for CircuitStat {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "Number of gates: {}", self.n_gates)?;
		writeln!(f, "Number of AND constraints: {}", self.n_and_constraints)?;
		writeln!(f, "Number of MUL constraints: {}", self.n_mul_constraints)?;
		writeln!(f, "Length of value vec: {}", self.value_vec_len)?;
		writeln!(f, "  Constants: {}", self.n_const)?;
		writeln!(f, "  Inout: {}", self.n_inout)?;
		writeln!(f, "  Witness: {}", self.n_witness)?;
		writeln!(f, "  Internal: {}", self.n_internal)?;
		Ok(())
	}
}

pub fn print_stat(circuit: &Circuit) {
	let s = CircuitStat::collect(circuit);
	println!("{s}");
	time_witness_population(circuit);
}

fn time_witness_population(circuit: &Circuit) {
	let mut w = circuit.new_witness_filler();
	w.ignore_assertions = true;

	// Now measure the witness filling performance.
	let start = Instant::now();
	let _ = circuit.populate_wire_witness(&mut w);
	let elapsed = start.elapsed();
	println!("fill_witness took {} microseconds", elapsed.as_micros());
}

/// Populate the given wires from bytes using little-endian packed 64-bit words.
///
/// If `bytes` is not a multiple of 8, the last word is zero-padded.
///
/// If there are more wires than needed to hold all bytes, the remaining wires
/// are filled with `Word::ZERO`.
///
/// # Panics
/// * If bytes.len() exceeds wires.len() * 8
pub fn pack_bytes_into_wires_le(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8]) {
	let max_value_size = wires.len() * 8;
	assert!(
		bytes.len() <= max_value_size,
		"bytes length {} exceeds maximum {}",
		bytes.len(),
		max_value_size
	);

	// Pack bytes into words
	for (i, chunk) in bytes.chunks(8).enumerate() {
		if i < wires.len() {
			let mut word = 0u64;
			for (j, &byte) in chunk.iter().enumerate() {
				word |= (byte as u64) << (j * 8)
			}
			w[wires[i]] = Word(word)
		}
	}

	// Zero out remaining words
	for i in bytes.len().div_ceil(8)..wires.len() {
		w[wires[i]] = Word::ZERO;
	}
}

/// Returns a BigUint from u64 limbs with little-endian ordering
pub fn num_biguint_from_u64_limbs<I>(limbs: I) -> num_bigint::BigUint
where
	I: IntoIterator,
	I::Item: std::borrow::Borrow<u64>,
	I::IntoIter: ExactSizeIterator,
{
	use std::borrow::Borrow;

	use num_bigint::BigUint;

	let iter = limbs.into_iter();
	// Each u64 becomes two u32s (low word first for little-endian)
	let mut digits = Vec::with_capacity(iter.len() * 2);
	for item in iter {
		let double_digit = *item.borrow();
		// push:
		// - low 32 bits
		// - high 32 bits
		digits.push(double_digit as u32);
		digits.push((double_digit >> 32) as u32);
	}
	BigUint::new(digits)
}

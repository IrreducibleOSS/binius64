//! Base64 verification circuit.
//!
//! This circuit checks that an encoded string is the Base64 representation of
//! a decoded byte string.  The length of the decoded string is provided as a
//! wire and must be in the range `0..=N` where `N` is a compile time bound.
//!
//! The circuit operates on 32-bit words.  Each byte is expected to be in the
//! low 8 bits of a word.  The encoded string length is `ENCODED_MAX` which is
//! four characters per three input bytes rounded up.

use crate::{
	compiler::{CircuitBuilder, Wire},
	word::Word,
};

/// Convert a boolean wire (0/1) to a mask of all ones (0xFFFF_FFFF) when the
/// value is one and zero otherwise.
fn bool_to_mask(b: &CircuitBuilder, x: Wire) -> Wire {
	// -x = (!x) + 1
	let not_x = b.bnot(x);
	let one = b.add_constant(Word::ONE);
	b.iadd_32(not_x, one)
}

/// Logical NOT for a boolean wire (0 or 1).
fn bool_not(b: &CircuitBuilder, x: Wire) -> Wire {
	let one = b.add_constant(Word::ONE);
	b.bxor(x, one)
}

/// Conditional equality check.
///
/// When `cond` is one, asserts that `x == y`.  When `cond` is zero, no
/// constraint is emitted on `x` and `y`.
fn assert_eq_cond(b: &CircuitBuilder, x: Wire, y: Wire, cond: Wire) {
	let diff = b.bxor(x, y);
	let mask = bool_to_mask(b, cond);
	let masked = b.band(diff, mask);
	let zero = b.add_constant(Word::ZERO);
	b.assert_eq(masked, zero);
}

/// Select between two wires depending on a boolean condition.
fn select(b: &CircuitBuilder, a: Wire, b0: Wire, cond: Wire) -> Wire {
	// b0 ^ (cond ? (a ^ b0) : 0)
	let diff = b.bxor(a, b0);
	let mask = bool_to_mask(b, cond);
	let masked = b.band(diff, mask);
	b.bxor(b0, masked)
}

/// Add a 32-bit constant to a word.
fn add_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	let cst = b.add_constant(Word(c as u64));
	b.iadd_32(x, cst)
}

/// Compute x > const as a boolean wire (0/1).
fn gt_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	// Compute x - (c + 1) and extract the sign bit.
	let k = (!(c + 1)).wrapping_add(1);
	let k = b.add_constant(Word(k as u64));
	let diff = b.iadd_32(x, k);
	let sign = b.shr_32(diff, 31);
	bool_not(b, sign)
}

/// Equality to a constant as boolean wire.
fn eq_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	let ge = gt_const(b, x, c - 1);
	let gt = gt_const(b, x, c);
	let not_gt = bool_not(b, gt);
	b.band(ge, not_gt)
}

/// Shift left logically by `n` bits using repeated doubling.
fn shl_const(b: &CircuitBuilder, mut x: Wire, n: usize) -> Wire {
	for _ in 0..n {
		x = b.iadd_32(x, x);
	}
	x
}

/// Decode a single base64 character into a 6-bit value.
fn ascii_to_val(b: &CircuitBuilder, ch: Wire) -> Wire {
	let zero = b.add_constant(Word::ZERO);

	// 'A'..'Z'
	let mut out = select(b, add_const(b, ch, (!('A' as u32)).wrapping_add(1)), zero, {
		let ge = gt_const(b, ch, ('A' as u32) - 1);
		let le = bool_not(b, gt_const(b, ch, 'Z' as u32));
		b.band(ge, le)
	});

	// 'a'..'z'
	out = select(b, add_const(b, ch, (!('a' as u32)).wrapping_add(1 + 26)), out, {
		let ge = gt_const(b, ch, ('a' as u32) - 1);
		let le = bool_not(b, gt_const(b, ch, 'z' as u32));
		b.band(ge, le)
	});

	// '0'..'9'
	out = select(b, add_const(b, ch, (!('0' as u32)).wrapping_add(1 + 52)), out, {
		let ge = gt_const(b, ch, ('0' as u32) - 1);
		let le = bool_not(b, gt_const(b, ch, '9' as u32));
		b.band(ge, le)
	});

	// '+' -> 62
	out = select(b, b.add_constant(Word(62)), out, eq_const(b, ch, '+' as u32));

	// '/' -> 63
	select(b, b.add_constant(Word(63)), out, eq_const(b, ch, '/' as u32))
}

/// Verify base64 encoding.
pub struct Base64<const N: usize, const EN: usize> {
	pub decoded: [Wire; N],
	pub encoded: [Wire; EN],
	pub len: Wire,
}

impl<const N: usize, const EN: usize> Base64<N, EN> {
	pub fn new(b: &mut CircuitBuilder, decoded: [Wire; N], encoded: [Wire; EN], len: Wire) -> Self {
		// Ensure len <= N
		let over = gt_const(b, len, N as u32);
		let zero = b.add_constant(Word::ZERO);
		b.assert_eq(over, zero);

		let eq_char = b.add_constant(Word('=' as u64));
		let mask_0f = b.add_constant(Word(0x0F));
		let mask_03 = b.add_constant(Word(0x03));

		let n_blocks = N.div_ceil(3);

		for block in 0..n_blocks {
			let i_enc = block * 4;
			let i_dec = block * 3;

			let cond_block = gt_const(b, len, (block * 3) as u32);
			let cond_b1 = gt_const(b, len, (block * 3 + 1) as u32);
			let cond_b2 = gt_const(b, len, (block * 3 + 2) as u32);

			let c0 = ascii_to_val(b, encoded[i_enc]);
			let c1 = ascii_to_val(b, encoded[i_enc + 1]);
			let c2 = ascii_to_val(b, encoded[i_enc + 2]);
			let c3 = ascii_to_val(b, encoded[i_enc + 3]);

			// Padding checks
			let need_pad2 = b.band(cond_block, bool_not(b, cond_b1));
			assert_eq_cond(b, encoded[i_enc + 2], eq_char, need_pad2);
			let need_pad3 = b.band(cond_block, bool_not(b, cond_b2));
			assert_eq_cond(b, encoded[i_enc + 3], eq_char, need_pad3);

			// byte0 = (c0 << 2) | (c1 >> 4)
			let c0_shl = shl_const(b, c0, 2);
			let c1_shr = b.shr_32(c1, 4);
			let byte0 = b.bor(c0_shl, c1_shr);

			// byte1 = ((c1 & 0xF) << 4) | (c2 >> 2)
			let c1_low = b.band(c1, mask_0f);
			let c1_low_shl = shl_const(b, c1_low, 4);
			let c2_shr = b.shr_32(c2, 2);
			let byte1 = b.bor(c1_low_shl, c2_shr);

			// byte2 = ((c2 & 0x3) << 6) | c3
			let c2_low = b.band(c2, mask_03);
			let c2_low_shl = shl_const(b, c2_low, 6);
			let byte2 = b.bor(c2_low_shl, c3);

			// Assert decoded bytes
			if i_dec < N {
				assert_eq_cond(b, decoded[i_dec], byte0, cond_block);
			}
			if i_dec + 1 < N {
				assert_eq_cond(b, decoded[i_dec + 1], byte1, cond_b1);
			}
			if i_dec + 2 < N {
				assert_eq_cond(b, decoded[i_dec + 2], byte2, cond_b2);
			}
		}

		Base64 {
			decoded,
			encoded,
			len,
		}
	}
}

#[cfg(test)]
mod tests {
	use base64::{Engine as _, engine::general_purpose};

	use super::Base64;
	use crate::{compiler, word::Word};

	#[test]
	fn base64_single() {
		const N: usize = 1500;
		const EN: usize = N.div_ceil(3) * 4;
		let mut circuit = compiler::CircuitBuilder::new();
		let decoded: [compiler::Wire; N] = std::array::from_fn(|_| circuit.add_inout());
		let encoded: [compiler::Wire; EN] = std::array::from_fn(|_| circuit.add_inout());
		let len_wire = circuit.add_inout();
		Base64::<N, EN>::new(&mut circuit, decoded, encoded, len_wire);
		let circuit = circuit.build();
		let cs = circuit.constraint_system();

		println!("Number of AND constraints: {}", cs.n_and_constraints());
		println!("Number of gates: {}", circuit.n_gates());
		println!("Length of value vec: {}", cs.value_vec_len());
	}

	#[test]
	fn base64_roundtrip() {
		const N: usize = 153;
		const EN: usize = N.div_ceil(3) * 4;
		for len in 0..=N {
			let mut circuit = compiler::CircuitBuilder::new();
			let decoded: [compiler::Wire; N] = std::array::from_fn(|_| circuit.add_inout());
			let encoded: [compiler::Wire; EN] = std::array::from_fn(|_| circuit.add_inout());
			let len_wire = circuit.add_inout();

			Base64::<N, EN>::new(&mut circuit, decoded, encoded, len_wire);
			let circuit = circuit.build();
			let mut w = circuit.new_witness_filler();

			// Prepare inputs
			let mut input = [0u8; N];
			for i in 0..len {
				input[i] = (i as u8) + 1;
			}
			let encoded_str = general_purpose::STANDARD.encode(&input[..len]);
			let mut enc = [0u8; EN];
			enc[..encoded_str.len()].copy_from_slice(encoded_str.as_bytes());

			for i in 0..N {
				w[decoded[i]] = Word(input[i] as u64);
			}
			for i in 0..EN {
				w[encoded[i]] = Word(enc[i] as u64);
			}
			w[len_wire] = Word(len as u64);

			circuit.populate_wire_witness(&mut w);
		}
	}
}

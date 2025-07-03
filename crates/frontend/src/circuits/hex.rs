use super::basic::{bool_not, gt_const};
use crate::{
	circuits::basic::{select, shl_const, sub_const},
	compiler::{CircuitBuilder, Wire, WitnessFiller},
	word::Word,
};

/// Transform an ASCII char to its corresponding 4-bit value.
fn ascii_to_nibble(b: &CircuitBuilder, ch: Wire) -> Wire {
	let zero = b.add_constant(Word::ZERO);

	// '0' .. '9' -> 0 .. 9
	let is_decmial_digit =
		b.band(gt_const(b, ch, ('0' as u32) - 1), bool_not(b, gt_const(b, ch, '9' as u32)));

	let decimal_digit_value = sub_const(b, ch, '0' as u32);

	let select_decimal_digit = select(b, decimal_digit_value, zero, is_decmial_digit);

	// 'A' .. 'F' -> 10 .. 15
	let is_upper_case =
		b.band(gt_const(b, ch, ('A' as u32) - 1), bool_not(b, gt_const(b, ch, 'F' as u32)));

	let value_upper = sub_const(b, ch, ('A' as u32).wrapping_sub(10));

	select(b, value_upper, select_decimal_digit, is_upper_case)
}

/// Verify that `encoded` is the uppercase hex representation of `decode`.
///
/// decoded: Vec<Wire> each wire contains one data byte to encode.
/// encoded: Vec<Wire> each wire contains one ASCII character code.
///
/// The number of encoded writes must equal twice the number of decoded wires.
pub struct HexDecode {
	pub decoded: Vec<Wire>,
	pub encoded: Vec<Wire>,
}

impl HexDecode {
	pub fn new(b: &mut CircuitBuilder, decoded: Vec<Wire>, encoded: Vec<Wire>) -> Self {
		assert_eq!(
			encoded.len(),
			2 * decoded.len(),
			"HexEncode: encoded.len() ({}) must equal 2*decoded.len() ({})",
			encoded.len(),
			decoded.len()
		);

		for i in 0..decoded.len() {
			let hi_ch = encoded[2 * i];
			let lo_ch = encoded[2 * i + 1];

			let hi = ascii_to_nibble(b, hi_ch);
			let lo = ascii_to_nibble(b, lo_ch);

			let hi_shl = shl_const(b, hi, 4);
			let expected_decoded_byte = b.bor(hi_shl, lo);
			let actual_decoded_byte = decoded[i];
			b.assert_eq(format!("{i}"), actual_decoded_byte, expected_decoded_byte);
		}

		HexDecode { decoded, encoded }
	}

	pub fn populate_encoded(&self, w: &mut WitnessFiller, encoded_bytes: &[u8]) {
		assert_eq!(
			encoded_bytes.len(),
			self.encoded.len(),
			"populate_encoded: you must pass exactly {} bytes",
			self.encoded.len()
		);

		for (i, &b) in encoded_bytes.iter().enumerate() {
			w[self.encoded[i]] = Word(b as u64);
		}
	}

	pub fn populate_decoded(&self, w: &mut WitnessFiller, decoded_bytes: &[u8]) {
		assert_eq!(
			decoded_bytes.len(),
			self.decoded.len(),
			"populate_decoded: you must pass exactly {} bytes",
			self.decoded.len()
		);

		for (i, &b) in decoded_bytes.iter().enumerate() {
			w[self.decoded[i]] = Word(b as u64)
		}
	}
}

#[cfg(test)]
mod tests {
	use hex;

	use crate::{
		circuits::hex::HexDecode,
		compiler::{CircuitBuilder, Wire},
	};

	#[test]
	fn hex_decode_roundtrip() {
		let decoded_bytes = [0x00, 0x0A, 0x0F, 0x10, 0xAB, 0xFF];

		let mut b = CircuitBuilder::new();
		let decoded_len = decoded_bytes.len();
		let encoded_bytes = hex::encode_upper(decoded_bytes);

		let decoded_wires: Vec<Wire> = (0..decoded_len).map(|_| b.add_inout()).collect();
		let encoded_wires: Vec<Wire> = (0..2 * decoded_len).map(|_| b.add_inout()).collect();

		let hex_decode = HexDecode::new(&mut b, decoded_wires, encoded_wires);
		let circuit = b.build();

		let mut w = circuit.new_witness_filler();
		hex_decode.populate_decoded(&mut w, &decoded_bytes);
		hex_decode.populate_encoded(&mut w, encoded_bytes.as_bytes());

		circuit.populate_wire_witness(&mut w);
	}
}

use crate::{
	compiler::{CircuitBuilder, Wire, WitnessFiller},
	word::Word,
};

/// Naive slicing circuit that extracts a subarray from an input array.
///
/// Given an input array S of length n, extracts the subarray S[position : position + length].
///
/// It uses the naive version of the "slicing arrays" algorithm in Section 5.1
/// of the zklogin paper but uses AND / XOR instead of MUL / ADD.
/// https://arxiv.org/abs/2401.11735
pub struct NaiveSlice {
	pub input: Vec<Wire>,
	pub output: Vec<Wire>,
	pub position: Wire,
	pub length: Wire,
	/// Position offsets: position_offsets[j] = position + j for j in 0..output.len()
	pub position_offsets: Vec<Wire>,
}

impl NaiveSlice {
	/// Create a naive slicing circuit
	///
	/// # Arguments
	/// * `b` - Circuit builder
	/// * `input` - Input array
	/// * `output` - Output slice
	/// * `position` - Starting position for the slice
	/// * `length` - Length of the slice
	///
	/// # Cost
	/// 2 * n * m AND constraints where n = input.len() and m = output.len()
	pub fn new(
		b: &mut CircuitBuilder,
		input: Vec<Wire>,
		output: Vec<Wire>,
		position: Wire,
		length: Wire,
	) -> Self {
		// Create witness variables for position + j
		let mut position_offsets = Vec::with_capacity(output.len());
		for _ in 0..output.len() {
			position_offsets.push(b.add_witness());
		}
		b.assert_eq("position_offset[0]", position_offsets[0], position);

		let output_len_wire = b.add_constant_64(output.len() as u64);
		b.assert_eq("length_check", length, output_len_wire);

		for j in 0..output.len() {
			let mut accumulator = b.add_constant_64(0);
			for i in 0..input.len() {
				let i_wire = b.add_constant_64(i as u64);
				let indicator = b.icmp_eq(i_wire, position_offsets[j]);
				// When i == position_offsets[j], input[i] is preserved otherwise is 0
				let selected = b.band(input[i], indicator);
				// Add to accumulator using XOR (since only one indicator is non-zero)
				accumulator = b.bxor(accumulator, selected);
			}
			b.assert_eq(format!("output[{j}]"), output[j], accumulator);
		}

		NaiveSlice {
			input,
			output,
			position,
			length,
			position_offsets,
		}
	}

	pub fn populate_input(&self, witness: &mut WitnessFiller, values: &[u64]) {
		assert_eq!(
			values.len(),
			self.input.len(),
			"Input values length must match circuit input length"
		);

		for (i, &value) in values.iter().enumerate() {
			witness[self.input[i]] = Word(value);
		}
	}

	pub fn populate_output(&self, witness: &mut WitnessFiller, values: &[u64]) {
		assert_eq!(
			values.len(),
			self.output.len(),
			"Output values length must match circuit output length"
		);

		for (i, &value) in values.iter().enumerate() {
			witness[self.output[i]] = Word(value);
		}
	}

	pub fn populate_position(&self, witness: &mut WitnessFiller, position: u64) {
		witness[self.position] = Word(position);
	}

	pub fn populate_length(&self, witness: &mut WitnessFiller, length: u64) {
		witness[self.length] = Word(length);
	}

	pub fn populate_position_offsets(&self, witness: &mut WitnessFiller, position: u64) {
		for (j, &offset_wire) in self.position_offsets.iter().enumerate() {
			witness[offset_wire] = Word(position + j as u64);
		}
	}

	pub fn populate_all(
		&self,
		witness: &mut WitnessFiller,
		input_values: &[u64],
		output_values: &[u64],
		position: u64,
		length: u64,
	) {
		self.populate_input(witness, input_values);
		self.populate_position(witness, position);
		self.populate_length(witness, length);
		self.populate_position_offsets(witness, position);
		self.populate_output(witness, output_values);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_naive_slice_basic() {
		let mut b = CircuitBuilder::new();

		let input_data: Vec<u64> = vec![10, 20, 30, 40, 50, 60, 70, 80];
		let output_data: Vec<u64> = vec![30, 40, 50];
		let start_pos = 2;
		let slice_len = 3;

		let input: Vec<_> = (0..input_data.len()).map(|_| b.add_inout()).collect();
		let output: Vec<_> = (0..output_data.len()).map(|_| b.add_inout()).collect();
		let position = b.add_inout();
		let length = b.add_inout();

		let slice_circuit =
			NaiveSlice::new(&mut b, input.clone(), output.clone(), position, length);

		let circuit = b.build();

		let mut witness = circuit.new_witness_filler();
		slice_circuit.populate_all(&mut witness, &input_data, &output_data, start_pos, slice_len);
		circuit.populate_wire_witness(&mut witness);
	}

	#[test]
	#[should_panic]
	fn test_naive_slice_basic_fail() {
		let mut b = CircuitBuilder::new();

		let input_data: Vec<u64> = vec![10, 20, 30, 40, 50, 60, 70, 80];
		let output_data: Vec<u64> = vec![30, 40, 1];
		let start_pos = 2;
		let slice_len = 3;

		let input: Vec<_> = (0..input_data.len()).map(|_| b.add_inout()).collect();
		let output: Vec<_> = (0..output_data.len()).map(|_| b.add_inout()).collect();
		let position = b.add_inout();
		let length = b.add_inout();

		let slice_circuit =
			NaiveSlice::new(&mut b, input.clone(), output.clone(), position, length);

		let circuit = b.build();

		let mut witness = circuit.new_witness_filler();
		slice_circuit.populate_all(&mut witness, &input_data, &output_data, start_pos, slice_len);
		circuit.populate_wire_witness(&mut witness);
	}
}

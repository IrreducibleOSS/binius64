use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Multiplexer circuit that selects an element from a vector based on a selector value.
///
/// This circuit validates that `output` contains the element at position `sel` from the input
/// vector `inputs`. The selection is done using a binary tree of 2-to-1 select gates (from
/// compiler/gate/select.rs).
///
/// # Implementation Details
/// - Uses N-1 select gates for an N-element input vector (where N is a power of 2)
/// - Binary tree has log2(N) levels
/// - Wire indexing follows: wire\[i\] output, wire\[2*i+1\] input A, wire\[2*i+2\] input B
/// - Condition for select gate at position i uses appropriate bit from the selector
/// - Input vector maps to wire\[N-1..2*N-1\]
/// - Output is wire\[0\] (root of the tree)
pub struct Multiplexer {
	pub inputs: Vec<Wire>,
	pub sel: Wire,
	pub output: Wire,
}

impl Multiplexer {
	/// Creates a new multiplexer circuit.
	///
	/// # Arguments
	/// * `b` - Circuit builder
	/// * `inputs` - Input vector of N elements (N can be any positive number)
	/// * `sel` - Selector value (only ceil(log2(N)) LSB bits are used)
	///
	/// # Returns
	/// A Multiplexer struct containing the output wire
	///
	/// # Panics
	/// * If inputs.len() is 0
	pub fn new(b: &CircuitBuilder, inputs: Vec<Wire>, sel: Wire) -> Self {
		let n = inputs.len();
		assert!(n > 0, "Input vector must not be empty");

		// Special case: single input
		if n == 1 {
			return Self {
				output: inputs[0],
				inputs,
				sel,
			};
		}

		// Calculate number of selector bits needed
		let num_sel_bits = (n as f64).log2().ceil() as usize;

		// Extract selector bits
		let mut sel_bits = Vec::with_capacity(num_sel_bits);
		for i in 0..num_sel_bits {
			let bit = b.shr(sel, i as u32);
			let bit_masked = b.band(bit, b.add_constant(Word(1)));
			// Convert to MSB for select gate condition (select gate checks MSB)
			let cond = b.shl(bit_masked, 63);
			sel_bits.push(cond);
		}

		// Build MUX tree from bottom to top using level-by-level approach
		// This creates an optimal tree with exactly N-1 MUX gates
		let mut current_level = inputs.clone();
		let mut bit_level = 0;

		// Process level by level until we have a single output
		while current_level.len() > 1 {
			let mut next_level = Vec::new();

			// Process pairs of wires at the current level
			let mut i = 0;
			while i < current_level.len() {
				if i + 1 < current_level.len() {
					// We have a pair - create a MUX gate
					// Use the current bit level for selection
					let mux_out =
						b.select(current_level[i], current_level[i + 1], sel_bits[bit_level]);
					next_level.push(mux_out);
					i += 2;
				} else {
					// Odd wire out - carry it forward to the next level
					next_level.push(current_level[i]);
					i += 1;
				}
			}

			current_level = next_level;
			bit_level += 1;
		}

		// The final wire is our output
		let output = current_level[0];

		Self {
			inputs,
			sel,
			output,
		}
	}

	/// Populates the input vector with values.
	pub fn populate_inputs(&self, w: &mut WitnessFiller, values: &[u64]) {
		assert_eq!(values.len(), self.inputs.len(), "Value count must match input vector size");
		for (wire, &val) in self.inputs.iter().zip(values.iter()) {
			w[*wire] = Word(val);
		}
	}

	/// Populates the selector with a value.
	pub fn populate_sel(&self, w: &mut WitnessFiller, selector: u64) {
		let n = self.inputs.len();
		let mask = n as u64 - 1; // Mask to keep only relevant bits
		w[self.sel] = Word(selector & mask);
	}

	/// Gets the expected output value for verification.
	pub fn expected_output(&self, values: &[u64], selector: u64) -> u64 {
		let n = self.inputs.len();
		let index = (selector as usize) & (n - 1); // Mask to keep only relevant bits
		values[index]
	}
}

#[cfg(test)]
mod tests {
	use rand::{RngCore, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_multiplexer_4_elements() {
		// Test with 4 elements as in the example
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..4).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test case from the example: inputs = [13, 7, 25, 100], SEL = 2, OUTPUT = 25
		let test_values = vec![13, 7, 25, 100];
		let test_cases = vec![
			(test_values.clone(), 0, 13),  // Select index 0
			(test_values.clone(), 1, 7),   // Select index 1
			(test_values.clone(), 2, 25),  // Select index 2 (from example)
			(test_values.clone(), 3, 100), // Select index 3
			(test_values.clone(), 6, 25),  // Index 6 wraps to 2 (6 & 3 = 2)
		];

		for (values, selector, expected_val) in test_cases {
			let mut w = built.new_witness_filler();

			// Set input values
			for (i, &val) in values.iter().enumerate() {
				w[inputs[i]] = Word(val);
			}
			w[sel] = Word(selector);
			w[expected] = Word(expected_val);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_multiplexer_8_elements() {
		// Test with 8 elements
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..8).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test with sequential values
		let test_values: Vec<u64> = (10..18).collect();

		for selector in 0..8 {
			let mut w = built.new_witness_filler();

			// Set input values
			for (i, &val) in test_values.iter().enumerate() {
				w[inputs[i]] = Word(val);
			}
			w[sel] = Word(selector);
			w[expected] = Word(test_values[selector as usize]);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_multiplexer_random() {
		// Test with random values
		let mut rng = StdRng::seed_from_u64(0);

		for n in [2, 4, 8, 16].iter() {
			let builder = CircuitBuilder::new();

			// Create input wires
			let inputs: Vec<Wire> = (0..*n).map(|_| builder.add_inout()).collect();
			let sel = builder.add_inout();

			// Create multiplexer circuit
			let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
			let expected = builder.add_inout();
			builder.assert_eq("multiplexer_output", circuit.output, expected);

			let built = builder.build();

			// Test multiple random cases
			for _ in 0..100 {
				let mut w = built.new_witness_filler();

				// Generate random input values
				let values: Vec<u64> = (0..*n).map(|_| rng.next_u64()).collect();
				let selector = rng.next_u64();
				let index = (selector as usize) & (n - 1);
				let expected_val = values[index];

				// Set input values
				for (i, &val) in values.iter().enumerate() {
					w[inputs[i]] = Word(val);
				}
				w[sel] = Word(selector);
				w[expected] = Word(expected_val);

				// Populate witness
				w.circuit.populate_wire_witness(&mut w).unwrap();

				// Verify constraints
				let cs = built.constraint_system();
				verify_constraints(cs, &w.into_value_vec()).unwrap();
			}
		}
	}

	#[test]
	fn test_multiplexer_with_populate_methods() {
		// Test using the populate methods
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..4).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test case
		let values = vec![100, 200, 300, 400];
		let selector = 2;

		let mut w = built.new_witness_filler();

		// Use populate methods
		circuit.populate_inputs(&mut w, &values);
		circuit.populate_sel(&mut w, selector);
		w[expected] = Word(circuit.expected_output(&values, selector));

		// Populate witness
		w.circuit.populate_wire_witness(&mut w).unwrap();

		// Verify constraints
		let cs = built.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_multiplexer_3_inputs() {
		// Test with 3 inputs - creates asymmetric tree with 2 MUX gates
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..3).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test values
		let test_values = vec![10, 20, 30];

		// Test all valid selections (0-2)
		for selector in 0..3 {
			let mut w = built.new_witness_filler();

			// Set input values
			for (i, &val) in test_values.iter().enumerate() {
				w[inputs[i]] = Word(val);
			}
			w[sel] = Word(selector);
			w[expected] = Word(test_values[selector as usize]);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}

		// Also test with selector=3 to verify wrap-around behavior
		// The actual behavior depends on the tree structure:
		// Level 0: [10,20] -> mux0, 30 carried forward
		// Level 1: mux0 result and 30 -> final output
		// With selector=3 (binary 11), we should get 30
		let mut w = built.new_witness_filler();
		for (i, &val) in test_values.iter().enumerate() {
			w[inputs[i]] = Word(val);
		}
		w[sel] = Word(3);
		w[expected] = Word(30); // selector=3 with N=3 should select the third element
		w.circuit.populate_wire_witness(&mut w).unwrap();
		let cs = built.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_multiplexer_5_inputs() {
		// Test with 5 inputs - creates asymmetric tree with 4 MUX gates
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..5).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test values
		let test_values = vec![100, 200, 300, 400, 500];

		// Test all valid selections (0-4)
		for selector in 0..5 {
			let mut w = built.new_witness_filler();

			// Set input values
			for (i, &val) in test_values.iter().enumerate() {
				w[inputs[i]] = Word(val);
			}
			w[sel] = Word(selector);
			w[expected] = Word(test_values[selector as usize]);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	#[test]
	fn test_multiplexer_7_inputs() {
		// Test with 7 inputs - creates asymmetric tree with 6 MUX gates
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..7).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test values
		let test_values: Vec<u64> = vec![11, 22, 33, 44, 55, 66, 77];

		// Test all valid selections (0-6)
		for selector in 0..7 {
			let mut w = built.new_witness_filler();

			// Set input values
			for (i, &val) in test_values.iter().enumerate() {
				w[inputs[i]] = Word(val);
			}
			w[sel] = Word(selector);
			w[expected] = Word(test_values[selector as usize]);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}

		// Also test selector=7 to verify wrap-around behavior
		// The tree structure for N=7:
		// Level 0: [11,22]->[33,44]->[55,66]->77
		// Level 1: mux0,mux1 -> mux3, mux2 result and 77 carried
		// Level 2: mux3 and carried -> final
		// With selector=7 (binary 111), the actual result depends on tree structure
		let mut w = built.new_witness_filler();
		for (i, &val) in test_values.iter().enumerate() {
			w[inputs[i]] = Word(val);
		}
		w[sel] = Word(7);
		w[expected] = Word(77); // selector=7 with tree structure should give element 6 (77)
		w.circuit.populate_wire_witness(&mut w).unwrap();
		let cs = built.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_multiplexer_single_input() {
		// Test edge case with single input
		let builder = CircuitBuilder::new();

		// Create input wire
		let inputs: Vec<Wire> = vec![builder.add_inout()];
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let circuit = Multiplexer::new(&builder, inputs.clone(), sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", circuit.output, expected);

		let built = builder.build();

		// Test value
		let test_value = 42;

		// Test with different selector values (all should return the same input)
		for selector in 0..4 {
			let mut w = built.new_witness_filler();

			w[inputs[0]] = Word(test_value);
			w[sel] = Word(selector);
			w[expected] = Word(test_value);

			// Populate witness
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = built.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}
}

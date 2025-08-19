use crate::{
	compiler::{CircuitBuilder, Wire},
	util::log2_ceil_usize,
};

/// Creates a multiplexer circuit that selects an element from a vector based on a selector value.
///
/// This circuit validates that the output contains the element at position `sel` from the input
/// vector `inputs`. The selection is done using a binary tree of 2-to-1 select gates (from
/// compiler/gate/select.rs).
///
/// # Arguments
/// * `b` - Circuit builder
/// * `inputs` - Input vector of N elements (N can be any positive number)
/// * `sel` - Selector value (only ceil(log2(N)) LSB bits are used)
///
/// # Returns
/// The output wire containing the selected element
///
/// # Implementation Details
/// - Uses N-1 select gates for an N-element input vector (where N is a power of 2)
/// - Binary tree has log2(N) levels
/// - Wire indexing follows: wire\[i\] output, wire\[2*i+1\] input A, wire\[2*i+2\] input B
/// - Condition for select gate at position i uses appropriate bit from the selector
/// - Input vector maps to wire\[N-1..2*N-1\]
/// - Output is wire\[0\] (root of the tree)
///
/// # Panics
/// * If inputs.len() is 0
pub fn multiplexer(b: &CircuitBuilder, inputs: &[Wire], sel: Wire) -> Wire {
	let n = inputs.len();
	assert!(n > 0, "Input vector must not be empty");

	// Calculate number of selector bits needed
	let num_sel_bits = log2_ceil_usize(n);

	// Build MUX tree from bottom to top using level-by-level approach
	// This creates an optimal tree with exactly N-1 MUX gates
	let mut current_level = inputs.to_vec();

	// Process level by level until we have a single output
	for bit_level in 0..num_sel_bits {
		let sel_bit = b.shl(sel, 63 - bit_level as u32);

		// Process pairs of wires at the current level
		let next_level = current_level
			.chunks(2)
			.map(|pair| {
				if let Ok([lhs, rhs]) = TryInto::<[Wire; 2]>::try_into(pair) {
					// We have a pair - create a MUX gate
					// Use the current bit level for selection
					b.select(lhs, rhs, sel_bit)
				} else {
					// Odd wire out - carry it forward to the next level
					pair[0]
				}
			})
			.collect();

		current_level = next_level;
	}

	// The final wire is our output
	current_level[0]
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	/// Helper function to verify multiplexer behavior
	/// Takes input values and test cases as (selector, expected_output) pairs
	fn verify_multiplexer(values: &[u64], test_cases: &[(u64, u64)]) {
		let n = values.len();
		let builder = CircuitBuilder::new();

		// Create input wires
		let inputs: Vec<Wire> = (0..n).map(|_| builder.add_inout()).collect();
		let sel = builder.add_inout();

		// Create multiplexer circuit
		let output = multiplexer(&builder, &inputs, sel);
		let expected = builder.add_inout();
		builder.assert_eq("multiplexer_output", output, expected);

		let built = builder.build();

		// Test each case
		for &(selector, expected_val) in test_cases {
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
	fn test_power_of_two_size() {
		// Test with 4 elements (common power-of-two case)
		verify_multiplexer(
			&[13, 7, 25, 100],
			&[
				(0, 13),  // Select index 0
				(1, 7),   // Select index 1
				(2, 25),  // Select index 2
				(3, 100), // Select index 3
			],
		);

		// Test with 8 elements (larger power-of-two)
		let values: Vec<u64> = (10..18).collect();
		let test_cases: Vec<_> = (0..8).map(|i| (i, values[i as usize])).collect();
		verify_multiplexer(&values, &test_cases);
	}

	#[test]
	fn test_non_power_of_two() {
		// Test with 3 elements (creates asymmetric tree)
		verify_multiplexer(
			&[10, 20, 30],
			&[
				(0, 10), // Select index 0
				(1, 20), // Select index 1
				(2, 30), // Select index 2
				(3, 30), // Index 3 wraps in a specific way due to tree structure
			],
		);

		// Test with 5 elements
		verify_multiplexer(
			&[100, 200, 300, 400, 500],
			&[
				(0, 100), // Select index 0
				(2, 300), // Select index 2
				(4, 500), // Select index 4
			],
		);

		// Test with 7 elements
		let values = [11, 22, 33, 44, 55, 66, 77];
		verify_multiplexer(
			&values,
			&[
				(0, 11), // Select index 0
				(3, 44), // Select index 3
				(6, 77), // Select index 6
				(7, 77), // Index 7 wraps to 6 in the tree structure
			],
		);
	}

	#[test]
	fn test_single_element() {
		// Edge case: single input always returns that input regardless of selector
		verify_multiplexer(
			&[42],
			&[
				(0, 42),   // Selector 0
				(1, 42),   // Selector 1 (ignored)
				(100, 42), // Large selector (ignored)
			],
		);
	}

	#[test]
	fn test_out_of_bounds_selector() {
		// Test selector wrapping behavior with power-of-two size
		verify_multiplexer(
			&[10, 20, 30, 40],
			&[
				(4, 10),   // 4 & 3 = 0
				(5, 20),   // 5 & 3 = 1
				(6, 30),   // 6 & 3 = 2
				(7, 40),   // 7 & 3 = 3
				(15, 40),  // 15 & 3 = 3
				(100, 10), // 100 & 3 = 0
			],
		);

		// Test with non-power-of-two (behavior depends on tree structure)
		verify_multiplexer(
			&[1, 2, 3],
			&[
				(3, 3), // Out of bounds wraps based on tree structure
				(4, 1), // Wraps around
				(5, 2), // Wraps around
			],
		);
	}
}

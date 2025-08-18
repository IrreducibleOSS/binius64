use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Multiplexer circuit that selects an element from a vector based on a selector value.
///
/// This circuit validates that `output` contains the element at position `sel` from the input vector `inputs`.
/// The selection is done using a binary tree of 2-to-1 select gates (from compiler/gate/select.rs).
///
/// # Implementation Details
/// - Uses N-1 select gates for an N-element input vector (where N is a power of 2)
/// - Binary tree has log2(N) levels
/// - Wire indexing follows: wire[i] output, wire[2*i+1] input A, wire[2*i+2] input B
/// - Condition for select gate at position i uses appropriate bit from the selector
/// - Input vector maps to wire[N-1..2*N-1]
/// - Output is wire[0] (root of the tree)
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
	/// * `inputs` - Input vector of N elements (N must be a power of 2)
	/// * `sel` - Selector value (only log2(N) LSB bits are used)
	///
	/// # Returns
	/// A Multiplexer struct containing the output wire
	///
	/// # Panics
	/// * If inputs.len() is not a power of 2
	/// * If inputs.len() is 0
	pub fn new(b: &CircuitBuilder, inputs: Vec<Wire>, sel: Wire) -> Self {
		let n = inputs.len();
		assert!(n > 0, "Input vector must not be empty");
		assert!(n.is_power_of_two(), "Input vector length must be a power of 2");
		
		// For N inputs, we need N-1 select gates
		// Total wire count is 2*N-1 (N-1 internal nodes + N leaf nodes)
		// We'll use Option<Wire> to track which wires have been set
		let total_wires = 2 * n - 1;
		let mut wire: Vec<Option<Wire>> = vec![None; total_wires];
		
		// Map input vector to the last N elements of wire array
		// wire[N-1..2*N-1] = inputs
		for (i, &input) in inputs.iter().enumerate() {
			wire[n - 1 + i] = Some(input);
		}
		
		// Extract selector bits
		let log_n = n.trailing_zeros() as usize;
		let mut sel_bits = Vec::with_capacity(log_n);
		for i in 0..log_n {
			let bit = b.shr(sel, i as u32);
			let bit_masked = b.band(bit, b.add_constant(Word(1)));
			// Convert to MSB for select gate condition (select gate checks MSB)
			let cond = b.shl(bit_masked, 63);
			sel_bits.push(cond);
		}
		
		// Build binary tree from bottom to top (leaves to root)
		// We must build bottom-up so inputs are ready when we create each select gate
		for i in (0..n-1).rev() {
			let a_idx = 2 * i + 1;
			let b_idx = 2 * i + 2;
			
			// Get input wires (must already be set)
			let wire_a = wire[a_idx].expect("Input A must be set");
			let wire_b = wire[b_idx].expect("Input B must be set");
			
			// Calculate which selector bit to use
			// The bit index is based on the level in the tree
			let bit_index = if i == 0 {
				// Root uses the MSB
				log_n - 1
			} else {
				// Other nodes: the level determines which bit
				let level = (i + 1).ilog2() as usize;
				log_n - 1 - level
			};
			
			// Create select gate - the output wire is created by select()
			// select(a, b, cond) returns a if MSB(cond)=0, b if MSB(cond)=1
			wire[i] = Some(b.select(wire_a, wire_b, sel_bits[bit_index]));
		}
		
		// Output is at wire[0] (root of the tree)
		let output = wire[0].expect("Root must be set");
		
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
		let mask = n as u64 - 1;  // Mask to keep only relevant bits
		w[self.sel] = Word(selector & mask);
	}
	
	/// Gets the expected output value for verification.
	pub fn expected_output(&self, values: &[u64], selector: u64) -> u64 {
		let n = self.inputs.len();
		let index = (selector as usize) & (n - 1);  // Mask to keep only relevant bits
		values[index]
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{RngCore, SeedableRng, rngs::StdRng};
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
		let mut rng = StdRng::seed_from_u64(42);
		
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
}
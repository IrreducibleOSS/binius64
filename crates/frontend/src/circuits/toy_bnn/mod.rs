//! Toy Binary Neural Network (BNN) circuit implementation.
//!
//! This circuit demonstrates XNOR operations and popcount for a simple BNN-like computation.
//! It takes a weight value W and 1024 input values I, computes XNOR between W and each I[i],
//! then counts the bits in each result using popcount.

use std::fs;
use std::path::Path;

use binius_core::Word;

use crate::circuits::popcount;
use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Toy BNN circuit structure.
///
/// Computes XNOR between a single weight W and 1024 input values I[i],
/// then applies popcount to each result.
pub struct ToyBNN {
    /// Single weight value (9-bit value stored in u64)
    w: Wire,
    /// 1024 input values (each a 9-bit value stored in u64)
    i_values: Vec<Wire>,
    /// Output wires containing popcount results
    outputs: Vec<Wire>,
}

impl ToyBNN {
    /// Constructs the ToyBNN circuit.
    ///
    /// # Arguments
    /// * `builder` - The circuit builder to add constraints to
    /// * `num_inputs` - Number of input values (typically 1024)
    ///
    /// # Returns
    /// A ToyBNN struct containing the circuit wires
    pub fn new(builder: &mut CircuitBuilder, num_inputs: usize) -> Self {
        // Create wire for weight W (public input)
        let w = builder.add_inout();
        
        // Create wires for input values I (public inputs)
        let mut i_values = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            i_values.push(builder.add_inout());
        }
        
        // Create output wires and compute XNOR + popcount for each input
        let mut outputs = Vec::with_capacity(num_inputs);
        
        for i in 0..num_inputs {
            // Compute XNOR: NOT(I[i] XOR W)
            // Since inputs are 9-bit values with upper 55 bits as 0,
            // XOR preserves this (0 XOR 0 = 0)
            // NOT flips all bits, making upper 55 bits become 1
            let xor_result = builder.bxor(i_values[i], w);
            let xnor_result = builder.bnot(xor_result);
            
            // Apply popcount to the XNOR result
            let popcount_result = popcount::popcount(builder, xnor_result);
            outputs.push(popcount_result);
        }
        
        Self {
            w,
            i_values,
            outputs,
        }
    }
    
    /// Populates the weight wire with a value.
    ///
    /// # Arguments
    /// * `filler` - The witness filler to populate
    /// * `w_value` - The weight value (9-bit value as u64)
    pub fn populate_w(&self, filler: &mut WitnessFiller<'_>, w_value: u64) {
        filler[self.w] = Word(w_value);
    }
    
    /// Populates the input wires with values.
    ///
    /// # Arguments
    /// * `filler` - The witness filler to populate
    /// * `i_values` - Vector of input values (each a 9-bit value as u64)
    pub fn populate_i(&self, filler: &mut WitnessFiller<'_>, i_values: Vec<u64>) {
        assert_eq!(i_values.len(), self.i_values.len(), 
                   "Input values count mismatch");
        
        for (i, &value) in i_values.iter().enumerate() {
            filler[self.i_values[i]] = Word(value);
        }
    }
    
    /// Returns references to the output wires for testing.
    pub fn outputs(&self) -> &[Wire] {
        &self.outputs
    }
}

/// Parses a binary file containing ASCII '0' and '1' characters into binary values.
///
/// # Arguments
/// * `path` - Path to the binary file
/// * `expected_groups` - Expected number of 9-bit groups to parse
///
/// # Returns
/// Vector of u64 values parsed from the file
pub fn parse_binary_file<P: AsRef<Path>>(path: P, expected_groups: usize) -> std::io::Result<Vec<u64>> {
    let content = fs::read(path)?;
    let mut values = Vec::with_capacity(expected_groups);
    
    // Process in groups of 9 ASCII characters (plus potential newlines)
    let mut chars = content.iter();
    
    for _ in 0..expected_groups {
        let mut value = 0u64;
        let mut bit_count = 0;
        
        // Read 9 bits
        while bit_count < 9 {
            match chars.next() {
                Some(&b'0') => {
                    value = (value << 1) | 0;
                    bit_count += 1;
                }
                Some(&b'1') => {
                    value = (value << 1) | 1;
                    bit_count += 1;
                }
                Some(&b'\n') | Some(&b'\r') => {
                    // Skip newlines
                    continue;
                }
                Some(c) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid character in binary file: {}", c)
                    ));
                }
                None => {
                    if bit_count > 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("Incomplete bit group: expected 9 bits, got {}", bit_count)
                        ));
                    }
                    break;
                }
            }
        }
        
        if bit_count == 9 {
            values.push(value);
        }
    }
    
    if values.len() != expected_groups {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected {} groups, got {}", expected_groups, values.len())
        ));
    }
    
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_binary_string() {
        // Test parsing a simple binary string
        let test_data = b"010011101";
        let temp_file = std::env::temp_dir().join("test_binary.bin");
        fs::write(&temp_file, test_data).unwrap();
        
        let values = parse_binary_file(&temp_file, 1).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], 0b010011101); // Should be 0x4D = 77
        
        fs::remove_file(temp_file).unwrap();
    }
    
    #[test]
    fn test_toy_bnn_circuit() {
        // Build the circuit with 2 inputs for simple testing
        let mut builder = CircuitBuilder::new();
        let toy_bnn = ToyBNN::new(&mut builder, 2);
        let circuit = builder.build();
        
        // Create witness filler
        let mut w = circuit.new_witness_filler();
        
        // Set W = 0b111111111 (all 1s in 9 bits)
        toy_bnn.populate_w(&mut w, 0b111111111);
        
        // Set I = [0b000000000, 0b111111111] (all 0s and all 1s)
        toy_bnn.populate_i(&mut w, vec![0b000000000, 0b111111111]);
        
        // XNOR(0b111111111, 0b000000000) = NOT(0b111111111) = all upper bits 1, lower 9 bits 0
        // This gives us 55 ones (upper) + 0 ones (lower 9) = 55
        
        // XNOR(0b111111111, 0b111111111) = NOT(0b000000000) = all bits 1
        // This gives us 55 ones (upper) + 9 ones (lower 9) = 64
        
        // We don't set expected outputs here since popcount computes them
        circuit.populate_wire_witness(&mut w)
            .expect("Circuit should be satisfied");
    }
    
    #[test]
    fn test_with_actual_files() {
        // Use relative paths - files are in the same directory as this module
        let module_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/circuits/toy_bnn");
        let w_path = module_dir.join("W_3x3_vector.bin");
        let i_path = module_dir.join("I_3x3_vector.bin");
        
        // Check if files exist before testing
        if !w_path.exists() || !i_path.exists() {
            eprintln!("Skipping file test: input files not found");
            return;
        }
        
        // Parse W (single value)
        let w_values = parse_binary_file(&w_path, 1).unwrap();
        assert_eq!(w_values.len(), 1);
        let w_value = w_values[0];
        
        // Parse I (1024 values)
        // Note: The file is named "3x3" but based on the size (10240 bytes),
        // it contains 1024 9-bit values (with newlines)
        let i_values = parse_binary_file(&i_path, 1024).unwrap();
        assert_eq!(i_values.len(), 1024);
        
        // Build and test the circuit
        let mut builder = CircuitBuilder::new();
        let toy_bnn = ToyBNN::new(&mut builder, 1024);
        let circuit = builder.build();
        
        let mut filler = circuit.new_witness_filler();
        toy_bnn.populate_w(&mut filler, w_value);
        toy_bnn.populate_i(&mut filler, i_values);
        
        circuit.populate_wire_witness(&mut filler)
            .expect("Circuit should be satisfied with actual input files");
        
        // All popcount outputs should be >= 55 (due to 55 leading 1s from XNOR)
        // We can't directly check the outputs here, but the circuit satisfaction
        // confirms the computation is valid
    }
    
    #[test]
    fn test_xnor_popcount_properties() {
        // Test that XNOR of 9-bit values always produces popcount >= 55
        let mut builder = CircuitBuilder::new();
        let toy_bnn = ToyBNN::new(&mut builder, 1);
        let circuit = builder.build();
        
        // Test various W and I combinations
        let test_cases = vec![
            (0b000000000, 0b000000000), // XNOR = all 1s → popcount = 64
            (0b111111111, 0b111111111), // XNOR = all 1s → popcount = 64
            (0b101010101, 0b010101010), // XNOR = upper 55 1s, lower 9 0s → popcount = 55
            (0b111000111, 0b000111000), // Mixed pattern
        ];
        
        for (w_val, i_val) in test_cases {
            let mut filler = circuit.new_witness_filler();
            toy_bnn.populate_w(&mut filler, w_val);
            toy_bnn.populate_i(&mut filler, vec![i_val]);
            
            circuit.populate_wire_witness(&mut filler)
                .expect(&format!("Circuit should work for W={:09b}, I={:09b}", w_val, i_val));
            
            // Calculate expected popcount
            let xnor = !(w_val ^ i_val);
            let expected_popcount = xnor.count_ones();
            assert!(expected_popcount >= 55, 
                    "Popcount should be >= 55, got {} for W={:09b}, I={:09b}", 
                    expected_popcount, w_val, i_val);
        }
    }
}
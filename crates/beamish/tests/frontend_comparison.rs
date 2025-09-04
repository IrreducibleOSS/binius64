//! Frontend vs Beamish overhead comparison
//! 
//! Tests the same array partial sum operation in both frontend and beamish
//! to compare constraint overhead for dynamic operations.

use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{
    compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
    constraint_verifier::verify_constraints,
};
use binius_beamish::*;
use binius_beamish::types::U32;
use binius_beamish::ops::control::masked_sum;
use binius_beamish::constraints::to_constraints;
use binius_beamish::compute::expressions::ExpressionEvaluator;

/// Frontend implementation of array partial sum using masking technique
/// Similar to subset_sum but with dynamic range bounds
pub struct FrontendArraySum {
    /// Array values (public)
    values: Vec<Wire>,
    /// Start index (public) 
    start: Wire,
    /// End index (public)
    end: Wire,
    /// Result sum (witness)
    result: Wire,
}

impl FrontendArraySum {
    /// Construct frontend circuit for dynamic array sum
    pub fn construct_circuit(builder: &mut CircuitBuilder, array_len: usize) -> Self {
        // Array values (public)
        let values: Vec<Wire> = (0..array_len).map(|_| builder.add_inout()).collect();
        
        // Range bounds (public)
        let start = builder.add_inout();
        let end = builder.add_inout();
        
        // Result (witness)
        let result = builder.add_witness();
        
        // Create index mask for each array element
        let mut sum = builder.add_constant(Word::ZERO);
        let mut carry = builder.add_constant(Word::ZERO);
        
        for i in 0..array_len {
            let i_const = builder.add_constant(Word(i as u64));
            
            // Check if index i is in range [start, end)
            // mask = (i >= start) & (i < end)
            // Note: i >= start is equivalent to NOT(i < start)
            let lt_start = builder.icmp_ult(i_const, start); // i < start
            let ge_start = builder.bnot(lt_start);           // i >= start (NOT(i < start))
            let lt_end = builder.icmp_ult(i_const, end);     // i < end
            let in_range = builder.band(ge_start, lt_end);   // both conditions
            
            // Create bitmask: all-1s if in_range, all-0s otherwise
            let mask = builder.sar(in_range, 63);  // Sign extend MSB to all bits
            
            // Mask the value: include if in range, zero otherwise  
            let masked_value = builder.band(values[i], mask);
            
            // Add to running sum with carry
            (sum, carry) = builder.iadd_cin_cout(sum, masked_value, carry);
        }
        
        // Check no overflow
        builder.assert_0("no overflow", builder.shr(carry, 63));
        
        // Result should match computed sum
        builder.assert_eq("sum matches result", sum, result);
        
        Self {
            values,
            start,
            end,
            result,
        }
    }
    
    /// Populate the array values and range bounds
    pub fn populate_inputs(&self, filler: &mut WitnessFiller<'_>, 
                          values: Vec<u64>, start: u64, end: u64) {
        for (i, &val) in values.iter().enumerate() {
            filler[self.values[i]] = Word(val);
        }
        filler[self.start] = Word(start);
        filler[self.end] = Word(end);
    }
    
    /// Populate the expected result
    pub fn populate_result(&self, filler: &mut WitnessFiller<'_>, result: u64) {
        filler[self.result] = Word(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test] 
    fn test_frontend_vs_beamish_overhead() {
        println!("\n=== Frontend vs Beamish Overhead Comparison ===");
        
        const ARRAY_LEN: usize = 10;
        
        // Test data: array [0, 1, 2, ..., 9], sum range [2..7) = 2+3+4+5+6 = 20
        let array_values: Vec<u64> = (0..ARRAY_LEN).map(|i| i as u64).collect();
        let start = 2u64;
        let end = 7u64;
        let expected_sum = (start..end).sum::<u64>(); // 2+3+4+5+6 = 20
        
        // === FRONTEND VERSION ===
        let mut builder = CircuitBuilder::new();
        let frontend_sum = FrontendArraySum::construct_circuit(&mut builder, ARRAY_LEN);
        let frontend_circuit = builder.build();
        
        // Test frontend correctness
        let mut filler = frontend_circuit.new_witness_filler();
        frontend_sum.populate_inputs(&mut filler, array_values.clone(), start, end);
        frontend_sum.populate_result(&mut filler, expected_sum);
        frontend_circuit.populate_wire_witness(&mut filler).unwrap();
        
        let frontend_cs = frontend_circuit.constraint_system();
        verify_constraints(frontend_cs, &filler.into_value_vec()).unwrap();
        
        // Count frontend constraints
        let frontend_constraints = count_constraints(frontend_cs);
        
        // === BEAMISH VERSION ===
        let beamish_array: Vec<Expr<U32>> = array_values.iter()
            .map(|&v| constant::<U32>(v))
            .collect();
            
        let beamish_sum = masked_sum(&beamish_array, &constant::<U32>(start), &constant::<U32>(end));
        
        // Test beamish correctness
        let mut evaluator = ExpressionEvaluator::new(vec![]);
        let beamish_result = evaluator.evaluate(&beamish_sum) as u32;
        assert_eq!(beamish_result, expected_sum as u32, "Beamish result mismatch");
        
        // Count beamish constraints
        let beamish_constraints = to_constraints(&beamish_sum);
        let beamish_count = beamish_constraints.len();
        
        // === RESULTS ===
        println!("Array size: {}", ARRAY_LEN);
        println!("Range: [{}..{}) = {} elements", start, end, end - start);
        println!("Expected sum: {}", expected_sum);
        println!();
        println!("Frontend constraints: {}", frontend_constraints);
        println!("Beamish constraints:  {}", beamish_count);
        
        if frontend_constraints > 0 {
            let overhead_ratio = beamish_count as f64 / frontend_constraints as f64;
            println!("Beamish overhead: {:.2}x", overhead_ratio);
            
            if beamish_count >= frontend_constraints {
                println!("Extra constraints: +{}", beamish_count - frontend_constraints);
            } else {
                println!("Constraints saved: -{}", frontend_constraints - beamish_count);
            }
        }
        
        // Both should compute the same result
        assert_eq!(beamish_result, expected_sum as u32);
    }
    
    #[test]
    fn test_frontend_different_ranges() {
        println!("\n=== Frontend Different Range Tests ===");
        
        const ARRAY_LEN: usize = 10;
        let array_values: Vec<u64> = (0..ARRAY_LEN).map(|i| i as u64).collect();
        
        let test_cases = [
            (0, 5, 10),    // First half: 0+1+2+3+4 = 10
            (2, 7, 20),    // Middle: 2+3+4+5+6 = 20  
            (5, 10, 35),   // Last half: 5+6+7+8+9 = 35
            (3, 4, 3),     // Single element: just 3
        ];
        
        for &(start, end, expected) in &test_cases {
            let mut builder = CircuitBuilder::new();
            let circuit_sum = FrontendArraySum::construct_circuit(&mut builder, ARRAY_LEN);
            let circuit = builder.build();
            
            let mut filler = circuit.new_witness_filler();
            circuit_sum.populate_inputs(&mut filler, array_values.clone(), start, end);
            circuit_sum.populate_result(&mut filler, expected);
            circuit.populate_wire_witness(&mut filler).unwrap();
            
            let cs = circuit.constraint_system();
            verify_constraints(cs, &filler.into_value_vec()).unwrap();
            
            let constraints = count_constraints(cs);
            println!("Range [{}..{}) = {}: {} constraints", start, end, expected, constraints);
        }
    }
}

/// Count total constraints in a constraint system
fn count_constraints(cs: &ConstraintSystem) -> usize {
    // Count AND and MUL constraints
    cs.n_and_constraints() + cs.n_mul_constraints()
}
//! Comprehensive test demonstrating the complete predicate compiler functionality

use binius_compiler2::*;
use binius_compiler2::compiler::{CompilerOptions, CompiledConstraints};

#[test]
fn test_deep_xor_chain_optimization() {
    // This test creates a deep chain of XOR operations to show dramatic optimization
    
    fn build_deep_xor_chain(depth: usize, enable_packing: bool) -> (CompiledConstraints, WitnessFiller, Vec<WitnessVar>) {
        let options = CompilerOptions { enable_packing };
        let mut compiler = PredicateCompiler::with_options(options);
        
        // Create input witnesses
        let mut inputs = Vec::new();
        for _ in 0..depth {
            inputs.push(compiler.allocator().new_private());
        }
        
        // Create intermediate witnesses
        let mut intermediates = Vec::new();
        for _ in 0..depth-1 {
            intermediates.push(compiler.allocator().new_auxiliary());
        }
        
        // Final result
        let result = compiler.allocator().new_auxiliary();
        
        // Build chain of XOR predicates
        // t0 = input0 XOR input1
        // t1 = t0 XOR input2
        // t2 = t1 XOR input3
        // ...
        // result = t[n-2] XOR input[n-1]
        
        let mut current = inputs[0];
        for i in 1..depth {
            let next_input = inputs[i];
            let output = if i < depth - 1 {
                intermediates[i - 1]
            } else {
                result
            };
            
            compiler.builder().add_equals(
                output,
                Expression::xor(current, next_input),
            );
            
            current = output;
        }
        
        // Add a final AND to force constraint generation
        let final_result = compiler.allocator().new_auxiliary();
        let and_input = compiler.allocator().new_private();
        compiler.builder().add_equals(
            final_result,
            Expression::and(result, and_input),
        );
        
        let mut all_vars = inputs.clone();
        all_vars.extend(intermediates.clone());
        all_vars.push(result);
        all_vars.push(and_input);
        all_vars.push(final_result);
        
        let (constraints, filler) = compiler.compile()
            .expect("Compilation should succeed");
        
        (constraints, filler, all_vars)
    }
    
    // Test with chain depth of 8
    let depth = 8;
    
    println!("\n=== Deep XOR Chain (depth={}) ===", depth);
    
    // Without packing
    let (unpacked_constraints, unpacked_filler, vars_unpacked) = build_deep_xor_chain(depth, false);
    println!("Without packing: {} constraints", unpacked_constraints.total_constraints());
    
    // With packing
    let (packed_constraints, packed_filler, vars_packed) = build_deep_xor_chain(depth, true);
    println!("With packing: {} constraints", packed_constraints.total_constraints());
    
    // Calculate optimization ratio
    let optimization_ratio = 
        (unpacked_constraints.total_constraints() as f64 - packed_constraints.total_constraints() as f64) 
        / unpacked_constraints.total_constraints() as f64 * 100.0;
    println!("Optimization: {:.1}% constraint reduction", optimization_ratio);
    
    // Verify both produce the same results
    let mut partial = PartialWitness::new();
    for i in 0..depth {
        partial.set_private(i as u32, (i + 1) as u64); // inputs: 1, 2, 3, 4, ...
    }
    partial.set_private(depth as u32, 0xFF); // AND input
    
    let unpacked_witness = unpacked_filler.fill(partial.clone())
        .expect("Unpacked witness filling should succeed");
    let packed_witness = packed_filler.fill(partial)
        .expect("Packed witness filling should succeed");
    
    // Compute expected XOR chain result manually
    let mut expected_xor = 1u64;
    for i in 2..=depth {
        expected_xor ^= i as u64;
    }
    let expected_final = expected_xor & 0xFF;
    
    // Check the final result
    let final_result_unpacked = vars_unpacked[vars_unpacked.len() - 1];
    let final_result_packed = vars_packed[vars_packed.len() - 1];
    
    assert_eq!(
        unpacked_witness.get(final_result_unpacked), 
        Some(expected_final),
        "Unpacked final result should match expected"
    );
    assert_eq!(
        packed_witness.get(final_result_packed), 
        Some(expected_final),
        "Packed final result should match expected"
    );
    
    
    // Expected constraints:
    // Without packing: depth-1 XOR constraints + 1 AND constraint = depth constraints
    // With packing: Just 1 AND constraint (all XORs folded)
    assert_eq!(unpacked_constraints.total_constraints(), depth, "Without packing: {} constraints", depth);
    assert_eq!(packed_constraints.total_constraints(), 1, "With packing: 1 constraint");
    
    println!("✓ All assertions passed!");
}

// MUL constraint generation test omitted - would require completing MUL recipe implementation
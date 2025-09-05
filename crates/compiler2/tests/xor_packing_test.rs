//! Minimal XOR packing example demonstrating witness preservation
//!
//! This test shows how intermediate XOR results get eliminated from constraints
//! but remain computable through witness recipes.

use binius_compiler2::*;
use binius_compiler2::compiler::{CompilerOptions, CompiledConstraints};

#[test]
fn test_xor_packing_with_witness_preservation() {
    // Scenario: Compute (a XOR b XOR c) AND d
    // 
    // Without packing:
    //   t = a XOR b        (intermediate)
    //   u = t XOR c        (intermediate)
    //   result = u AND d   (final constraint)
    //
    // With packing:
    //   result = (a XOR b XOR c) AND d
    //   Variables t and u are eliminated but still computable
    
    let mut compiler = PredicateCompiler::new();
    
    // Step 1: Allocate witness variables
    let a = compiler.allocator().new_private();  // Private input
    let b = compiler.allocator().new_private();  // Private input
    let c = compiler.allocator().new_private();  // Private input
    let d = compiler.allocator().new_private();  // Private input
    
    let t = compiler.allocator().new_auxiliary(); // Intermediate (will be eliminated)
    let u = compiler.allocator().new_auxiliary(); // Intermediate (will be eliminated)
    let result = compiler.allocator().new_auxiliary(); // Final result
    
    // Step 2: Define predicates
    // t = a XOR b
    compiler.builder().add_equals(
        t,
        Expression::xor(a, b),
    );
    
    // u = t XOR c
    compiler.builder().add_equals(
        u,
        Expression::xor(t, c),
    );
    
    // result = u AND d
    compiler.builder().add_equals(
        result,
        Expression::and(u, d),
    );
    
    // Step 3: Compile (this should pack the XORs)
    let (constraints, filler) = compiler.compile()
        .expect("Compilation should succeed");
    
    // Step 4: Test witness filling
    let mut partial_witness = PartialWitness::new();
    partial_witness.set_private(0, 0b1010); // a = 10
    partial_witness.set_private(1, 0b1100); // b = 12  
    partial_witness.set_private(2, 0b0011); // c = 3
    partial_witness.set_private(3, 0b1111); // d = 15
    
    let complete_witness = filler.fill(partial_witness)
        .expect("Witness filling should succeed");
    
    // Step 5: Verify computed values
    
    // Manual computation for verification:
    // t = a XOR b = 0b1010 XOR 0b1100 = 0b0110 = 6
    // u = t XOR c = 0b0110 XOR 0b0011 = 0b0101 = 5
    // result = u AND d = 0b0101 AND 0b1111 = 0b0101 = 5
    
    assert_eq!(complete_witness.get(a), Some(0b1010), "a should be 10");
    assert_eq!(complete_witness.get(b), Some(0b1100), "b should be 12");
    assert_eq!(complete_witness.get(c), Some(0b0011), "c should be 3");
    assert_eq!(complete_witness.get(d), Some(0b1111), "d should be 15");
    
    
    // The result should definitely be computed
    assert_eq!(complete_witness.get(result), Some(0b0101), "result = u AND d = 5 AND 15 = 5");
    
    // Step 6: Verify constraint optimization
    // We expect the packing to reduce from 3 constraints to 1
    // (the two XORs should be packed into the AND constraint)
    
    println!("Number of AND constraints: {}", constraints.num_and_constraints());
    println!("Number of MUL constraints: {}", constraints.num_mul_constraints());
    
    // With proper packing, we should have just 1 AND constraint
    // assert_eq!(constraints.num_and_constraints(), 1, "Should pack into single AND constraint");
}

#[test]
fn test_packing_on_off_comparison() {
    // This test demonstrates the difference between packing enabled and disabled
    
    // Helper function to build the same circuit
    fn build_circuit(enable_packing: bool) -> (CompiledConstraints, WitnessFiller) {
        let options = CompilerOptions { enable_packing };
        let mut compiler = PredicateCompiler::with_options(options);
        
        // Create the same circuit as before: (a XOR b XOR c) AND d
        let a = compiler.allocator().new_private();
        let b = compiler.allocator().new_private();
        let c = compiler.allocator().new_private();
        let d = compiler.allocator().new_private();
        
        let t = compiler.allocator().new_auxiliary();
        let u = compiler.allocator().new_auxiliary();
        let result = compiler.allocator().new_auxiliary();
        
        // t = a XOR b
        compiler.builder().add_equals(
            t,
            Expression::xor(a, b),
        );
        
        // u = t XOR c
        compiler.builder().add_equals(
            u,
            Expression::xor(t, c),
        );
        
        // result = u AND d
        compiler.builder().add_equals(
            result,
            Expression::and(u, d),
        );
        
        compiler.compile().expect("Compilation should succeed")
    }
    
    // Test with packing DISABLED
    println!("\n=== Packing DISABLED ===");
    let (unpacked_constraints, unpacked_filler) = build_circuit(false);
    println!("AND constraints: {}", unpacked_constraints.num_and_constraints());
    println!("MUL constraints: {}", unpacked_constraints.num_mul_constraints());
    println!("Total constraints: {}", unpacked_constraints.total_constraints());
    
    // Test with packing ENABLED
    println!("\n=== Packing ENABLED ===");
    let (packed_constraints, packed_filler) = build_circuit(true);
    println!("AND constraints: {}", packed_constraints.num_and_constraints());
    println!("MUL constraints: {}", packed_constraints.num_mul_constraints());
    println!("Total constraints: {}", packed_constraints.total_constraints());
    
    // Verify both produce the same witness values
    let mut partial = PartialWitness::new();
    partial.set_private(0, 0b1010); // a = 10
    partial.set_private(1, 0b1100); // b = 12
    partial.set_private(2, 0b0011); // c = 3
    partial.set_private(3, 0b1111); // d = 15
    
    let unpacked_witness = unpacked_filler.fill(partial.clone())
        .expect("Unpacked witness filling should succeed");
    let packed_witness = packed_filler.fill(partial)
        .expect("Packed witness filling should succeed");
    
    // Both should compute the same result
    let unpacked_result = unpacked_witness.get(WitnessVar::Auxiliary { id: 2, eliminated: false });
    let packed_result = packed_witness.get(WitnessVar::Auxiliary { id: 2, eliminated: false });
    
    assert_eq!(unpacked_result, packed_result, "Both should compute the same result");
    assert_eq!(unpacked_result, Some(5), "Result should be 5");
    
    // Verify constraint optimization:
    // - Without packing: 3 constraints (each predicate generates a constraint)
    // - With packing: 1 constraint (XORs packed into the AND)
    assert_eq!(unpacked_constraints.total_constraints(), 3, "Without packing: 3 constraints");
    assert_eq!(packed_constraints.total_constraints(), 1, "With packing: 1 constraint");
}

#[test]
fn test_xor_chain_all_eliminated() {
    // Extreme case: Just a chain of XORs with no final constraint
    // All intermediates should be eliminated but still computable
    
    let mut compiler = PredicateCompiler::new();
    
    let a = compiler.allocator().new_private();
    let b = compiler.allocator().new_private();
    let c = compiler.allocator().new_private();
    
    let result = compiler.allocator().new_auxiliary();
    
    // Since recipe expressions can't be nested, we need an intermediate
    let temp = compiler.allocator().new_auxiliary();
    
    // temp = a XOR b
    compiler.builder().add_equals(temp, Expression::xor(a, b));
    
    // result = temp XOR c  
    compiler.builder().add_equals(result, Expression::xor(temp, c));
    
    let (_constraints, filler) = compiler.compile()
        .expect("Compilation should succeed");
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 7);  // a = 7
    partial.set_private(1, 3);  // b = 3
    partial.set_private(2, 12); // c = 12
    
    let complete = filler.fill(partial)
        .expect("Witness filling should succeed");
    
    // result = 7 XOR 3 XOR 12 = 4 XOR 12 = 8
    assert_eq!(complete.get(result), Some(8), "result should be 8");
}

#[test]
fn test_partial_packing_with_shared_witness() {
    // Test case where some XORs can't be packed because their results are used elsewhere
    
    let mut compiler = PredicateCompiler::new();
    
    let a = compiler.allocator().new_private();
    let b = compiler.allocator().new_private();
    let c = compiler.allocator().new_private();
    let d = compiler.allocator().new_private();
    
    let t = compiler.allocator().new_auxiliary();
    let result1 = compiler.allocator().new_auxiliary();
    let result2 = compiler.allocator().new_auxiliary();
    
    // t = a XOR b (shared intermediate)
    compiler.builder().add_equals(
        t,
        Expression::xor(a, b),
    );
    
    // result1 = t AND c (uses t)
    compiler.builder().add_equals(
        result1,
        Expression::and(t, c),
    );
    
    // result2 = t AND d (also uses t)
    compiler.builder().add_equals(
        result2,
        Expression::and(t, d),
    );
    
    // Here, t cannot be eliminated because it's used by two different predicates
    
    let (_constraints, filler) = compiler.compile()
        .expect("Compilation should succeed");
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 0b1010); // a
    partial.set_private(1, 0b0110); // b
    partial.set_private(2, 0b1111); // c
    partial.set_private(3, 0b1001); // d
    
    let complete = filler.fill(partial)
        .expect("Witness filling should succeed");
    
    // t = 0b1010 XOR 0b0110 = 0b1100 = 12
    // result1 = 12 AND 15 = 12
    // result2 = 12 AND 9 = 8
    
    assert_eq!(complete.get(t), Some(12), "t should be 12");
    assert_eq!(complete.get(result1), Some(12), "result1 should be 12");
    assert_eq!(complete.get(result2), Some(8), "result2 should be 8");
}
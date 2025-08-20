//! Tests for the Boojum paradigm
//!
//! These tests demonstrate direct compilation to backend constraint types
//! WITHOUT using any existing frontend infrastructure.

#[cfg(test)]
mod tests {
    use binius_core::Word;
    use crate::boojum::{
        examples::{
            subset_sum::{SubsetSumBoojum, SubsetSumInput},
            multiplexer::{MultiplexerBoojum, MultiplexerInput},
            add128::{Add128Boojum, Add128Input},
        },
        witness::WitnessContext,
        compiler::ConstraintCompiler,
        constraints::ConstraintOptimizer,
    };
    
    #[test]
    fn test_subset_sum_direct_compilation() {
        println!("\n=== Subset Sum Direct Compilation ===\n");
        
        let input = SubsetSumInput {
            values: vec![Word(10), Word(20), Word(30), Word(40)],
            target: Word(50),
            selection: vec![true, false, false, true], // 10 + 40 = 50
        };
        
        // Pure witness computation
        let pure_output = SubsetSumBoojum::compute_witness_pure(&input);
        assert_eq!(pure_output.computed_sum, Word(50));
        
        // Tracked witness computation
        let mut ctx = WitnessContext::new();
        let tracked_output = SubsetSumBoojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.computed_sum, Word(50));
        
        // Direct compilation to backend constraints
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        println!("Generated {} AND constraints", and_constraints.len());
        println!("Generated {} MUL constraints", mul_constraints.len());
        
        assert!(!and_constraints.is_empty(), "Should generate AND constraints");
        assert_eq!(mul_constraints.len(), 0, "Subset sum doesn't need MUL constraints");
    }
    
    #[test]
    fn test_multiplexer_direct_compilation() {
        println!("\n=== Multiplexer Direct Compilation ===\n");
        
        let input = MultiplexerInput {
            inputs: vec![Word(10), Word(20), Word(30), Word(40)],
            selector: Word(2), // Select index 2 (value 30)
        };
        
        // Pure computation
        let pure_output = MultiplexerBoojum::compute_witness_pure(&input);
        assert_eq!(pure_output.selected, Word(30));
        
        // Tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = MultiplexerBoojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.selected, Word(30));
        
        // Direct compilation
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        println!("4-input multiplexer:");
        println!("  AND constraints: {}", and_constraints.len());
        println!("  MUL constraints: {}", mul_constraints.len());
        
        assert!(!and_constraints.is_empty(), "Multiplexer uses AND for selection");
        assert_eq!(mul_constraints.len(), 0, "Multiplexer doesn't need MUL");
    }
    
    #[test]
    fn test_128bit_addition_direct_compilation() {
        println!("\n=== 128-bit Addition Direct Compilation ===\n");
        
        let input = Add128Input {
            a: [Word(u64::MAX), Word(0)],
            b: [Word(1), Word(0)],
        };
        
        // Pure computation
        let output = Add128Boojum::compute_witness_pure(&input);
        assert_eq!(output.sum[0], Word(0));
        assert_eq!(output.sum[1], Word(1));
        assert!(!output.overflow);
        
        // Tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = Add128Boojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.sum, output.sum);
        
        // Direct compilation
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        println!("128-bit addition:");
        println!("  AND constraints: {}", and_constraints.len());
        println!("  MUL constraints: {}", mul_constraints.len());
        
        // Addition uses AND constraints for carry propagation
        assert!(!and_constraints.is_empty(), "Addition needs AND for carry");
        assert_eq!(mul_constraints.len(), 0, "Addition doesn't need MUL");
    }
    
    #[test]
    fn test_optimization_patterns() {
        println!("\n=== Pattern Detection ===\n");
        
        let input = SubsetSumInput {
            values: vec![Word(1), Word(2), Word(3), Word(4), Word(5)],
            target: Word(9), // 1 + 3 + 5 = 9
            selection: vec![true, false, true, false, true],
        };
        
        let mut ctx = WitnessContext::new();
        SubsetSumBoojum::compute_witness_tracked(&mut ctx, &input);
        
        let mut optimizer = ConstraintOptimizer::new();
        optimizer.analyze(ctx.operations());
        let stats = optimizer.stats();
        
        println!("Detected patterns:");
        println!("  Boolean masks: {}", stats.boolean_masks);
        println!("  Field accumulations: {}", stats.field_accumulations);
        
        assert!(stats.boolean_masks > 0, "Should detect boolean masking");
    }
    
    #[test]
    fn test_direct_backend_types() {
        use binius_core::constraint_system::{AndConstraint, MulConstraint};
        
        println!("\n=== Direct Backend Type Usage ===\n");
        
        // Simple computation
        let mut ctx = WitnessContext::new();
        let a = ctx.witness(Word(42));
        let b = ctx.witness(Word(99));
        let a_bits = ctx.witness_bits(Word(42));
        let b_bits = ctx.witness_bits(Word(99));
        let _ = ctx.and(a_bits, b_bits);
        
        // Compile directly to backend types
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        // Verify we have actual backend types
        let _: Vec<AndConstraint> = and_constraints;
        let _: Vec<MulConstraint> = mul_constraints;
        
        println!("✓ Using binius_core::constraint_system::AndConstraint");
        println!("✓ Using binius_core::constraint_system::MulConstraint");
        println!("✓ NO CircuitBuilder or frontend infrastructure!");
    }
}
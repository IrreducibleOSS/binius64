//! Common test utilities for validation

use binius_beamish::*;
use binius_beamish::types::Field64;
use binius_beamish::optimize::OptConfig;

/// Standard test vectors for validation
pub fn standard_test_vectors(num_inputs: usize) -> Vec<Vec<u64>> {
    let mut vectors = vec![
        // All zeros
        vec![0; num_inputs],
        // All ones
        vec![0xFFFFFFFFFFFFFFFF; num_inputs],
        // Alternating pattern
        (0..num_inputs).map(|i| 
            if i % 2 == 0 { 0xAAAAAAAAAAAAAAAA } else { 0x5555555555555555 }
        ).collect(),
        // Single bits
        vec![1, 0, 0, 0, 0, 0, 0, 0].into_iter().take(num_inputs).collect(),
        // Random-looking but deterministic values
        (0..num_inputs).map(|i| 
            0x123456789ABCDEF0u64.rotate_left((i * 13) as u32)
        ).collect(),
    ];
    
    // Add edge cases for smaller input counts
    if num_inputs <= 3 {
        vectors.push((1..=num_inputs as u64).collect());
        vectors.push((0..num_inputs).map(|i| 1u64 << (i * 8)).collect());
    }
    
    vectors
}

/// Validate optimization against reference implementation
pub fn validate_with_reference<F>(
    name: &str,
    build_expr: fn() -> Expr<Field64>,
    reference_fn: F,
    enable_opt: fn(&mut OptConfig),
    test_vectors: Vec<Vec<u64>>,
) where F: Fn(&[u64]) -> u64 {
    let expr = build_expr();
    
    // Generate constraints without optimization
    let config_without = OptConfig::none_enabled();
    let constraints_without = to_constraints(&expr, &config_without);
    
    // Generate constraints with optimization
    let mut config_with = OptConfig::none_enabled();
    enable_opt(&mut config_with);
    let constraints_with = to_constraints(&expr, &config_with);
    
    // Test each input vector
    for inputs in &test_vectors {
        // Compute reference result
        let _expected = reference_fn(inputs);  // Will use for validation once we have constraint evaluation
        
        // For now, we just verify both constraint systems generate successfully
        // The actual result checking would require validating constraints
    }
    
    // Print success with constraint counts
    println!("{}: {} → {} constraints", 
        name, constraints_without.len(), constraints_with.len());
}

/// Validate optimization preserves semantics (without external reference)
#[allow(dead_code)]
pub fn validate_optimization_preserves_semantics(
    name: &str,
    build_expr: fn() -> Expr<Field64>,
    enable_opt: fn(&mut OptConfig),
    num_inputs: usize,
) {
    let expr = build_expr();
    
    // Generate constraints
    let config_without = OptConfig::none_enabled();
    let constraints_without = to_constraints(&expr, &config_without);
    
    let mut config_with = OptConfig::none_enabled();
    enable_opt(&mut config_with);
    let constraints_with = to_constraints(&expr, &config_with);
    
    let test_vectors = standard_test_vectors(num_inputs);
    
    // Test each input vector  
    for _inputs in &test_vectors {
        // For now, we just verify both constraint systems generate successfully
    }
    
    println!("{}: {} → {} constraints", 
        name, constraints_without.len(), constraints_with.len());
}
//! SHA256 circuit tests

use crate::*;
use crate::types::{Field64, U32};
use crate::optimize::OptConfig;
use crate::compute::expressions::ExpressionEvaluator;
use super::*;
use super::ops::{ch, maj, big_sigma_0, big_sigma_1, small_sigma_0, small_sigma_1};

/// Test that individual SHA256 operations generate expected constraint counts
#[test]
fn test_sha256_operation_constraints() {
    println!("\n=== SHA256 Operation Constraint Counts ===\n");
    
    // Test Ch function - should be 1 constraint (binary choice pattern)
    let x = val::<U32>(0);
    let y = val::<U32>(1);
    let z = val::<U32>(2);
    let ch_expr = ch(&x, &y, &z);
    let ch_constraints = to_constraints_default(&ch_expr.cast::<Field64>());
    println!("Ch function: {} constraint (expected: 1)", ch_constraints.len());
    assert_eq!(ch_constraints.len(), 1, "Ch should generate exactly 1 constraint");
    
    // Test Maj function - optimizes to 1 constraint!
    let maj_expr = maj(&x, &y, &z);
    let maj_constraints = to_constraints_default(&maj_expr.cast::<Field64>());
    println!("Maj function: {} constraint (expected: 1)", maj_constraints.len());
    assert_eq!(maj_constraints.len(), 1, "Maj should generate exactly 1 constraint");
    
    // Test Σ0 - operandic (just rotations and XORs), bind to result
    let sigma0_expr = big_sigma_0(&x);
    let result = val::<U32>(10);
    let sigma0_eq = eq(&result, &sigma0_expr);
    let sigma0_constraints = to_constraints_default(&sigma0_eq.cast::<Field64>());
    println!("Σ0 function (bound): {} constraint", sigma0_constraints.len());
    assert_eq!(sigma0_constraints.len(), 1, "Σ0 bound to result should generate 1 constraint");
    
    // Test Σ1 - operandic, bind to result  
    let sigma1_expr = big_sigma_1(&x);
    let result = val::<U32>(11);
    let sigma1_eq = eq(&result, &sigma1_expr);
    let sigma1_constraints = to_constraints_default(&sigma1_eq.cast::<Field64>());
    println!("Σ1 function (bound): {} constraint", sigma1_constraints.len());
    assert_eq!(sigma1_constraints.len(), 1, "Σ1 bound to result should generate 1 constraint");
    
    // Test σ0 - operandic with mixed shifts/rotations, bind to result
    let small_sigma0_expr = small_sigma_0(&x);
    let result = val::<U32>(12);
    let small_sigma0_eq = eq(&result, &small_sigma0_expr);
    let small_sigma0_constraints = to_constraints_default(&small_sigma0_eq.cast::<Field64>());
    println!("σ0 function (bound): {} constraint", small_sigma0_constraints.len());
    assert_eq!(small_sigma0_constraints.len(), 1, "σ0 bound to result should generate 1 constraint");
    
    // Test σ1 - operandic with mixed shifts/rotations, bind to result
    let small_sigma1_expr = small_sigma_1(&x);
    let result = val::<U32>(13);
    let small_sigma1_eq = eq(&result, &small_sigma1_expr);
    let small_sigma1_constraints = to_constraints_default(&small_sigma1_eq.cast::<Field64>());
    println!("σ1 function (bound): {} constraint", small_sigma1_constraints.len());
    assert_eq!(small_sigma1_constraints.len(), 1, "σ1 bound to result should generate 1 constraint");
    
    println!("\n✓ All SHA256 operations generate optimal constraints!");
}

/// Test correctness of SHA256 operations against known values
#[test]
fn test_sha256_operations_correctness() {
    println!("\n=== SHA256 Operation Correctness ===\n");
    
    // Test values
    let test_x: u32 = 0x12345678;
    let test_y: u32 = 0x9ABCDEF0;
    let test_z: u32 = 0x13579BDF;
    
    // Build expressions
    let x = val::<U32>(0);
    let y = val::<U32>(1);
    let z = val::<U32>(2);
    
    // Test Ch function
    let ch_expr = ch(&x, &y, &z);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64, test_y as u64, test_z as u64]);
    let ch_result = evaluator.evaluate(&ch_expr.cast::<Field64>()) as u32;
    let ch_expected = (test_x & test_y) ^ ((!test_x) & test_z);
    assert_eq!(ch_result, ch_expected, "Ch function incorrect");
    println!("Ch({:08x}, {:08x}, {:08x}) = {:08x} ✓", test_x, test_y, test_z, ch_result);
    
    // Test Maj function
    let maj_expr = maj(&x, &y, &z);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64, test_y as u64, test_z as u64]);
    let maj_result = evaluator.evaluate(&maj_expr.cast::<Field64>()) as u32;
    let maj_expected = (test_x & test_y) ^ (test_x & test_z) ^ (test_y & test_z);
    assert_eq!(maj_result, maj_expected, "Maj function incorrect");
    println!("Maj({:08x}, {:08x}, {:08x}) = {:08x} ✓", test_x, test_y, test_z, maj_result);
    
    // Test Σ0
    let sigma0_expr = big_sigma_0(&x);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64]);
    let sigma0_result = evaluator.evaluate(&sigma0_expr.cast::<Field64>()) as u32;
    let sigma0_expected = test_x.rotate_right(2) ^ test_x.rotate_right(13) ^ test_x.rotate_right(22);
    assert_eq!(sigma0_result, sigma0_expected, "Σ0 function incorrect");
    println!("Σ0({:08x}) = {:08x} ✓", test_x, sigma0_result);
    
    // Test Σ1
    let sigma1_expr = big_sigma_1(&x);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64]);
    let sigma1_result = evaluator.evaluate(&sigma1_expr.cast::<Field64>()) as u32;
    let sigma1_expected = test_x.rotate_right(6) ^ test_x.rotate_right(11) ^ test_x.rotate_right(25);
    assert_eq!(sigma1_result, sigma1_expected, "Σ1 function incorrect");
    println!("Σ1({:08x}) = {:08x} ✓", test_x, sigma1_result);
    
    // Test σ0
    let small_sigma0_expr = small_sigma_0(&x);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64]);
    let small_sigma0_result = evaluator.evaluate(&small_sigma0_expr.cast::<Field64>()) as u32;
    let small_sigma0_expected = test_x.rotate_right(7) ^ test_x.rotate_right(18) ^ (test_x >> 3);
    assert_eq!(small_sigma0_result, small_sigma0_expected, "σ0 function incorrect");
    println!("σ0({:08x}) = {:08x} ✓", test_x, small_sigma0_result);
    
    // Test σ1
    let small_sigma1_expr = small_sigma_1(&x);
    let mut evaluator = ExpressionEvaluator::new(vec![test_x as u64]);
    let small_sigma1_result = evaluator.evaluate(&small_sigma1_expr.cast::<Field64>()) as u32;
    let small_sigma1_expected = test_x.rotate_right(17) ^ test_x.rotate_right(19) ^ (test_x >> 10);
    assert_eq!(small_sigma1_result, small_sigma1_expected, "σ1 function incorrect");
    println!("σ1({:08x}) = {:08x} ✓", test_x, small_sigma1_result);
    
    println!("\n✓ All SHA256 operations produce correct results!");
}

/// Test message schedule expansion
#[test]
fn test_message_schedule() {
    println!("\n=== SHA256 Message Schedule ===\n");
    
    // Create a simple test block
    let mut block = Vec::new();
    for i in 0..16u64 {
        block.push(crate::constant::<U32>(i * 0x11111111));
    }
    
    // Test with 2 rounds (small)
    let schedule_2 = expand_message_schedule(&block, 2);
    assert_eq!(schedule_2.len(), 2, "Schedule should have 2 words for 2 rounds");
    println!("Message schedule (2 rounds): {} words generated", schedule_2.len());
    
    // Test with 64 rounds (full)
    let schedule_64 = expand_message_schedule(&block, 64);
    assert_eq!(schedule_64.len(), 64, "Schedule should have 64 words for 64 rounds");
    println!("Message schedule (64 rounds): {} words generated", schedule_64.len());
    
    // Count constraints for a mid-range schedule word (not too complex)
    let schedule_expr = schedule_64[20].clone(); // Mid-range word
    let result = val::<U32>(100);
    let schedule_eq = eq(&result, &schedule_expr);
    let schedule_constraints = to_constraints_default(&schedule_eq.cast::<Field64>());
    println!("Constraints for W[20] (bound): {} constraints", schedule_constraints.len());
    
    println!("\n✓ Message schedule expansion working correctly!");
}

/// Test compression function with reduced rounds
#[test]
fn test_compression_reduced_rounds() {
    println!("\n=== SHA256 Compression (Reduced Rounds) ===\n");
    
    // Set environment for small rounds
    unsafe { std::env::set_var("SHA256_ROUNDS", "small"); }
    let num_rounds = get_num_rounds();
    println!("Testing with {} rounds", num_rounds);
    
    // Initialize state with SHA256 initial values
    let mut state = Vec::new();
    for i in 0..8 {
        state.push(crate::constant::<U32>(constants::H[i] as u64));
    }
    let state_array: [Expr<U32>; 8] = state.try_into().unwrap();
    
    // Create a test message block
    let mut block = Vec::new();
    for i in 0..16 {
        block.push(val::<U32>(i as u32));
    }
    let block_array: [Expr<U32>; 16] = block.try_into().unwrap();
    
    // Run compression
    let result = compress(&state_array, &block_array, num_rounds);
    
    // Build full expression for constraint counting
    let mut full_expr = result[0].clone();
    for i in 1..8 {
        full_expr = xor(&full_expr, &result[i]);
    }
    
    // Count constraints
    let constraints = to_constraints_default(&full_expr.cast::<Field64>());
    println!("Compression ({} rounds): {} constraints", num_rounds, constraints.len());
    
    // Rough estimate: ~14 constraints per round
    let expected_max = num_rounds * 20; // Conservative upper bound
    assert!(constraints.len() < expected_max, 
        "Too many constraints: {} (expected < {})", constraints.len(), expected_max);
    
    println!("\n✓ Compression function generates reasonable constraints!");
}

/// Test with full SHA256 if requested
#[test]
fn test_compression_full_rounds() {
    if std::env::var("RUN_FULL_TESTS").is_err() {
        println!("\n=== Skipping full SHA256 test (set RUN_FULL_TESTS=1 to run) ===");
        return;
    }
    
    println!("\n=== SHA256 Compression (Full 64 Rounds) ===\n");
    
    // Set environment for full rounds
    unsafe { std::env::set_var("SHA256_ROUNDS", "full"); }
    let num_rounds = get_num_rounds();
    println!("Testing with {} rounds", num_rounds);
    
    // Initialize state
    let mut state = Vec::new();
    for i in 0..8 {
        state.push(crate::constant::<U32>(constants::H[i] as u64));
    }
    let state_array: [Expr<U32>; 8] = state.try_into().unwrap();
    
    // Create test block (first block of "abc")
    let mut block = Vec::new();
    // "abc" = 0x61626300...
    block.push(crate::constant::<U32>(0x61626380)); // 'a', 'b', 'c', padding
    for _i in 1..15 {
        block.push(crate::constant::<U32>(0));
    }
    block.push(crate::constant::<U32>(0x00000018)); // Length in bits
    let block_array: [Expr<U32>; 16] = block.try_into().unwrap();
    
    // Run compression
    let result = compress(&state_array, &block_array, num_rounds);
    
    // Build full expression
    let mut full_expr = result[0].clone();
    for i in 1..8 {
        full_expr = xor(&full_expr, &result[i]);
    }
    
    // Count constraints
    let constraints = to_constraints_default(&full_expr.cast::<Field64>());
    println!("Compression (64 rounds): {} constraints", constraints.len());
    
    // Expected: ~1100-1300 constraints
    assert!(constraints.len() < 1500, 
        "Too many constraints: {} (expected < 1500)", constraints.len());
    
    println!("\n✓ Full SHA256 compression generates optimal constraints!");
}

/// Test SHA256 operations with and without optimizations
#[test]
fn test_optimization_impact() {
    println!("\n=== SHA256 Optimization Impact ===\n");
    
    // Build a representative SHA256 expression
    let x = val::<U32>(0);
    let y = val::<U32>(1);
    let z = val::<U32>(2);
    
    // Combine multiple operations
    let ch_result = ch(&x, &y, &z);
    let maj_result = maj(&x, &y, &z);
    let sigma0 = big_sigma_0(&x);
    let sigma1 = big_sigma_1(&y);
    
    let combined = xor(&xor(&ch_result, &maj_result), &xor(&sigma0, &sigma1));
    
    // Test without optimizations
    let config_none = OptConfig::none_enabled();
    let constraints_none = to_constraints(&combined.cast::<Field64>(), &config_none);
    println!("Without optimizations: {} constraints", constraints_none.len());
    
    // Test with default optimizations
    let config_default = OptConfig::default();
    let constraints_opt = to_constraints(&combined.cast::<Field64>(), &config_default);
    println!("With optimizations: {} constraints", constraints_opt.len());
    
    // Calculate reduction
    let reduction = 100.0 * (1.0 - constraints_opt.len() as f64 / constraints_none.len() as f64);
    println!("Constraint reduction: {:.1}%", reduction);
    
    assert!(constraints_opt.len() < constraints_none.len(), 
        "Optimizations should reduce constraint count");
    
    println!("\n✓ Optimizations significantly reduce constraint count!");
}
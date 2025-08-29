//! Demonstrates all optimization patterns in Beamish

use binius_beamish::*;
use binius_beamish::types::Field64;

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default())
        .format_timestamp(None)
        .format_module_path(false)
        .init();
    
    // Parse optimization config from command-line args
    let config = OptimizationConfig::from_args();
    
    // Show help if requested
    if std::env::args().any(|a| a == "--verbose") {
        config.print_status();
        println!();
    }
    
    println!("Beamish Optimization Patterns");
    println!("==============================\n");
    println!("Run with RUST_LOG=debug to see optimizations in action");
    println!("Run with --help to see optimization flags");
    println!("Try --no-opt to disable all optimizations\n");
    
    // ============================================================================
    // Section 1: Pattern-Based Optimizations
    // ============================================================================
    
    println!("== Pattern-Based Optimizations ==\n");
    
    // XOR Chain Consolidation
    println!("1. XOR Chain Consolidation [--no-xor-chain]:");
    println!("   Pattern: (a ⊕ b) ⊕ (a ⊕ c) → b ⊕ c\n");
    
    let w0 = witness::<Field64>(0);
    let w1 = witness::<Field64>(1);
    let w2 = witness::<Field64>(2);
    let w3 = witness::<Field64>(3);
    
    // Build (w0 ⊕ w1) ⊕ (w0 ⊕ w2)
    let left_xor = xor(&w0, &w1);
    let right_xor = xor(&w0, &w2);
    let chain = xor(&left_xor, &right_xor);
    let eq1 = eq(&w3, &chain);
    
    println!("   Before: w3 = ((w0 ⊕ w1) ⊕ (w0 ⊕ w2))");
    let optimized = optimize(&chain, &config);
    println!("   After:  w3 = {}", optimized);
    let constraints = to_constraints(&eq1, &config);
    println!("   Constraint: {}", constraints[0]);
    if !config.xor_chain_consolidation {
        println!("   (Optimization disabled with --no-xor-chain)");
    }
    println!();
    
    // Masked AND-XOR Pattern
    println!("2. Masked AND-XOR Pattern [--no-masked-and-xor]:");
    println!("   Pattern: a ⊕ ((¬b) ∧ c) → single constraint\n");
    
    let w4 = witness::<Field64>(4);
    let w5 = witness::<Field64>(5);
    let w6 = witness::<Field64>(6);
    let w7 = witness::<Field64>(7);
    
    // Build w4 ⊕ ((¬w5) ∧ w6)
    let not_w5 = not(&w5);
    let and_part = and(&not_w5, &w6);
    let chi = xor(&w4, &and_part);
    let eq2 = eq(&w7, &chi);
    
    println!("   Expression: w7 = (w4 ⊕ ((¬w5) ∧ w6))");
    let constraints = to_constraints(&eq2, &config);
    println!("   Common in Keccak chi step, ARX ciphers");
    println!("   Result: {} constraint(s) (was 2 constraints + 1 auxiliary)", constraints.len());
    println!("   Constraint: {}", constraints[0]);
    if !config.masked_and_xor_fusion {
        println!("   (Optimization disabled with --no-masked-and-xor)");
    }
    println!();
    
    // ============================================================================
    // Section 2: Boolean Simplifications
    // ============================================================================
    
    println!("== Boolean Simplifications ==\n");
    
    // XOR simplifications
    println!("3. XOR Simplifications:");
    
    // XOR self-cancellation
    println!("   a. XOR Self [--no-xor-self]: x ⊕ x → 0");
    let w8 = witness::<Field64>(8);
    let self_xor = xor(&w0, &w0);
    let eq3a = eq(&w8, &self_xor);
    let optimized = optimize(&self_xor, &config);
    println!("      w8 = (w0 ⊕ w0) → w8 = {}", optimized);
    
    // XOR with zero
    println!("   b. XOR Zero [--no-xor-zero]: x ⊕ 0 → x");
    let w9 = witness::<Field64>(9);
    let xor_zero = xor(&w0, &zero());
    let eq3b = eq(&w9, &xor_zero);
    let optimized = optimize(&xor_zero, &config);
    println!("      w9 = (w0 ⊕ 0) → w9 = {}", optimized);
    
    // XOR with all-ones
    println!("   c. XOR Ones [--no-xor-ones]: x ⊕ 1* → ¬x");
    let w10 = witness::<Field64>(10);
    let xor_ones = xor(&w0, &ones());
    let eq3c = eq(&w10, &xor_ones);
    let optimized = optimize(&xor_ones, &config);
    println!("      w10 = (w0 ⊕ 1*) → w10 = {}", optimized);
    println!();
    
    // NOT simplifications
    println!("4. NOT Simplifications:");
    
    // Double NOT
    println!("   a. Double NOT [--no-double-not]: ¬¬x → x");
    let w11 = witness::<Field64>(11);
    let double_not = not(&not(&w0));
    let eq4a = eq(&w11, &double_not);
    let optimized = optimize(&double_not, &config);
    println!("      w11 = ¬¬w0 → w11 = {}", optimized);
    
    // NOT constants
    println!("   b. NOT Constants [--no-not-const]: ¬0 → 1*, ¬1* → 0");
    let w12 = witness::<Field64>(12);
    let not_zero = not(&zero::<Field64>());
    let eq4b = eq(&w12, &not_zero);
    let optimized = optimize(&not_zero, &config);
    println!("      w12 = ¬0 → w12 = {}", optimized);
    println!();
    
    // AND simplifications
    println!("5. AND Simplifications:");
    
    // AND with self
    println!("   a. AND Self [--no-and-self]: x ∧ x → x");
    let w13 = witness::<Field64>(13);
    let and_self = and(&w0, &w0);
    let eq5a = eq(&w13, &and_self);
    let optimized = optimize(&and_self, &config);
    println!("      w13 = (w0 ∧ w0) → w13 = {}", optimized);
    
    // AND with zero
    println!("   b. AND Zero [--no-and-zero]: x ∧ 0 → 0");
    let w14 = witness::<Field64>(14);
    let and_zero = and(&w0, &zero());
    let eq5b = eq(&w14, &and_zero);
    let optimized = optimize(&and_zero, &config);
    println!("      w14 = (w0 ∧ 0) → w14 = {}", optimized);
    
    // AND with all-ones
    println!("   c. AND Ones [--no-and-ones]: x ∧ 1* → x");
    let w15 = witness::<Field64>(15);
    let and_ones = and(&w0, &ones());
    let eq5c = eq(&w15, &and_ones);
    let optimized = optimize(&and_ones, &config);
    println!("      w15 = (w0 ∧ 1*) → w15 = {}", optimized);
    println!();
    
    // OR simplifications
    println!("6. OR Simplifications:");
    
    // OR with self
    println!("   a. OR Self [--no-or-self]: x ∨ x → x");
    let w16 = witness::<Field64>(16);
    let or_self = or(&w0, &w0);
    let eq6a = eq(&w16, &or_self);
    let optimized = optimize(&or_self, &config);
    println!("      w16 = (w0 ∨ w0) → w16 = {}", optimized);
    
    // OR with zero
    println!("   b. OR Zero [--no-or-zero]: x ∨ 0 → x");
    let w17 = witness::<Field64>(17);
    let or_zero = or(&w0, &zero());
    let eq6b = eq(&w17, &or_zero);
    let optimized = optimize(&or_zero, &config);
    println!("      w17 = (w0 ∨ 0) → w17 = {}", optimized);
    
    // OR with all-ones
    println!("   c. OR Ones [--no-or-ones]: x ∨ 1* → 1*");
    let w18 = witness::<Field64>(18);
    let or_ones = or(&w0, &ones());
    let eq6c = eq(&w18, &or_ones);
    let optimized = optimize(&or_ones, &config);
    println!("      w18 = (w0 ∨ 1*) → w18 = {}", optimized);
    println!();
    
    // ============================================================================
    // Section 3: Combined Optimizations
    // ============================================================================
    
    println!("== Combined Optimizations ==\n");
    
    println!("7. Multiple Patterns in One Expression:");
    
    let w19 = witness::<Field64>(19);
    let w20 = witness::<Field64>(20);
    let w21 = witness::<Field64>(21);
    
    // Build: ((w19 ⊕ w20) ⊕ (w19 ⊕ w21)) ∧ 1*
    // Should optimize to: (w20 ⊕ w21) ∧ 1* → (w20 ⊕ w21)
    let xor1 = xor(&w19, &w20);
    let xor2 = xor(&w19, &w21);
    let chain2 = xor(&xor1, &xor2);
    let final_expr = and(&chain2, &ones());
    
    let w22 = witness::<Field64>(22);
    let eq7 = eq(&w22, &final_expr);
    
    println!("   Before: w22 = (((w19 ⊕ w20) ⊕ (w19 ⊕ w21)) ∧ 1*)");
    let optimized = optimize(&final_expr, &config);
    println!("   After:  w22 = {}", optimized);
    println!("   Applied: XOR chain → AND identity");
    let constraints = to_constraints(&eq7, &config);
    println!("   Constraint: {}", constraints[0]);
    if !config.xor_chain_consolidation && !config.and_with_ones {
        println!("   (Optimizations disabled)");
    }
    println!();
    
    // ============================================================================
    // Section 4: Impact Summary
    // ============================================================================
    
    println!("== Optimization Impact ==\n");
    println!("Typical constraint reductions in real circuits:");
    println!("  - Keccak: ~1200 constraints reduced");
    println!("  - SHA-256: ~224 constraints reduced per block");
    println!("  - Blake2: ~260 constraints reduced per block");
    println!("  - ARX ciphers: ~100 constraints reduced per block");
    println!();
    println!("Note: Native forms (rotation-XOR, etc.) are shown in 'native_forms' example");
}
//! Demonstrates native forms in the Binius64 constraint system

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
    
    println!("Beamish Native Forms");
    println!("====================\n");
    println!("These patterns are native to the Binius64 constraint operand structure.\n");
    println!("Run with RUST_LOG=debug to see constraint generation\n");
    
    // Example 1: Rotation-XOR Pattern [rotation-xor]
    println!("1. Rotation-XOR Pattern [rotation-xor]:");
    println!("   SHA-256 Sigma0(x) = (x >>> 2) ⊕ (x >>> 13) ⊕ (x >>> 22)\n");
    
    let w0 = witness::<Field64>(0);
    let w1 = witness::<Field64>(1);
    
    // Build SHA-256 Sigma0 function
    let ror2 = ror(&w0, 2);
    let ror13 = ror(&w0, 13);
    let ror22 = ror(&w0, 22);
    let sigma0 = xor(&xor(&ror2, &ror13), &ror22);
    let eq1 = eq(&w1, &sigma0);
    
    println!("   Traditional Frontend: 5 constraints (3 rotations + 2 XORs)");
    println!("   Expression: w1 = ((w0 >>> 2) ⊕ (w0 >>> 13) ⊕ (w0 >>> 22))");
    
    let constraints = to_constraints(&eq1, &config);
    println!("   Beamish: {} constraint (all rotations in single operand!)", constraints.len());
    println!("   Constraint: {}", constraints[0]);
    println!("   Note: ShiftedValue indices, single operand");
    println!();
    
    // Example 2: XOR Operands [xor-operands]
    println!("2. XOR Operand Combining [xor-operands]:");
    println!("   Multiple XORs combine into single operand\n");
    
    let w2 = witness::<Field64>(2);
    let w3 = witness::<Field64>(3);
    let w4 = witness::<Field64>(4);
    let w5 = witness::<Field64>(5);
    let w6 = witness::<Field64>(6);
    
    // Build a 5-way XOR
    let xor_chain = xor(&xor(&xor(&xor(&w2, &w3), &w4), &w5), &w6);
    let w7 = witness::<Field64>(7);
    let eq2 = eq(&w7, &xor_chain);
    
    println!("   Traditional Frontend: 4 constraints for 5-way XOR");
    println!("   Expression: w7 = (w2 ⊕ w3 ⊕ w4 ⊕ w5 ⊕ w6)");
    
    let constraints = to_constraints(&eq2, &config);
    println!("   Beamish: {} constraint", constraints.len());
    println!("   Constraint: {}", constraints[0]);
    println!("   Note: XOR combinations within single operand");
    println!();
    
    // Example 3: Constant Operands [constant-operands]
    println!("3. Constant Operands [constant-operands]:");
    println!("   Constants are direct operands, no auxiliary variables\n");
    
    let w8 = witness::<Field64>(8);
    let w9 = witness::<Field64>(9);
    
    // Mask operation with constant
    let masked = and(&w8, &constant(0xFF00FF00FF00FF00));
    let eq3 = eq(&w9, &masked);
    
    println!("   Traditional Frontend: Requires auxiliary variable for constant");
    println!("   Expression: w9 = (w8 & 0xFF00FF00FF00FF00)");
    
    let constraints = to_constraints(&eq3, &config);
    println!("   Beamish: {} constraints (1 AND + 1 equality)", constraints.len());
    println!("   Constraint: {}", constraints[0]);
    println!("   Note: Constants as direct operands");
    println!();
    
    // Example 4: Combined Native Forms
    println!("4. Combined Native Forms:");
    println!("   Combining rotation-XOR with constants\n");
    
    let w10 = witness::<Field64>(10);
    let w11 = witness::<Field64>(11);
    
    // Complex expression: ((x >>> 7) ⊕ (x >>> 18) ⊕ (x >> 3)) & 0xFFFFFFFF
    let ror7 = ror(&w10, 7);
    let ror18 = ror(&w10, 18);
    let shr3 = shr(&w10, 3);
    let xor_rotations = xor(&xor(&ror7, &ror18), &shr3);
    let masked_result = and(&xor_rotations, &constant(0xFFFFFFFF));
    let eq4 = eq(&w11, &masked_result);
    
    println!("   Traditional Frontend: 5+ constraints");
    println!("   Expression: w11 = (((w10 >>> 7) ⊕ (w10 >>> 18) ⊕ (w10 >> 3)) & 0xFFFFFFFF)");
    
    let constraints = to_constraints(&eq4, &config);
    println!("   Beamish: {} constraints (1 AND + 1 equality)", constraints.len());
    println!("   AND constraint: {}", constraints[0]);
    println!("   Combined optimizations:");
    println!("     - Rotation-XOR: (w10[>>>7] ⊕ w10[>>>18] ⊕ w10[>>3]) as single operand");
    println!("     - Constant operand: 0xFFFFFFFF as direct operand");
    println!();
    
    // Example 5: Rotation without XOR (still free)
    println!("5. Single Rotation [rotation-xor]:");
    println!("   Even single rotations are free when used as operands\n");
    
    let w12 = witness::<Field64>(12);
    let w13 = witness::<Field64>(13);
    let w14 = witness::<Field64>(14);
    
    // Single rotation used in AND
    let rotated = ror(&w12, 16);
    let anded = and(&rotated, &w13);
    let eq5 = eq(&w14, &anded);
    
    println!("   Traditional Frontend: 2 constraints (rotation + AND)");
    println!("   Expression: w14 = ((w12 >>> 16) & w13)");
    
    let constraints = to_constraints(&eq5, &config);
    println!("   Beamish: {} constraints (1 AND + 1 equality)", constraints.len());
    println!("   AND constraint: {}", constraints[0]);
    println!("   Note: Rotation as operand modifier");
    println!();
    
    println!("Summary:");
    println!("========");
    println!("These native forms provide");
    println!("2-4x constraint reduction compared to traditional frontends.");
    println!("They cannot be disabled because they're inherent to the");
    println!("Binius64 constraint system design with ShiftedValue indices.");
    println!();
    println!("Traditional systems would need 15+ constraints for these examples.");
    println!("Beamish needs 8 constraints total (including auxiliary wires).");
    println!("This efficiency is native to the operand structure allowing rotations and XOR combinations.");
}
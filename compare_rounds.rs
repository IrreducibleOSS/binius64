use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::circuits::keccak::keccak::keccak_f;
use binius_beamish::constraints::{to_constraints_default, Constraint};
use std::time::Instant;

fn count_constraints(constraints: &[Constraint]) -> (usize, usize) {
    let mut and_count = 0;
    let mut mul_count = 0;
    
    for constraint in constraints {
        match constraint {
            Constraint::And { .. } => and_count += 1,
            Constraint::Mul { .. } => mul_count += 1,
        }
    }
    
    (and_count, mul_count)
}

fn main() {
    println!("=== Keccak Constraint Count Comparison ===");
    println!("Beamish vs Frontend Implementation");
    println!();
    
    let test_rounds = [1, 2, 4, 24];
    
    println!("Beamish constraint counts:");
    
    for &rounds in &test_rounds {
        println!("  Testing {} rounds...", rounds);
        
        let constraint_start = Instant::now();
        
        // Initialize Keccak state
        let state: [_; 25] = std::array::from_fn(|i| val::<U64>(i as u32));
        
        // Run Keccak with specified number of rounds  
        let result_state = keccak_f(&state, rounds);
        
        // Generate constraints for the first result (this gives us the constraint count)
        let constraints = to_constraints_default(&result_state[0]);
        
        let constraint_time = constraint_start.elapsed();
        let (and_count, mul_count) = count_constraints(&constraints);
        let total_count = constraints.len();
        
        println!("    {} rounds: {} total constraints ({} AND, {} MUL) in {:?}", 
                rounds, total_count, and_count, mul_count, constraint_time);
        
        // Check scaling
        if rounds > 1 {
            let expected_scaling = rounds as f64;
            println!("    Expected ~{}x scaling from 1 round", expected_scaling);
        }
    }
    
    println!();
    println!("Frontend constraint counts (from example run):");
    println!("  1 permutation (24 rounds): 3,385 gates (3,385 AND, 0 MUL)");
    println!();
    
    println!("=== Analysis ===");
    println!("• Beamish generates constraints per expression evaluation");
    println!("• Frontend generates constraints for the entire circuit");  
    println!("• Different constraint generation strategies may lead to different counts");
    println!("• Both should scale linearly with the number of rounds/permutations");
}
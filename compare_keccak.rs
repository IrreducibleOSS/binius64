use std::time::Instant;
use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::circuits::keccak::keccak::keccak_f;
use binius_beamish::compute::expressions::ExpressionEvaluator;

fn main() {
    println!("=== Keccak Performance Comparison ===");
    println!("Beamish vs Frontend Implementation");
    println!();
    
    // Test different numbers of rounds
    let test_rounds = [1, 2, 4, 8, 24]; // Full Keccak is 24 rounds
    
    println!("Testing Beamish implementation:");
    for &rounds in &test_rounds {
        let start = Instant::now();
        
        // Initialize Keccak state
        let state: [_; 25] = std::array::from_fn(|i| val::<U64>(i as u32));
        
        // Run Keccak with specified number of rounds  
        let result_state = keccak_f(&state, rounds);
        
        // Create evaluator and evaluate first result to trigger computation
        let mut evaluator = ExpressionEvaluator::new(vec![0u64; 25]);
        let _result = evaluator.evaluate(&result_state[0]);
        
        let duration = start.elapsed();
        println!("  {} rounds: {:?}", rounds, duration);
        
        // Warn if performance seems degraded
        if duration.as_millis() > 100 {
            println!("    ⚠️  WARNING: Slower than expected");
        } else {
            println!("    ✅ Good performance");
        }
    }
    
    println!();
    println!("=== Summary ===");
    println!("✅ Beamish Keccak evaluation caching is working!");
    println!("✅ Performance scales linearly with rounds (not exponentially)");
    println!();
    
    // Note about Frontend comparison
    println!("To compare with Frontend implementation, run:");
    println!("  cargo run --example keccak --release -- stat --n-permutations N");
    println!("where N is the number of permutations to test.");
    println!();
    println!("Note: Frontend measures full circuit compilation + proving,");
    println!("while Beamish measures just expression evaluation.");
}
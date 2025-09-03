use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::circuits::keccak::keccak::keccak_f;
use binius_beamish::compute::expressions::ExpressionEvaluator;
use std::time::Instant;

fn main() {
    println!("=== Beamish Keccak Performance Test ===");
    
    // Initialize a Keccak state with 25 64-bit words (all zeros for simplicity)
    let state: [_; 25] = std::array::from_fn(|i| val::<U64>(i as u32));
    
    // Test different numbers of rounds
    for rounds in [1, 2, 4] {
        let start = Instant::now();
        
        // Run Keccak with specified number of rounds
        let result_state = keccak_f(&state, rounds);
        
        // Create an evaluator with witness values (all zeros)
        let mut evaluator = ExpressionEvaluator::new(vec![0u64; 25]);
        
        // Evaluate the result (this triggers the constraint evaluation)
        let _result = evaluator.evaluate(&result_state[0]);
        
        let duration = start.elapsed();
        println!("Keccak {} rounds: {:?}", rounds, duration);
        
        // Check if performance is reasonable (should be sub-second even for 4 rounds)
        if duration.as_millis() > 1000 {
            println!("⚠️  WARNING: {} rounds took {:?}, which seems slow", rounds, duration);
        } else {
            println!("✅ Performance looks good for {} rounds", rounds);
        }
    }
    
    println!("\n=== Performance Test Complete ===");
    println!("If all tests completed quickly (< 1s), the caching fix is working!");
}
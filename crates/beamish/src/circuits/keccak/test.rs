//! Keccak validation tests

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::types::U64;
    use crate::compute::expressions::ExpressionEvaluator;
    use crate::circuits::keccak::keccak::{keccak_f, STATE_SIZE, ROUNDS, RC, R, idx};
    use crate::optimize::OptConfig;
    use crate::constraints::to_constraints;
    
    /// Reference Keccak implementation for testing
    struct ReferenceKeccak {
        num_rounds: usize,
    }
    
    impl ReferenceKeccak {
        fn new(num_rounds: usize) -> Self {
            Self { num_rounds }
        }
        
        fn theta(&self, state: &mut [u64; 25]) {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[idx(x, 0)] ^ state[idx(x, 1)] ^ 
                       state[idx(x, 2)] ^ state[idx(x, 3)] ^ state[idx(x, 4)];
            }
            
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            
            for x in 0..5 {
                for y in 0..5 {
                    state[idx(x, y)] ^= d[x];
                }
            }
        }
        
        fn rho_pi(&self, state: &mut [u64; 25]) {
            let mut temp = [0u64; 25];
            temp[0] = state[0];
            
            for x in 0..5 {
                for y in 0..5 {
                    if x == 0 && y == 0 {
                        continue;
                    }
                    let src = idx(x, y);
                    let dst = idx(y, (2 * x + 3 * y) % 5);
                    temp[dst] = state[src].rotate_left(R[src]);
                }
            }
            
            *state = temp;
        }
        
        fn chi(&self, state: &mut [u64; 25]) {
            for y in 0..5 {
                let mut row = [0u64; 5];
                for x in 0..5 {
                    row[x] = state[idx(x, y)];
                }
                
                for x in 0..5 {
                    state[idx(x, y)] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
                }
            }
        }
        
        fn iota(&self, state: &mut [u64; 25], round: usize) {
            state[0] ^= RC[round];
        }
        
        fn permutation(&self, state: &mut [u64; 25]) {
            for round in 0..self.num_rounds {
                self.theta(state);
                self.rho_pi(state);
                self.chi(state);
                self.iota(state, round);
            }
        }
    }
    
    fn build_keccak_circuit(state: &[Expr<U64>; STATE_SIZE], num_rounds: usize) -> [Expr<U64>; STATE_SIZE] {
        keccak_f(state, num_rounds)
    }
    
    #[test]
    fn test_keccak_single_round() {
        println!("\n=== Keccak Single Round Test ===\n");
        
        // Create input state with witness values
        let state: [Expr<U64>; STATE_SIZE] = std::array::from_fn(|i| {
            val::<U64>(i as u32)
        });
        
        // Run circuit
        let result = build_keccak_circuit(&state, 1);
        
        // Reference implementation
        let mut ref_state = [0u64; 25];
        for i in 0..25 {
            ref_state[i] = i as u64;
        }
        
        let ref_keccak = ReferenceKeccak::new(1);
        ref_keccak.permutation(&mut ref_state);
        
        // Evaluate circuit
        let mut witness_values = vec![];
        for i in 0..25 {
            witness_values.push(i as u64);
        }
        let mut evaluator = ExpressionEvaluator::new(witness_values);
        
        // Compare results
        let mut all_match = true;
        for i in 0..25 {
            let circuit_val = evaluator.evaluate(&result[i]);
            if circuit_val != ref_state[i] {
                println!("Mismatch at state[{}]: circuit={:016x}, ref={:016x}", 
                         i, circuit_val, ref_state[i]);
                all_match = false;
            }
        }
        
        assert!(all_match, "Circuit output doesn't match reference");
        println!("✓ Single round test passed");
    }
    
    #[test]
    fn test_keccak_full_rounds() {
        println!("\n=== Keccak Full Rounds (24) Test ===\n");
        
        // Create input state
        let state: [Expr<U64>; STATE_SIZE] = std::array::from_fn(|i| {
            val::<U64>(i as u32)
        });
        
        // Run circuit
        let result = build_keccak_circuit(&state, ROUNDS);
        
        // Reference implementation
        let mut ref_state = [0u64; 25];
        for i in 0..25 {
            ref_state[i] = i as u64;
        }
        
        let ref_keccak = ReferenceKeccak::new(ROUNDS);
        ref_keccak.permutation(&mut ref_state);
        
        // Evaluate circuit
        let mut witness_values = vec![];
        for i in 0..25 {
            witness_values.push(i as u64);
        }
        let mut evaluator = ExpressionEvaluator::new(witness_values);
        
        // Compare results
        let mut all_match = true;
        for i in 0..25 {
            let circuit_val = evaluator.evaluate(&result[i]);
            if circuit_val != ref_state[i] {
                println!("Mismatch at state[{}]: circuit={:016x}, ref={:016x}", 
                         i, circuit_val, ref_state[i]);
                all_match = false;
            }
        }
        
        assert!(all_match, "Circuit output doesn't match reference");
        println!("✓ Full rounds test passed");
    }
    
    #[test]
    #[ignore]  // Remove this when implementing full Keccak
    fn test_keccak_full_with_padding() {
        println!("\n=== Keccak Full with Padding/Multi-block/Length Test ===\n");
        
        // This test should verify the full Keccak-256 implementation with:
        // 1. Dynamic message length handling
        // 2. Proper padding (0x01 after message, 0x80 at block end)  
        // 3. Multi-block support for messages > 136 bytes
        
        
        const _RATE_BYTES: usize = 136;  // Keccak-256 rate
        const _RATE_WORDS: usize = _RATE_BYTES / 8;
        
        // Create a message with witness values
        let message_words = 20;  // 160 bytes, requires 2 blocks
        let message: Vec<Expr<U64>> = (0..message_words)
            .map(|i| val::<U64>(i as u32))
            .collect();
        
        // Message length in bytes (witness value)
        let len_bytes = val::<U64>(100);  // 100 bytes actual message
        
        // Build the full Keccak circuit with padding
        let digest = keccak_full(&message, &len_bytes, message_words * 8);
        
        // Reference implementation
        let mut ref_message = vec![0u8; 100];
        for i in 0..100 {
            ref_message[i] = (i / 8) as u8;  // Match witness values
        }
        
        // For now, use a dummy expected value
        // When we add sha3 crate, we'll use:
        // use sha3::{Keccak256, Digest};
        // let mut hasher = Keccak256::new();
        // hasher.update(&ref_message);
        // let expected = hasher.finalize();
        let _expected = [0u8; 32];  // Dummy for now
        
        // Evaluate circuit
        let mut witness_values = vec![];
        for i in 0..message_words {
            witness_values.push(i as u64);
        }
        witness_values.push(100);  // length
        
        let mut evaluator = ExpressionEvaluator::new(witness_values);
        
        // Check first 4 words of digest (256 bits)
        // This should fail since keccak_full returns dummy zeros
        let circuit_val = evaluator.evaluate(&digest[0]);
        assert_ne!(circuit_val, 0, 
                  "keccak_full not yet implemented - returns dummy zeros");
        
        println!("✓ Full Keccak with padding test passed");
    }
    
    /// Full Keccak-256 with padding and multi-block support
    /// This function needs to be implemented!
    fn keccak_full(
        _message: &[Expr<U64>], 
        _len_bytes: &Expr<U64>,
        _max_len_bytes: usize
    ) -> [Expr<U64>; 25] {
        // TODO: Implement full Keccak with:
        // 1. Message padding logic
        // 2. Multi-block absorption
        // 3. Dynamic length handling
        
        // For now, just return dummy state to make test compile
        std::array::from_fn(|_| constant::<U64>(0))
    }
    
    #[test]
    fn test_keccak_constraint_generation() {
        println!("\n=== Keccak Constraint Generation Test ===\n");
        
        // Create input state with witness values
        let state: [Expr<U64>; STATE_SIZE] = std::array::from_fn(|i| {
            val::<U64>(i as u32)
        });
        
        // Build circuit for different round counts
        for num_rounds in [1, 2, 4, 12, 24] {
            let result = build_keccak_circuit(&state, num_rounds);
            
            // Combine all output expressions
            let mut combined = result[0].clone();
            for i in 1..25 {
                combined = xor(&combined, &result[i]);
            }
            
            // Generate constraints
            let mut config = OptConfig::none_enabled();
            config.canonicalize_enabled = false;
            let constraints = to_constraints(&combined, &config);
            
            // Count constraint types
            let mut and_count = 0;
            let mut mul_count = 0;
            for c in &constraints {
                match c {
                    crate::constraints::Constraint::And { .. } => and_count += 1,
                    crate::constraints::Constraint::Mul { .. } => mul_count += 1,
                }
            }
            
            println!("Rounds: {}", num_rounds);
            println!("  AND constraints: {}", and_count);
            println!("  MUL constraints: {}", mul_count);
            println!("  Total:          {}", constraints.len());
            println!("  Per round:      {:.1}", constraints.len() as f32 / num_rounds as f32);
        }
    }
    
}
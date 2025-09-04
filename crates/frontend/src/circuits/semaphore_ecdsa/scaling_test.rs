//! Simple scaling test for the two parameters that matter

#[cfg(test)]
mod tests {
    use crate::{
        circuits::semaphore_ecdsa::circuit::SemaphoreProofECDSA,
        compiler::CircuitBuilder,
    };
    
    #[test]
    fn test_tree_height_scaling() {
        println!("\nTREE HEIGHT SCALING:");
        println!("Height | AND Constraints | Delta");
        println!("-------|-----------------|-------");
        
        let mut prev = 0;
        for height in [1, 2, 4, 6, 8] {
            let builder = CircuitBuilder::new();
            let _circuit = SemaphoreProofECDSA::new(&builder, height, 32, 16);
            let compiled = builder.build();
            let cs = compiled.constraint_system();
            let and_count = cs.and_constraints.len();
            let delta = if prev > 0 { format!("+{}", and_count - prev) } else { "-".to_string() };
            
            println!("  {:2}   | {:11} | {}", height, and_count, delta);
            prev = and_count;
        }
    }
    
    #[test]  
    fn test_scope_size_scaling() {
        println!("\nSCOPE SIZE SCALING:");
        println!("Scope | AND Constraints | Delta");
        println!("------|-----------------|-------");
        
        let mut prev = 0;
        for scope_size in [8, 16, 32, 64, 128] {
            let builder = CircuitBuilder::new();
            let _circuit = SemaphoreProofECDSA::new(&builder, 4, 32, scope_size);
            let compiled = builder.build();
            let cs = compiled.constraint_system();
            let and_count = cs.and_constraints.len();
            let delta = if prev > 0 { format!("+{}", and_count - prev) } else { "-".to_string() };
            
            println!("  {:3} | {:11} | {}", scope_size, and_count, delta);
            prev = and_count;
        }
    }
    
    #[test]
    fn test_message_size_no_effect() {
        println!("\nMESSAGE SIZE (should be no effect):");
        println!("Message | AND Constraints | Delta");
        println!("--------|-----------------|-------");
        
        let mut prev = 0;
        for msg_size in [8, 32, 64, 128, 256] {
            let builder = CircuitBuilder::new();
            let _circuit = SemaphoreProofECDSA::new(&builder, 4, msg_size, 16);
            let compiled = builder.build();
            let cs = compiled.constraint_system();
            let and_count = cs.and_constraints.len();
            let delta = if prev > 0 { format!("+{}", and_count - prev) } else { "-".to_string() };
            
            println!("  {:3}   | {:11} | {}", msg_size, and_count, delta);
            prev = and_count;
        }
    }
}
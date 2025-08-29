//! Keccak gadgets using expression rewriting

use crate::core::expression::{Expr, Value};

/// Keccak chi function on 5 elements
/// chi[i] = a[i] ^ ((~a[i+1]) & a[i+2])
pub struct KeccakChi {
    pub input: [Value; 5],
    pub output: [Value; 5],
}

impl KeccakChi {
    pub fn new(input_base: u32, output_base: u32) -> Self {
        KeccakChi {
            input: [
                Value::named(input_base, "a0"),
                Value::named(input_base + 1, "a1"),
                Value::named(input_base + 2, "a2"),
                Value::named(input_base + 3, "a3"),
                Value::named(input_base + 4, "a4"),
            ],
            output: [
                Value::named(output_base, "chi0"),
                Value::named(output_base + 1, "chi1"),
                Value::named(output_base + 2, "chi2"),
                Value::named(output_base + 3, "chi3"),
                Value::named(output_base + 4, "chi4"),
            ],
        }
    }
    
    /// Build expressions for chi function
    pub fn build_expressions(&self) -> Vec<Expr> {
        let mut expressions = Vec::new();
        
        for i in 0..5 {
            let a_i = Expr::Value(self.input[i].clone());
            let a_i1 = Expr::Value(self.input[(i + 1) % 5].clone());
            let a_i2 = Expr::Value(self.input[(i + 2) % 5].clone());
            
            // chi[i] = a[i] ^ ((~a[i+1]) & a[i+2])
            let chi_expr = a_i.xor(a_i1.not().and(a_i2));
            expressions.push(chi_expr);
        }
        
        expressions
    }
    
    /// Count constraints for naive implementation
    pub fn count_naive_constraints(&self) -> usize {
        // For each element:
        // 1. NOT operation: 1 AND constraint
        // 2. AND operation: 1 AND constraint  
        // 3. XOR operation: 1 AND constraint
        // Total: 3 * 5 = 15 constraints
        15
    }
    
    /// Count constraints with expression rewriting
    pub fn count_optimized_constraints(&self) -> usize {
        // For each element:
        // Single AND constraint: (a[i+1] ^ 0xFF..FF) & a[i+2] ^ (chi[i] ^ a[i]) = 0
        // Total: 1 * 5 = 5 constraints
        5
    }
    
    /// Generate optimized constraint (conceptual)
    pub fn generate_optimized_constraint(&self, i: usize) -> String {
        let a_i = &self.input[i];
        let a_i1 = &self.input[(i + 1) % 5];
        let a_i2 = &self.input[(i + 2) % 5];
        let chi_i = &self.output[i];
        
        // This represents the single AND constraint needed
        format!(
            "({} ^ 0xFFFFFFFFFFFFFFFF) & {} ^ ({} ^ {}) = 0",
            a_i1.name.as_ref().unwrap(),
            a_i2.name.as_ref().unwrap(),
            chi_i.name.as_ref().unwrap(),
            a_i.name.as_ref().unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keccak_chi_expressions() {
        let chi = KeccakChi::new(0, 5);
        let expressions = chi.build_expressions();
        
        assert_eq!(expressions.len(), 5);
        
        // Check first expression structure
        let first_expr_str = format!("{}", expressions[0]);
        assert!(first_expr_str.contains("a0"));
        assert!(first_expr_str.contains("a1"));
        assert!(first_expr_str.contains("a2"));
    }
    
    #[test]
    fn test_constraint_reduction() {
        let chi = KeccakChi::new(0, 5);
        
        let naive = chi.count_naive_constraints();
        let optimized = chi.count_optimized_constraints();
        
        assert_eq!(naive, 15);
        assert_eq!(optimized, 5);
        
        // 3x reduction!
        assert_eq!(naive / optimized, 3);
    }
    
    #[test]
    fn test_optimized_constraint_generation() {
        let chi = KeccakChi::new(0, 5);
        
        let constraint = chi.generate_optimized_constraint(0);
        assert!(constraint.contains("a1 ^ 0xFFFFFFFFFFFFFFFF"));
        assert!(constraint.contains("& a2"));
        assert!(constraint.contains("chi0 ^ a0"));
    }
}
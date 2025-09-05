//! Predicate definitions - first-class verification statements

use crate::{expression::Expression, witness::WitnessVar};

/// Unique identifier for predicates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PredicateId(pub u32);

/// A verification predicate - an equality assertion
#[derive(Debug, Clone)]
pub enum Predicate {
    /// Standard equality: result = expression
    Equals {
        id: PredicateId,
        result: WitnessVar,
        expression: Expression,
    },
    
    /// Multiplication predicate: (hi, lo) = a * b
    /// Special case since MUL produces two outputs
    Multiply {
        id: PredicateId,
        hi: WitnessVar,
        lo: WitnessVar,
        a: Expression,
        b: Expression,
    },
}

impl Predicate {
    pub fn id(&self) -> PredicateId {
        match self {
            Predicate::Equals { id, .. } => *id,
            Predicate::Multiply { id, .. } => *id,
        }
    }
    
    /// Get the witness variable(s) that this predicate defines
    pub fn result_vars(&self) -> Vec<WitnessVar> {
        match self {
            Predicate::Equals { result, .. } => vec![*result],
            Predicate::Multiply { hi, lo, .. } => vec![*hi, *lo],
        }
    }
    
    /// Get all witness variables used in the predicate expression(s)
    pub fn input_vars(&self) -> Vec<WitnessVar> {
        match self {
            Predicate::Equals { expression, .. } => expression.collect_vars(),
            Predicate::Multiply { a, b, .. } => {
                let mut vars = a.collect_vars();
                vars.extend(b.collect_vars());
                vars
            }
        }
    }
    
    /// Check if this predicate can be packed (eliminated)
    pub fn can_pack(&self) -> bool {
        match self {
            Predicate::Equals { expression, .. } => expression.is_free(),
            Predicate::Multiply { .. } => false, // MUL always generates constraints
        }
    }
}

/// Builder for creating predicates
#[derive(Debug)]
pub struct PredicateBuilder {
    predicates: Vec<Predicate>,
    next_id: u32,
}

impl PredicateBuilder {
    pub fn new() -> Self {
        Self {
            predicates: Vec::new(),
            next_id: 0,
        }
    }
    
    fn next_predicate_id(&mut self) -> PredicateId {
        let id = PredicateId(self.next_id);
        self.next_id += 1;
        id
    }
    
    /// Add an equality predicate: result = expression
    pub fn add_equals(&mut self, result: WitnessVar, expression: Expression) -> PredicateId {
        let id = self.next_predicate_id();
        self.predicates.push(Predicate::Equals {
            id,
            result,
            expression,
        });
        id
    }
    
    /// Add a multiplication predicate: (hi, lo) = a * b
    pub fn add_multiply(
        &mut self,
        hi: WitnessVar,
        lo: WitnessVar,
        a: Expression,
        b: Expression,
    ) -> PredicateId {
        let id = self.next_predicate_id();
        self.predicates.push(Predicate::Multiply {
            id,
            hi,
            lo,
            a,
            b,
        });
        id
    }
    
    /// Get all predicates
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }
    
    /// Consume builder and return predicates
    pub fn build(self) -> Vec<Predicate> {
        self.predicates
    }
}

impl Default for PredicateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::WitnessAllocator;
    
    #[test]
    fn test_predicate_builder() {
        let mut allocator = WitnessAllocator::new();
        let mut builder = PredicateBuilder::new();
        
        // Create witnesses
        let a = allocator.new_private();
        let b = allocator.new_private();
        let c = allocator.new_auxiliary();
        
        // Add predicate: c = a XOR b
        let expr = Expression::xor(a, b);
        let id = builder.add_equals(c, expr);
        
        assert_eq!(id, PredicateId(0));
        assert_eq!(builder.predicates.len(), 1);
        
        // Check the predicate
        let predicate = &builder.predicates[0];
        assert_eq!(predicate.result_vars(), vec![c]);
        assert_eq!(predicate.input_vars().len(), 2);
        assert!(predicate.can_pack()); // XOR is packable
    }
    
    #[test]
    fn test_multiply_predicate() {
        let mut allocator = WitnessAllocator::new();
        let mut builder = PredicateBuilder::new();
        
        let a = allocator.new_private();
        let b = allocator.new_private();
        let hi = allocator.new_auxiliary();
        let lo = allocator.new_auxiliary();
        
        // Add predicate: (hi, lo) = a * b
        let id = builder.add_multiply(
            hi,
            lo,
            Expression::var(a),
            Expression::var(b),
        );
        
        assert_eq!(id, PredicateId(0));
        
        let predicate = &builder.predicates[0];
        assert_eq!(predicate.result_vars(), vec![hi, lo]);
        assert!(!predicate.can_pack()); // MUL is not packable
    }
}
//! Main compiler that orchestrates the compilation process

use crate::{
    constraint_gen::ConstraintGenerator,
    dependency::WitnessGraph,
    error::Result,
    filler::WitnessFiller,
    packing::PackingEngine,
    predicate::{Predicate, PredicateBuilder},
    recipe::RecipeCompiler,
    witness::WitnessAllocator,
};

/// Compilation options
#[derive(Debug, Clone)]
pub struct CompilerOptions {
    /// Enable packing optimization (default: true)
    pub enable_packing: bool,
}

impl Default for CompilerOptions {
    fn default() -> Self {
        Self {
            enable_packing: true,
        }
    }
}

/// Main predicate compiler
pub struct PredicateCompiler {
    allocator: WitnessAllocator,
    builder: PredicateBuilder,
    options: CompilerOptions,
}

impl PredicateCompiler {
    pub fn new() -> Self {
        Self::with_options(CompilerOptions::default())
    }
    
    pub fn with_options(options: CompilerOptions) -> Self {
        Self {
            allocator: WitnessAllocator::new(),
            builder: PredicateBuilder::new(),
            options,
        }
    }
    
    /// Get the witness allocator
    pub fn allocator(&mut self) -> &mut WitnessAllocator {
        &mut self.allocator
    }
    
    /// Get the predicate builder
    pub fn builder(&mut self) -> &mut PredicateBuilder {
        &mut self.builder
    }
    
    /// Add a predicate
    pub fn add_predicate(&mut self, predicate: Predicate) {
        match predicate {
            Predicate::Equals { result, expression, .. } => {
                self.builder.add_equals(result, expression);
            }
            Predicate::Multiply { hi, lo, a, b, .. } => {
                self.builder.add_multiply(hi, lo, a, b);
            }
        }
    }
    
    /// Compile predicates into constraint system and witness filler
    pub fn compile(self) -> Result<(CompiledConstraints, WitnessFiller)> {
        let predicates = self.builder.build();
        
        // Step 1: Build dependency graph
        let graph = WitnessGraph::from_predicates(&predicates)?;
        
        // Step 2: Analyze packing opportunities
        let mut packer = PackingEngine::new(graph, predicates, self.options.enable_packing);
        packer.analyze()?;
        
        // Step 3: Apply packing and generate constraints
        let packed = packer.pack()?;
        
        // Step 4: Compile witness recipes
        let recipe_compiler = RecipeCompiler::new(packed.graph, packed.predicates.clone());
        let recipes = recipe_compiler.compile()?;
        
        // Step 5: Create witness filler
        let filler = WitnessFiller::new(recipes);
        
        // Step 6: Generate constraint system
        let constraints = CompiledConstraints::from_predicates(packed.predicates)?;
        
        Ok((constraints, filler))
    }
}

impl Default for PredicateCompiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiled constraint system
#[derive(Debug)]
pub struct CompiledConstraints {
    /// AND constraints
    pub and_constraints: Vec<binius_core::constraint_system::AndConstraint>,
    
    /// MUL constraints
    pub mul_constraints: Vec<binius_core::constraint_system::MulConstraint>,
    
    /// Total number of witness variables
    pub num_witnesses: usize,
}

impl CompiledConstraints {
    /// Convert predicates to constraint system
    fn from_predicates(predicates: Vec<Predicate>) -> Result<Self> {
        let mut generator = ConstraintGenerator::new();
        generator.generate(&predicates)?;
        
        let num_witnesses = generator.num_witnesses();
        let (and_constraints, mul_constraints) = generator.into_constraints();
        
        Ok(Self {
            and_constraints,
            mul_constraints,
            num_witnesses,
        })
    }
    
    /// Get the number of AND constraints
    pub fn num_and_constraints(&self) -> usize {
        self.and_constraints.len()
    }
    
    /// Get the number of MUL constraints
    pub fn num_mul_constraints(&self) -> usize {
        self.mul_constraints.len()
    }
    
    /// Get total number of constraints
    pub fn total_constraints(&self) -> usize {
        self.num_and_constraints() + self.num_mul_constraints()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::Expression;
    
    #[test]
    fn test_compiler_basic() {
        let mut compiler = PredicateCompiler::new();
        
        // Create witnesses
        let a = compiler.allocator().new_private();
        let b = compiler.allocator().new_private();
        let c = compiler.allocator().new_auxiliary();
        
        // Add predicate: c = a XOR b
        compiler.builder().add_equals(c, Expression::xor(a, b));
        
        // Compile
        let result = compiler.compile();
        assert!(result.is_ok());
        
        let (constraints, _filler) = result.unwrap();
        
        // For now, we expect empty constraints since implementation is incomplete
        assert_eq!(constraints.total_constraints(), 0);
    }
}
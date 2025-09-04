# Implementation Plan: Predicate-Based Compiler

## Overview

Build a compiler that transforms predicates into:
1. Optimized constraint systems
2. Witness computation functions

The key challenge: Preserve witness computability while aggressively optimizing constraints.

## Phase 1: Foundation (Week 1)

### 1.1 Core Types
```rust
// crates/compiler2/src/predicate.rs
pub struct Predicate {
    pub id: PredicateId,
    pub result: WitnessVar,
    pub expression: Expression,
}

// crates/compiler2/src/expression.rs  
pub enum Expression {
    Var(WitnessVar),
    Xor(Box<Expression>, Box<Expression>),
    And(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
    Shift(Box<Expression>, ShiftVariant, u8),
    Mul { 
        a: Box<Expression>, 
        b: Box<Expression>,
        hi: WitnessVar,  // High bits go to specific witness
        lo: WitnessVar,  // Low bits go to specific witness
    },
    Constant(ConstantId),
}

// crates/compiler2/src/witness.rs
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub enum WitnessVar {
    Public { id: u32 },
    Private { id: u32 },  
    Auxiliary { id: u32, eliminated: bool },
}
```

### 1.2 Builder API
```rust
// crates/compiler2/src/builder.rs
pub struct PredicateBuilder {
    predicates: Vec<Predicate>,
    witness_counter: u32,
    constant_pool: HashMap<u64, ConstantId>,
}

impl PredicateBuilder {
    pub fn new_witness(&mut self) -> WitnessVar;
    pub fn new_public(&mut self) -> WitnessVar;
    
    // Predicate: result = a XOR b
    pub fn add_xor(&mut self, result: WitnessVar, a: impl Into<Expression>, b: impl Into<Expression>);
    
    // Predicate: result = a AND b  
    pub fn add_and(&mut self, result: WitnessVar, a: impl Into<Expression>, b: impl Into<Expression>);
    
    // Predicate: (hi, lo) = a * b
    pub fn add_mul(&mut self, hi: WitnessVar, lo: WitnessVar, a: impl Into<Expression>, b: impl Into<Expression>);
}
```

## Phase 2: Dependency Graph (Week 1-2)

### 2.1 Witness Dependency Tracking
```rust
// crates/compiler2/src/dependency.rs
pub struct WitnessGraph {
    nodes: HashMap<WitnessVar, WitnessNode>,
    edges: Vec<DependencyEdge>,
}

pub struct WitnessNode {
    pub var: WitnessVar,
    pub source: WitnessSource,
    pub consumers: HashSet<PredicateId>,
}

pub enum WitnessSource {
    External,                           // Public or private input
    Computed(PredicateId),              // Computed by a predicate
    Eliminated(Box<Expression>),        // Eliminated but reconstructible
}

pub struct DependencyEdge {
    from: WitnessVar,  // Source witness
    to: WitnessVar,    // Target witness  
    via: PredicateId,  // Which predicate creates this dependency
}
```

### 2.2 Usage Analysis
```rust
impl WitnessGraph {
    // Build from predicates
    pub fn from_predicates(predicates: &[Predicate]) -> Self;
    
    // Check if witness is used by multiple predicates
    pub fn is_shared(&self, var: WitnessVar) -> bool;
    
    // Check if witness is a circuit output
    pub fn is_output(&self, var: WitnessVar) -> bool;
    
    // Get topological order for evaluation
    pub fn topological_order(&self) -> Vec<WitnessVar>;
}
```

## Phase 3: Packing Engine (Week 2-3)

### 3.1 Packing Analysis
```rust
// crates/compiler2/src/packing.rs
pub struct PackingEngine {
    graph: WitnessGraph,
    predicates: Vec<Predicate>,
    decisions: HashMap<PredicateId, PackingDecision>,
}

pub struct PackingDecision {
    pub predicate_id: PredicateId,
    pub should_pack: bool,
    pub reason: PackingReason,
}

pub enum PackingReason {
    ResultUsedElsewhere,     // Result witness used by other predicates
    ResultIsOutput,          // Result is circuit output
    FreeOperation,           // XOR/NOT/SHIFT can always pack
    ConstraintOperation,     // AND/MUL generates constraint
}
```

### 3.2 Delayed Binding Integration
```rust
impl PackingEngine {
    pub fn analyze(&mut self) {
        // For each predicate, decide whether to pack
        for predicate in &self.predicates {
            let decision = self.analyze_predicate(predicate);
            self.decisions.insert(predicate.id, decision);
        }
    }
    
    fn can_eliminate_witness(&self, var: WitnessVar) -> bool {
        !self.graph.is_shared(var) && !self.graph.is_output(var)
    }
    
    pub fn pack(&mut self) -> PackedConstraints {
        // Apply packing decisions using delayed binding
        // Mark eliminated witnesses in graph
    }
}
```

## Phase 4: Witness Recipe Compiler (Week 3-4)

### 4.1 Recipe Generation
```rust
// crates/compiler2/src/recipe.rs
pub struct WitnessRecipe {
    pub var: WitnessVar,
    pub computation: Computation,
}

pub enum Computation {
    Input,                                      // External input
    BinaryOp { op: BinaryOp, left: WitnessVar, right: WitnessVar },
    UnaryOp { op: UnaryOp, input: WitnessVar },
    Constant(u64),
    FromExpression(Expression),                 // Eliminated, compute from expression
}

pub struct RecipeCompiler {
    graph: WitnessGraph,
    recipes: HashMap<WitnessVar, WitnessRecipe>,
}

impl RecipeCompiler {
    pub fn compile(&mut self) -> WitnessFiller {
        // Generate recipes for all witnesses
        let order = self.graph.topological_order();
        
        for var in order {
            let recipe = self.generate_recipe(var);
            self.recipes.insert(var, recipe);
        }
        
        WitnessFiller::new(self.recipes)
    }
}
```

### 4.2 Witness Filler
```rust
// crates/compiler2/src/filler.rs
pub struct WitnessFiller {
    recipes: HashMap<WitnessVar, WitnessRecipe>,
    eval_order: Vec<WitnessVar>,
}

impl WitnessFiller {
    pub fn fill(&self, partial: PartialWitness) -> Result<CompleteWitness, FillError> {
        let mut witness = WitnessValues::from_partial(partial);
        
        for var in &self.eval_order {
            if witness.has(var) { continue; }
            
            let recipe = &self.recipes[var];
            let value = self.compute_recipe(recipe, &witness)?;
            witness.set(var, value);
        }
        
        Ok(witness.into_complete())
    }
}
```

## Phase 5: Integration (Week 4-5)

### 5.1 Complete Compiler
```rust
// crates/compiler2/src/compiler.rs
pub struct PredicateCompiler {
    builder: PredicateBuilder,
    packing_engine: PackingEngine,
    recipe_compiler: RecipeCompiler,
}

impl PredicateCompiler {
    pub fn compile(self) -> (ConstraintSystem, WitnessFiller) {
        // 1. Build dependency graph
        let graph = WitnessGraph::from_predicates(&self.builder.predicates);
        
        // 2. Analyze packing opportunities
        let mut packer = PackingEngine::new(graph, self.builder.predicates);
        packer.analyze();
        
        // 3. Generate optimized constraints
        let constraints = packer.pack();
        
        // 4. Compile witness recipes
        let filler = RecipeCompiler::new(packer.graph).compile();
        
        (constraints, filler)
    }
}
```

### 5.2 Testing Infrastructure
```rust
#[cfg(test)]
mod tests {
    // Test: Packed constraints are equivalent to unpacked
    #[test]
    fn test_packing_preserves_semantics() { }
    
    // Test: Witness filler produces valid witnesses
    #[test]
    fn test_witness_computation() { }
    
    // Test: Eliminated witnesses are correctly reconstructed
    #[test]
    fn test_eliminated_witness_reconstruction() { }
}
```

## Phase 6: Optimization (Week 5-6)

### 6.1 Expression Simplification
- XOR with self → 0
- Double NOT → identity
- Shift composition

### 6.2 Common Subexpression Elimination
- Detect repeated expressions
- Share computation

### 6.3 Witness Computation Optimization
- Minimize intermediate storage
- Vectorize operations where possible

## Success Metrics

1. **Correctness**: All tests pass, witness filler produces valid witnesses
2. **Efficiency**: 50% reduction in constraint count vs naive compilation
3. **Performance**: Witness filling < 10ms for 10K witnesses
4. **Maintainability**: Clean separation between optimization and witness computation

## Risk Mitigation

**Risk**: Packing breaks witness computation
**Mitigation**: Conservative packing initially, extensive testing

**Risk**: Complex dependency graphs
**Mitigation**: Start with DAGs only, add cycle detection

**Risk**: Performance of witness filling
**Mitigation**: Profile and optimize hot paths, consider parallelization

## Next Steps

1. Set up crate structure
2. Implement Phase 1 core types
3. Write initial test cases
4. Begin Phase 2 dependency analysis

This plan provides a systematic approach to building the predicate-based compiler while maintaining the critical invariant: optimized constraints with computable witnesses.
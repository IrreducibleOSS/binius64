# DESIGN2: Predicate-Based Compiler with Witness Recipes

## Core Philosophy

ZK circuits compute verification predicates of the form:
```
∃ witnesses : Predicate(public_inputs, witnesses) = TRUE
```

The compiler must produce:
1. **Constraint system**: Efficient encoding of the predicate
2. **Witness filler**: Function that computes witness values given partial inputs

## The Fundamental Problem

When we optimize constraints through delayed binding and packing, we eliminate intermediate witnesses. But witness computation still needs those intermediates! 

Example:
```rust
// User writes:
predicate: t = a XOR b
predicate: u = t XOR c  
predicate: v = u AND d

// After packing:
constraint: v = (a XOR b XOR c) AND d
// Variable 't' and 'u' eliminated!

// But witness computation needs:
t := compute_xor(a, b)    // Eliminated but needed!
u := compute_xor(t, c)    // Eliminated but needed!
v := compute_and(u, d)
```

## Key Concepts

### 1. Predicates (First-Class Citizens)

Predicates are equality assertions over witness variables:
```rust
enum Predicate {
    // Basic equality: a = b OP c
    Equals { 
        result: WitnessVar,
        expr: Expression 
    },
}

enum Expression {
    Var(WitnessVar),
    Xor(Box<Expression>, Box<Expression>),
    And(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
    Shift(Box<Expression>, ShiftOp, u8),
    Mul(Box<Expression>, Box<Expression>),
}
```

**Key insight**: Standalone expressions like `a XOR b` are meaningless - only predicates like `c = a XOR b` have meaning in verification.

### 2. Witness Variables

Three types of witness variables:
```rust
enum WitnessVar {
    Public(PublicId),      // Public inputs (deterministic)
    Private(WitnessId),    // Private inputs (prover-supplied)
    Auxiliary(AuxId),      // Computed intermediates
}
```

### 3. Witness Dependency Graph

Tracks how to compute each witness:
```rust
struct WitnessGraph {
    nodes: HashMap<WitnessVar, WitnessNode>,
    edges: Vec<(WitnessVar, WitnessVar)>, // source → target dependencies
}

struct WitnessNode {
    var: WitnessVar,
    recipe: WitnessRecipe,
    consumed_by: Vec<PredicateId>,
    required_for_output: bool,
}

enum WitnessRecipe {
    Input,                                    // Provided externally
    Compute { op: Operation, inputs: Vec<WitnessVar> }, // Computed
    Eliminated { expanded: Expression },      // Eliminated by packing
}
```

### 4. Compilation Phases

#### Phase 1: Predicate Registration
```rust
// User writes predicates
compiler.add_predicate(t, xor(a, b));
compiler.add_predicate(u, xor(t, c));
compiler.add_predicate(v, and(u, d));
```

#### Phase 2: Dependency Analysis
Build witness dependency graph:
- `t` depends on `a`, `b`
- `u` depends on `t`, `c`  
- `v` depends on `u`, `d`

#### Phase 3: Delayed Binding with Witness Preservation
```rust
fn optimize_with_preservation(&mut self) {
    for predicate in self.predicates {
        if can_pack(predicate) && !witness_needed_elsewhere(predicate.result) {
            // Pack the predicate
            let packed = pack_expression(predicate);
            
            // Mark witness as eliminated but keep recipe
            self.witness_graph.mark_eliminated(
                predicate.result,
                predicate.expr
            );
        }
    }
}
```

#### Phase 4: Generate Constraint System
Convert optimized predicates to constraints, using packed expressions where possible.

#### Phase 5: Generate Witness Filler
```rust
fn generate_witness_filler(&self) -> impl Fn(PartialWitness) -> FullWitness {
    let graph = self.witness_graph.clone();
    
    move |partial: PartialWitness| {
        let mut witness = partial;
        
        // Topological traversal of dependency graph
        for node in graph.topological_order() {
            match node.recipe {
                WitnessRecipe::Input => {
                    // Already in partial witness
                },
                WitnessRecipe::Compute { op, inputs } => {
                    let values = inputs.iter().map(|i| witness[i]);
                    witness[node.var] = compute_op(op, values);
                },
                WitnessRecipe::Eliminated { expanded } => {
                    // Compute from expanded expression
                    witness[node.var] = evaluate_expression(expanded, &witness);
                }
            }
        }
        
        witness
    }
}
```

## Terminology

- **Witness Variable**: A slot in the witness vector (corresponds to a wire in the circuit)
- **Expression**: A computational tree (e.g., `a XOR b XOR c`)
- **Predicate**: An equality assertion (e.g., `d = a XOR b XOR c`)
- **Term**: An atomic operation in an expression (XOR, AND, etc.)
- **Recipe**: Instructions for computing a witness value

## The Packing Problem

When we pack predicates, we face a choice:

1. **Pack aggressively**: Minimize constraints but complicate witness computation
2. **Pack conservatively**: Keep witness computation simple but have more constraints

Solution: Track witness usage across predicates:
```rust
struct PackingDecision {
    predicate: PredicateId,
    pack: bool,
    reason: PackingReason,
}

enum PackingReason {
    WitnessUsedElsewhere,    // Can't pack - witness needed by other predicates
    OutputWitness,           // Can't pack - witness is a circuit output
    Packable,                // Can pack - witness is purely internal
}
```

## Example: Complete Flow

Input predicates:
```rust
// User defines predicates
p1: h1 = sha_intermediate_1(input)
p2: h2 = sha_intermediate_2(h1)
p3: digest = sha_finalize(h2)
```

After compilation:
```rust
// Constraint system (optimized)
constraints: [
    digest = sha_complete(input)  // Fully packed
]

// Witness filler (preserves computation)
witness_filler: |input| {
    h1 = compute_sha_intermediate_1(input);  // Eliminated but computed
    h2 = compute_sha_intermediate_2(h1);     // Eliminated but computed
    digest = compute_sha_finalize(h2);
    
    return WitnessVec { input, digest }; // Only non-eliminated in final witness
}
```

## Benefits

1. **Verification/Computation Separation**: Clearly separates the predicate (what to verify) from the computation (how to compute witnesses)

2. **Optimization Transparency**: Can pack constraints aggressively while preserving witness computability

3. **Composability**: Predicates compose naturally, and witness recipes compose too

4. **Debugging**: Can trace how each witness value was computed, even if eliminated from constraints

## Implementation Plan

### Step 1: Core Predicate System
- [ ] Define `Predicate`, `Expression`, `WitnessVar` types
- [ ] Implement predicate builder API

### Step 2: Witness Graph  
- [ ] Build dependency graph from predicates
- [ ] Implement topological sorting
- [ ] Track witness usage across predicates

### Step 3: Packing with Preservation
- [ ] Implement packing decision logic
- [ ] Mark eliminated witnesses with recipes
- [ ] Generate packed constraints

### Step 4: Witness Filler Generation
- [ ] Generate computation function from graph
- [ ] Handle eliminated witness reconstruction
- [ ] Optimize witness computation order

### Step 5: Integration
- [ ] Connect to existing constraint system types
- [ ] Add tests for witness computation correctness
- [ ] Benchmark constraint count vs witness computation cost

## Key Invariant

**The Witness Completeness Invariant**: 
For any valid partial witness input, the generated witness filler MUST be able to compute ALL witness values (including eliminated ones) needed to satisfy the constraint system.

This ensures that constraint optimization never breaks the ability to generate valid proofs.
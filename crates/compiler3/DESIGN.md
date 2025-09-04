# Beamish: A Predicate-Based Compiler for Zero-Knowledge Constraint Systems

## Executive Summary

Beamish is a compiler framework that transforms high-level predicate specifications into optimized constraint systems for zero-knowledge proofs. The core innovation is recognizing that aggressive constraint optimization through operand packing creates a fundamental tension: it reduces constraint count but eliminates auxiliary witnesses needed for proof generation. Our solution preserves auxiliary witness computation throughout the compilation pipeline while achieving significant constraint reduction.

## Part I: Theoretical Foundations

### 1.1 The Fundamental Duality

In zero-knowledge proof systems, every user statement exhibits dual interpretation:

**Verification Intent**: A predicate that must hold over the witness vector
**Computational Intent**: A method to compute witness values during proving

When a user writes `r = a mod n`, they simultaneously express:
- A verification predicate: `∃q : a = n × q + r ∧ r < n`
- A computation recipe: `r := a - n × ⌊a/n⌋`

This duality becomes problematic in constraint systems where the available constraint operations (our "instruction set") don't match computational operations. The user writes `=` but means two different things:
- As predicate: "r must equal a mod n" (verified through multiplication)
- As computation: "compute r using division" (executed during proving)

### 1.2 The Predicate-Computation Duality of Equality

The equality operator `=` in user predicates has profound dual meaning:

```rust
// When user writes:
t = a ⊕ b

// This simultaneously means:
// 1. PREDICATE: "t must equal a ⊕ b" (constraint)
// 2. COMPUTATION: "compute t as a ⊕ b" (witness filling)
```

But these two meanings can diverge dramatically:
- **Simple case**: `t = a ⊕ b` → Both predicate and computation use XOR
- **Complex case**: `r = a mod n` → Predicate uses multiplication, computation uses division

This duality is the source of both the system's power and its complexity. The same `=` operator bridges two different algebras: the constraint algebra (AND/MUL over GF(2^64)) and the computation algebra (arbitrary operations).

### 1.3 The Constraint System as Algebraic Varieties

Each constraint in our system defines an algebraic variety over GF(2^64). The AND constraint `(A) & (B) ⊕ (C) = 0` defines a variety in the space of all witness assignments. The compilation problem is fundamentally about decomposing complex varieties (user predicates) into intersections of simpler varieties (AND/MUL constraints).

**Key Insight**: What we call "operands" are linear forms over GF(2^64):
- `A = Σ(aᵢ·xᵢ·2^(shiftᵢ)) ⊕ constant`

The "free" operations within operands correspond to linear transformations that preserve the variety structure. This explains why XOR chains consolidate - they define affine subspaces that can be represented by single linear equations.

### 1.4 The Constraint System Model

Our target is the Binius64 constraint system with exactly two constraint types:

```
AND-constraint: (A) & (B) ⊕ (C) = 0
MUL-constraint: (A) × (B) = (HI << 64) | LO
```

Where A, B, C are "operands" - each operand can contain unlimited XOR combinations of shifted witness values and constants at zero marginal cost:

```
Operand := Σ(wᵢ ≪ sᵢ) ⊕ constant
```

This creates an unusual "instruction set" where each constraint can encode many operations, fundamentally changing the compilation problem from minimizing instruction count to maximizing operations per constraint.

### 1.5 The Operand Packing Problem: The Central Challenge

**Definition**: Operand packing is the process of combining multiple simple constraints into fewer complex constraints by exploiting the free operations within operands.

#### The Fundamental Tension

Consider a concrete example that illustrates the central challenge:

```rust
// User writes this simple predicate:
predicate example {
    let t = a ⊕ b;
    let u = t ⊕ c;
    let v = u ∧ d;
    return v;
}

// Naive compilation produces these constraints:
C₁: (a) & (0xFF..FF) ⊕ (b ⊕ t) = 0    // Defines: t = a ⊕ b
C₂: (t) & (0xFF..FF) ⊕ (c ⊕ u) = 0    // Defines: u = t ⊕ c
C₃: (u) & (d) ⊕ (v) = 0               // Defines: v = u ∧ d

// After packing optimization:
C₁': ((a ⊕ b ⊕ c)) & (d) ⊕ (v) = 0   // Single constraint!
```

#### The Critical Problem Explained

**Before packing**, the constraint system explicitly defines every intermediate witness:
- Witness `t` appears in constraints C₁ (as output) and C₂ (as input)
- Witness `u` appears in constraints C₂ (as output) and C₃ (as input)
- The witness computer can simply read the constraints to know: `t = a ⊕ b`, `u = t ⊕ c`

**After packing**, witnesses `t` and `u` have completely vanished:
- They appear in NO constraints
- The single packed constraint only relates `a, b, c, d, v`
- **The computation recipe for t and u is irretrievably lost**

#### Why Recovery is Impossible

Once packed, you cannot deduce the original computation from the constraint alone. Consider the packed constraint:

```
((a ⊕ b ⊕ c)) & (d) ⊕ (v) = 0
```

This constraint tells us that `v = (a ⊕ b ⊕ c) & d`, but it doesn't tell us:
1. That there was ever an intermediate value `t = a ⊕ b`
2. That there was ever an intermediate value `u = t ⊕ c`
3. The order of operations (was it `(a ⊕ b) ⊕ c` or `a ⊕ (b ⊕ c)`?)

In fact, there are multiple computation paths that lead to the same packed constraint:
- Path 1: `t = a ⊕ b; u = t ⊕ c; v = u & d`
- Path 2: `s = b ⊕ c; r = a ⊕ s; v = r & d`
- Path 3: `v = (a ⊕ b ⊕ c) & d` (direct computation)

The packed constraint is satisfied by all these paths, but the original witnesses `t` and `u` only exist in Path 1.

#### Why This Matters for Zero-Knowledge Proofs

The real problem isn't that auxiliary witnesses are eliminated - that's the goal of optimization. The problem is that once packed, **the computation recipe for these auxiliaries becomes unrecoverable from the constraints alone**.

Consider a real example from SHA-256:

```
// Original computation with auxiliary witnesses:
let w0 = message[0];
let w1 = message[1];
let s0 = σ₀(w1);
let t = w0 + s0;        // Auxiliary witness
let w16 = t + w9 + s1;  // Uses t

// After packing:
w16 = w0 + σ₀(w1) + w9 + σ₁(w14)  // Constraint form
```

Looking at the packed constraint `w16 = w0 + σ₀(w1) + w9 + σ₁(w14)`, you cannot determine:
1. That there was an intermediate value `t`
2. That `t = w0 + s0` specifically
3. Whether the computation was `((w0 + σ₀(w1)) + w9) + σ₁(w14)` or `w0 + ((σ₀(w1) + w9) + σ₁(w14))`

This matters because:

**Witness generation requires knowing HOW to compute values, not just WHAT constraints they satisfy**. The prover needs to compute `t` to eventually compute `w16`, but the packed constraint doesn't reveal the computation path. Without preserving the original computation recipe `t = w0 + s0`, the prover cannot generate the witness.

**Different computation orders may have different numerical properties**. In finite field arithmetic, while addition is associative algebraically, the actual computation path matters for:
- Overflow behavior in intermediate steps
- Numerical stability
- Consistency with other parts of the proof system

**The constraint verifies correctness but doesn't specify computation**. The packed constraint `w16 = w0 + σ₀(w1) + w9 + σ₁(w14)` tells the verifier what to check, but doesn't tell the prover how to compute the witnesses that satisfy it.

#### The Deceptive Nature of the Problem

The problem is particularly insidious because:

1. **Local optimization looks correct**: Each packing step preserves semantic equivalence locally
2. **Constraint verification still works**: The packed constraints are mathematically equivalent
3. **The issue only appears at witness generation time**: When you try to compute witnesses, you realize you don't know how to compute the eliminated auxiliary values

This is analogous to a compiler that optimizes away all debugging information - the program still runs correctly, but you can no longer inspect or compute intermediate states.

#### Traditional Solutions and Why They Fail

**Approach 1: Don't Pack**
- Keep all intermediate constraints
- Result: Many more constraints, making proofs expensive

**Approach 2: Reverse-Engineer from Packed Constraints**
- Try to deduce computation from final constraints
- Fails because multiple computation paths lead to same constraint

**Approach 3: Re-compute When Needed**
- Detect when eliminated witnesses are needed and recompute
- Problem: How do you know HOW to compute them if the recipe is lost?

#### The Beamish Solution: Preserve Computation Semantics

Our key insight is that witness computation must be captured **before packing**, when the computation recipe is still explicit:

```rust
struct CompilationState {
    // Capture computation BEFORE packing
    auxiliary_computation: {
        t: AuxiliaryRecipe::Compute(a ⊕ b),
        u: AuxiliaryRecipe::Compute(t ⊕ c),
        v: AuxiliaryRecipe::Compute(u & d)
    },

    // After packing, constraints are optimized
    constraints: [
        ((a ⊕ b ⊕ c)) & (d) ⊕ (v) = 0
    ],

    // Mark which auxiliaries were eliminated
    eliminated: {t, u}
}
```

During witness generation:
1. We compute ALL auxiliary witnesses using the preserved recipes (including eliminated ones)
2. Only non-eliminated witnesses are included in the final witness vector
3. Eliminated witnesses exist temporarily during computation but not in constraints

This approach maintains the best of both worlds:
- Minimal constraints through aggressive packing (verification efficiency)
- Complete witness computability through preserved recipes (proving capability)

### 1.6 Auxiliary Witnesses as Existential Variables

From the user's perspective, all non-public witnesses are auxiliary - implementation details they never see or care about. The user writes:

```rust
predicate modulo(a: u64, n: u64) -> u64 {
    a % n
}
```

The compiler introduces auxiliary witnesses:
- Quotient `q` (existentially quantified: ∃q)
- Any intermediate computations

These auxiliary witnesses are existential variables in the formal sense - the predicate states they exist, but doesn't specify their value. The prover must find values that satisfy the constraints.

### 1.7 Non-Determinism as Computational Bridges

Non-deterministic auxiliary witnesses serve as bridges between the computational model and the constraint model:

```
Computation knows: q = ⌊a/n⌋
Constraint verifies: ∃q : a = n × q + r
```

The existential quantification in constraints allows us to use different operations for computation (division) and verification (multiplication). This is the essence of zero-knowledge: proving knowledge of a witness without revealing it.

### 1.8 Formal Framework

Let:
- **P** be the set of all predicates
- **C** be the set of all constraints
- **W** be the set of all possible witness vectors
- **V** ⊆ W be the set of valid witness vectors (satisfying all constraints)

A predicate compilation is a function: `compile: P → (C, W → W)`

That produces:
1. A constraint set C for verification
2. A witness synthesis function for proving

**Correctness Condition**: For any partial witness w_partial containing public inputs:
```
synthesize(w_partial) ∈ V
```

**Optimality Goal**: Minimize |C| while maintaining efficient synthesis.

**The Witness Completeness Invariant**: For any valid partial witness input, the generated witness filler MUST be able to compute ALL witness values (including eliminated auxiliaries) needed to satisfy the constraint system.

### 1.9 Mathematical Foundations of Rewriting Rules

#### XOR Chain Consolidation

**Pattern**: Sequential XOR constraints
```
C₁: a & 0xFF..FF ⊕ (b ⊕ t₁) = 0
C₂: t₁ & 0xFF..FF ⊕ (c ⊕ result) = 0
```

**Optimization**: Single operand `a ⊕ b ⊕ c` in consuming constraint

**Proof**: From C₁: `a = b ⊕ t₁`, so `t₁ = a ⊕ b`. From C₂: `t₁ = c ⊕ result`, so `result = t₁ ⊕ c = (a ⊕ b) ⊕ c = a ⊕ b ⊕ c`.

**Key insight**: In GF(2^64), XOR is associative and commutative, so the computation order doesn't matter for the final result, but it DOES matter for intermediate auxiliary witnesses.

#### Masked AND-XOR Pattern (Keccak Chi)

**Pattern**: `a ⊕ ((~b) & c)`

**Mathematical Identity**: In GF(2^64), this equals single constraint `(b ⊕ 0xFF..FF) & c ⊕ (a ⊕ result) = 0`

**Proof**: `~b = b ⊕ 0xFF..FF` in GF(2). Substituting: `((b ⊕ 0xFF..FF) & c) ⊕ a = result`.

#### Binary Choice Pattern (SHA256 Ch)

**Pattern**: `(a & b) ⊕ ((~a) & c)`

**Mathematical identity**: `a & (b ⊕ c) ⊕ c`

**Proof**: When `a = 1`: `(1 & b) ⊕ (0 & c) = b`. When `a = 0`: `(0 & b) ⊕ (1 & c) = c`. The identity `a & (b ⊕ c) ⊕ c` gives the same results.

#### XOR of ANDs Pattern (Majority)

**Pattern**: `(a & b) ⊕ (a & c) ⊕ (b & c)`

**Mathematical identity**: `(a ⊕ c) & (b ⊕ c) ⊕ c`

**Proof**: Expanding `(a ⊕ c) & (b ⊕ c)` using distributivity over GF(2): equals `(a & b) ⊕ (a & c) ⊕ (c & b) ⊕ (c & c)`. Since `c & c = c` in GF(2), this becomes `(a & b) ⊕ (a & c) ⊕ (b & c) ⊕ c`. XORing with `c` gives the original majority expression.

## Part II: Compiler Architecture

### 2.1 Three-Level Intermediate Representation

The compiler uses three distinct IR levels, each preserving different information:

#### Level 1: Semantic IR (SIR)
Captures user intent before decomposition into constraints.

```rust
enum SemExpr {
    Var(VarId),
    Const(u64),

    // Arithmetic semantics
    Add(Box<SemExpr>, Box<SemExpr>),
    Mul(Box<SemExpr>, Box<SemExpr>),
    Div(Box<SemExpr>, Box<SemExpr>),  // Creates auxiliary quotient
    Mod(Box<SemExpr>, Box<SemExpr>),  // Creates auxiliary quotient

    // Bitwise semantics
    Xor(Box<SemExpr>, Box<SemExpr>),
    And(Box<SemExpr>, Box<SemExpr>),

    // Existential auxiliary witness
    Auxiliary { id: AuxiliaryId, verifier: Box<SemExpr> }
}
```

#### Level 2: Constraint IR (CIR)
Post-decomposition, pre-optimization representation. This is the critical stage where auxiliary witness computation is still explicit.

```rust
struct ConstraintIR {
    constraints: Vec<BasicConstraint>,
    auxiliary_deps: DependencyGraph,      // Captures ALL auxiliary computation
    existential_points: HashMap<AuxiliaryId, AuxiliaryComputation>,
}
```

#### Level 3: Packed IR (PIR)
Post-optimization with preserved auxiliary computation.

```rust
struct PackedIR {
    constraints: Vec<BiniusConstraint>, // Optimized, auxiliaries eliminated
    eliminated: HashSet<AuxiliaryId>,   // Which auxiliaries got packed away
    auxiliary_computer: AuxiliaryComputer,  // Preserved from CIR - critical!
}
```

### 2.2 Compilation Pipeline

```
User Predicate → Semantic Analysis → Decomposition → Packing → Code Generation
                        ↓                ↓              ↓            ↓
                       SIR              CIR           PIR     (Constraints, Synthesizer)
                                         ↑
                              Critical point: Auxiliary
                              computation captured HERE
                              before packing destroys it
```

Each phase preserves auxiliary witness computation information while progressively optimizing constraints.

### 2.3 The Predicate-First Philosophy

Users express predicates for verification, not computations. Every expression is fundamentally about defining what must be true, not how to compute it. The computation is merely a side effect needed for proving.

Key observation: In a normal constraint system, you could deduce witness computation from the constraints themselves. But operand packing destroys this deducibility, necessitating preservation of computation semantics through compilation.

## Part III: Core Algorithms

### 3.1 Decomposition Algorithm

Decomposition transforms semantic operations into constraint-compatible operations:

```
decompose: SemExpr → (Constraints, AuxiliaryComputation)
```

**Algorithm**: Pattern-based recursive decomposition

```python
function decompose(expr):
    match expr:
        case Div(a, n):
            q = fresh_auxiliary()  # Existential auxiliary
            r = fresh_auxiliary()  # Result (may be public or auxiliary)

            constraints = [
                a = n × q + r,
                r < n  # Range constraint
            ]

            # Critical: Capture auxiliary computation NOW
            auxiliary_computation = {
                q: AuxiliarySource.Existential(⌊a/n⌋),
                r: AuxiliarySource.Computed(a - n×q)
            }

            return (constraints, auxiliary_computation)

        case Xor(a, b):
            result = fresh_auxiliary()
            # Direct mapping
            return (
                [result = a ⊕ b],
                {result: AuxiliarySource.Computed(a ⊕ b)}
            )
```

### 3.2 Operand Packing Algorithm (With Auxiliary Preservation)

**Input**: List of basic constraints + auxiliary computation graph
**Output**: Packed constraints with minimal count + preserved computation

**Algorithm**: Sliding window with cost-based greedy selection AND computation preservation

```python
function pack_constraints_preserving_auxiliaries(constraints, auxiliary_graph):
    packed = []
    eliminated = set()
    preserved_auxiliaries = auxiliary_graph.clone()  # Critical!

    while constraints not empty:
        best_package = find_best_package(constraints)

        if best_package:
            # Pack the constraints
            packed_constraint = merge(best_package)
            packed.append(packed_constraint)

            # Mark eliminated auxiliaries but KEEP their computation recipes
            for auxiliary in best_package.eliminated_auxiliaries():
                eliminated.add(auxiliary)
                # Computation for auxiliary is still in preserved_auxiliaries

            constraints.remove(best_package.constraints)
        else:
            packed.append(constraints.pop(0))

    return PackedIR {
        constraints: packed,
        eliminated: eliminated,
        auxiliary_computer: preserved_auxiliaries  # Never lost!
    }
```

### 3.3 Witness Synthesis Algorithm (Using Preserved Auxiliaries)

**Input**: Public inputs, preserved auxiliary computation graph
**Output**: Complete witness vector

**Algorithm**: Topological evaluation including eliminated auxiliaries

```python
function synthesize_witness(public_inputs, preserved_auxiliary_graph):
    witness = new WitnessVector()

    # Initialize with public inputs
    for (id, value) in public_inputs:
        witness[id] = value

    # Compute ALL auxiliaries, even eliminated ones
    for node in topological_sort(preserved_auxiliary_graph):
        match node.source:
            case Computed(expr):
                witness[node.id] = evaluate(expr, witness)

            case Existential(computation):
                # Compute the existential auxiliary
                witness[node.id] = computation.compute(witness)

            case Eliminated(original_expr):
                # Critical: Still compute even though not in constraints!
                witness[node.id] = evaluate(original_expr, witness)

    # Only return non-eliminated witnesses for constraint checking
    return filter_non_eliminated(witness)
```

### 3.4 Pattern Recognition for Crypto Primitives

Special patterns for common cryptographic operations:

**Keccak Chi Step**:
```
Pattern: a ⊕ ((¬b) & c)
Packed: (b ⊕ 0xFF..FF) & c ⊕ (a ⊕ result) = 0
Benefit: 3 constraints → 1 constraint
Eliminated auxiliaries: temp1 = ¬b, temp2 = temp1 & c
Preserved computation: temp1 := b ⊕ 0xFF..FF, temp2 := temp1 & c
```

**SHA256 Sigma Function**:
```
Pattern: (x >>> r₁) ⊕ (x >>> r₂) ⊕ (x >>> r₃)
Packed: Single operand with three rotated terms
Benefit: 2 constraints → 0 constraints (absorbed)
Eliminated auxiliaries: rot1, rot2
Preserved computation: rot1 := x >>> r₁, rot2 := x >>> r₂
```

## Part IV: Implementation Design

### 4.1 Module Structure

```
beamish/
├── frontend/
│   ├── parser.rs       // Predicate language parser
│   ├── semantic.rs     // Semantic analysis
│   └── types.rs        // Type system (Field64, U32, etc.)
├── middleend/
│   ├── decompose.rs    // Semantic → Constraint decomposition
│   ├── pack.rs         // Constraint packing optimization
│   ├── preserve.rs     // Auxiliary computation preservation
│   └── patterns.rs     // Crypto-specific patterns
├── backend/
│   ├── constraints.rs  // Binius constraint generation
│   └── synthesis.rs    // Witness synthesizer generation
└── runtime/
    ├── auxiliary.rs    // Auxiliary witness computation
    └── compute.rs      // Witness computation runtime
```

### 4.2 User API

```rust
use beamish::prelude::*;

#[predicate]
fn sha256_valid(message: &[u8; 64]) -> [u8; 32] {
    // Declarative predicate - looks imperative but isn't
    let padded = sha_pad(message);
    let scheduled = message_schedule(padded);
    let compressed = compress_rounds(scheduled);
    finalize(compressed)
}

// Compilation (at build time)
let compiled = compile_predicate!(sha256_valid);

// Proving (at runtime)
fn prove(message: &[u8; 64]) -> Proof {
    let public_inputs = PublicInputs::from(message);

    // Synthesizer knows how to compute ALL auxiliaries,
    // even those eliminated by packing
    let witness = compiled.synthesize(public_inputs)?;

    create_proof(&compiled.constraints, &witness)
}

// Verification (independently)
fn verify(message: &[u8; 64], proof: Proof) -> bool {
    verify_proof(&compiled.constraints, &PublicInputs::from(message), &proof)
}
```

### 4.3 Data Structure Specifications

```rust
// Core witness types
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum WitnessId {
    Public(PublicId),
    Auxiliary(AuxiliaryId),
}

// Auxiliary witness tracking
struct AuxiliaryGraph {
    nodes: HashMap<AuxiliaryId, AuxiliaryNode>,
    edges: Vec<(AuxiliaryId, AuxiliaryId)>,  // src → dst
}

struct AuxiliaryNode {
    id: AuxiliaryId,
    source: AuxiliarySource,
    dependents: Vec<AuxiliaryId>,
    elimination_status: EliminationStatus,
}

enum AuxiliarySource {
    Computed(Expression),        // Deterministically computed
    Existential(Computation),    // Non-deterministically chosen
}

enum EliminationStatus {
    Required,      // Appears in final constraints
    Eliminated,    // Packed away but computation preserved
    Intermediate,  // Needed for computing other auxiliaries
}

// Binius constraint representation
enum BiniusConstraint {
    And {
        a: Operand,
        b: Operand,
        c: Operand
    },
    Mul {
        a: Operand,
        b: Operand,
        hi: WitnessId,
        lo: WitnessId
    },
}

struct Operand {
    terms: Vec<Term>,
    constant: Option<u64>,
}

struct Term {
    witness: WitnessId,
    shift: Option<(ShiftOp, u8)>,
}
```

### 4.4 Cost Model

The cost model drives packing decisions:

```rust
struct CostModel {
    and_cost: f64,      // 1.0 (baseline)
    mul_cost: f64,      // 200.0 (expensive)
    operand_term_cost: f64,  // 0.0 (free within operand)
}

impl CostModel {
    fn evaluate_packing(&self, before: &[Constraint], after: &Constraint) -> f64 {
        let before_cost = before.iter().map(|c| self.constraint_cost(c)).sum();
        let after_cost = self.constraint_cost(after);
        before_cost - after_cost  // Positive means beneficial
    }
}
```

## Part V: Correctness and Performance

### 5.1 Correctness Properties

**Property 1 (Soundness)**: Any witness produced by the synthesizer satisfies all constraints.

**Property 2 (Completeness)**: For any satisfiable predicate, the synthesizer produces a valid witness.

**Property 3 (Preservation)**: Packing preserves predicate semantics:
```
∀p ∈ Predicates: eval(p, w) = eval(pack(p), w)
```

**Property 4 (Auxiliary Completeness)**: The witness synthesis function can compute all necessary auxiliaries, including those eliminated by packing.

**Property 5 (Computation Preservation)**: For every auxiliary witness w:
```
computation_recipe(w) is preserved from CIR to PIR
```

### 5.2 Performance Metrics

Target constraint reductions observed in testing:

| Primitive | Naive Constraints | Optimized Constraints | Reduction |
|-----------|------------------|----------------------|-----------|
| Keccak-f  | 3000            | 1000                 | 67%       |
| SHA-256   | 2800            | 1200                 | 57%       |
| Add128    | 4               | 1                    | 75%       |
| Modulo    | 5               | 1                    | 80%       |

### 5.3 Complexity Analysis

- **Decomposition**: O(n) where n is expression tree size
- **Packing**: O(n² × w) where w is window size (typically ≤5)
- **Synthesis**: O(n) with topological sort
- **Space**: O(n) for auxiliary dependency graph storage

### 5.4 Theoretical Limits

**Theorem**: For any constraint system with k types of constraints, the minimal constraint count for a predicate P is bounded by:
```
min_constraints(P) ≥ information_content(P) / max_information_per_constraint
```

For Binius64, max_information_per_constraint is high due to unlimited XOR terms in operands, enabling aggressive packing.

## Part VI: Extensions and Future Work

### 6.1 Dynamic Control Flow

Support for bounded loops and conditionals through predicated execution:

```rust
#[predicate]
fn variable_length_hash(data: &[u8], len: u32) -> [u8; 32] {
    let mut state = INIT;
    for i in 0..MAX_LEN {
        if i < len {
            state = update(state, data[i]);
        }
    }
    finalize(state)
}
```

Implementation uses multiplexer trees and conditional state updates, unrolling all iterations but masking inactive ones.

### 6.2 Automatic Auxiliary Generation

Derive auxiliary computation from semantic analysis:

```rust
// Automatically generate division auxiliary
impl AuxiliaryProvider for DivisionAuxiliary {
    fn compute(&self, witness: &WitnessVector) -> u64 {
        let dividend = witness[self.dividend_id];
        let divisor = witness[self.divisor_id];
        dividend / divisor  // Computed outside constraint system
    }
}
```

### 6.3 Cross-Predicate Optimization

Share computation across multiple predicates:

```rust
#[predicate_set]
mod crypto {
    // Share message scheduling across variants
    fn sha256_hmac(key: &[u8], msg: &[u8]) -> [u8; 32];
    fn sha256_pbkdf2(password: &[u8], salt: &[u8]) -> [u8; 32];
}
```

### 6.4 Constraint Scheduling

Future work: optimal scheduling of constraints considering:
- Register pressure (witness vector size)
- Cache locality (witness access patterns)
- Parallelization opportunities

## Part VII: Related Work

### 7.1 Comparison with Existing Systems

| System | Approach | Constraint Types | Optimization Focus | Auxiliary Handling |
|--------|----------|-----------------|-------------------|-------------------|
| Circom | Template-based | R1CS | Manual optimization | Explicit |
| Leo | Functional | R1CS | Type-driven | Automatic |
| Noir | Imperative | PLONK | ACIR intermediate | Implicit |
| **Beamish** | Predicate-based | Binius AND/MUL | Operand packing | Preserved |

### 7.2 Theoretical Contributions

1. **Predicate-computation duality**: Formal framework for the dual nature of ZK specifications
2. **Operand packing**: Novel optimization exploiting constraint structure
3. **Auxiliary preservation**: Maintaining computability through aggressive optimization
4. **The packing-computability tension**: First formal treatment of this fundamental problem

## Conclusion

Beamish represents a fundamental rethinking of ZK compilation. By recognizing that users write verification predicates rather than computations, and that aggressive constraint optimization creates tension with witness generation, we've designed a compiler that:

1. Preserves auxiliary witness computability through all optimization phases
2. Achieves significant constraint reduction for common operations
3. Provides clean separation between verification and computation
4. Supports both deterministic and existential auxiliary witnesses naturally

The key innovation is the three-level IR design that captures semantic intent, preserves auxiliary computation requirements, and enables aggressive packing without losing essential information. The critical insight is that auxiliary witness computation must be captured at the CIR level, before packing optimization destroys the ability to recover computation recipes from constraints.

The system recognizes that constraint optimization and witness computation are parallel concerns that must be carefully coordinated, not conflated. This insight, combined with the unique properties of the Binius64 constraint system, enables significant optimization opportunities while maintaining the mathematical rigor required for zero-knowledge proofs.

The packing-witness tension we've identified and solved is fundamental to any constraint system that allows complex operations within primitive constraints. Our solution - preserving computation semantics through all optimization phases - provides a blueprint for future ZK compilers facing similar challenges.

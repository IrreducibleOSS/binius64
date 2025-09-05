# Beamish: Expression-Based Constraint Generation

## Overview

Beamish is a functional expression-based framework for generating Binius64 constraints. Users build expression trees using typed operations, and the system compiles these to optimized constraints through pattern recognition and delayed binding.

## Binius64 Constraint System

### Constraint Types

Binius64 has only two constraint types:

1. **AND Constraint**: `(A) & (B) ⊕ (C) = 0`
   - A, B, C are operands (XOR combinations of shifted values)
   - Cost: 1x (baseline)

2. **MUL Constraint**: `(A) × (B) = (HI << 64) | LO`
   - 64×64 bit multiplication producing 128-bit result
   - Cost: ~200x (expensive)

### Operand Structure

Within each operand (A, B, or C), these are "free" (no additional constraints):
- XOR of multiple values: `v1 ⊕ v2 ⊕ v3 ⊕ ...`
- Shifted values: `v1 >> 5`, `v2 << 3`, `v3 >>> 7`
- Constants: `0xFFFFFFFFFFFFFFFF`
- Any combination: `(v1 >> 2) ⊕ (v2 << 5) ⊕ 0x12345678`

### Basic Operation Encoding

#### XOR (Field Addition in GF(2^64))
To compute `result = a ⊕ b`:
```
Constraint: (a) & (0xFFFFFFFFFFFFFFFF) ⊕ (b ⊕ result) = 0
```
Since `a & 0xFF..FF = a`, this enforces `a = b ⊕ result`, thus `result = a ⊕ b`.

#### AND
To compute `result = a & b`:
```
Constraint: (a) & (b) ⊕ (result) = 0
```

#### NOT
To compute `result = ~a`:
```
Constraint: (a) & (0xFFFFFFFFFFFFFFFF) ⊕ (0xFFFFFFFFFFFFFFFF ⊕ result) = 0
```
This is just XOR with all-ones: `result = a ⊕ 0xFF..FF`.

#### Equality
To enforce `a = b`:
```
Constraint: (a ⊕ b) & (0xFFFFFFFFFFFFFFFF) ⊕ (0) = 0
```
This forces `a ⊕ b = 0`, which means `a = b` in GF(2^64).

## Architecture

### Expression Layer
Users write typed functional code that builds expression trees:
```rust
let a = val::<Field64>(0);
let b = val::<Field64>(1);
let c = val::<Field64>(2);
let result = xor(&a, &and(&not(&b), &c));
```

### Expression Tree Representation
```rust
enum ExprNode {
    // Values
    Witness(u32),
    Constant(u64),
    
    // Bitwise operations
    Xor(Rc<ExprNode>, Rc<ExprNode>),
    And(Rc<ExprNode>, Rc<ExprNode>),
    Or(Rc<ExprNode>, Rc<ExprNode>),
    Not(Rc<ExprNode>),
    
    // Shifts and rotations
    Shl(Rc<ExprNode>, u8),
    Shr(Rc<ExprNode>, u8),
    Ror(Rc<ExprNode>, u8),
    
    // Arithmetic
    Add32(Rc<ExprNode>, Rc<ExprNode>),
    Mul64(Rc<ExprNode>, Rc<ExprNode>),
    
    // Equality constraint
    Equal(Rc<ExprNode>, Rc<ExprNode>),
}
```

### Optimization Pipeline

The expression tree passes through four phases in strict order:

1. **Canonicalization**: Transforms expressions into a normal form where semantically equivalent expressions have identical structure. Flattens nested associative operations (XOR chains), sorts commutative operands by a deterministic ordering, and positions constants consistently. This ensures pattern matchers need only recognize one canonical form rather than all equivalent variations.

2. **Expression Rewriting**: Applies pattern-based transformations on the canonicalized tree. Patterns can be written simply since they match against predictable canonical forms. Rewriting may expose new optimization opportunities by restructuring expressions (e.g., transforming `(a&b)⊕(a&c)⊕(b&c)` into `(a⊕c)&(b⊕c)⊕c` creates shared subexpressions).

3. **Common Subexpression Elimination** (Optional, disabled by default): Identifies duplicate subtrees in the expression DAG and replaces them with references to a single computation. In practice, well-written circuits rarely have duplicate computations, so this pass is disabled by default to avoid its runtime cost. It can be enabled for poorly structured input code where the same complex expression might be computed multiple times.

   When enabled, CSE marks shared subexpressions so constraint generation knows to bind them to temporary variables rather than recomputing them.

4. **Constraint Generation**: Traverses the final optimized DAG to emit constraints. Must run last because delayed binding decisions depend on: (a) the final expression structure after all optimizations, (b) which values are shared versus used once (from CSE), and (c) the patterns present in the optimized form. The algorithm can make better packing decisions with complete structural information.

## Delayed Binding Constraint Generation

### Core Algorithm

The algorithm accumulates operations into complex operands until a constraint boundary is reached. Multiple XOR operations, shifts, and constants combine into single operand terms, eliminating intermediate constraints.

Example: `(a >> 2) ⊕ (b << 5) ⊕ c ⊕ 0x12345678` becomes a single operand term rather than requiring 3 XOR constraints. Temporary variables are created only at constraint boundaries (AND, MUL) or when results must be stored.

#### Operand Building

Operations fall into two categories:
- **Operandic**: Can be represented directly in operand structure (XOR, NOT, shifts)
- **Constraining**: Require generating constraints (AND, OR, MUL, ADD)

```rust
fn build_expr(&mut self, expr: &ExprNode) -> Operand {
    match expr {
        // Operandic operations - build operand without constraints
        ExprNode::Xor(a, b) => {
            let a_op = self.build_expr(a);
            let b_op = self.build_expr(b);
            a_op.xor(b_op)  // Combine operands
        }
        
        // Constraining operations - must generate constraint
        ExprNode::And(a, b) => {
            let a_op = self.build_expr(a);
            let b_op = self.build_expr(b);
            
            // Check if we can pack into existing constraint
            if let Some(packed) = self.try_pack_and(a_op, b_op) {
                return packed;
            }
            
            // Must create temporary and constraint
            let result = self.next_temp();
            self.constraints.push(Constraint::And {
                a: a_op,
                b: b_op,
                c: Operand::from_value(result),
            });
            Operand::from_value(result)
        }
    }
}
```

#### Constraint Packing

When an AND operation's result feeds into XORs, we can pack them together:

```rust
// Expression: x = a ⊕ ((¬b) & c)
// Becomes: (b ⊕ 0xFF..) & c ⊕ (a ⊕ x) = 0
```

The packing works because the AND constraint form `A & B ⊕ C = 0` allows arbitrary XOR combinations in the C operand.

### Operand Structure

```rust
struct Operand {
    terms: Vec<ShiftedValue>,  // XOR of these terms
    constant: Option<u64>,      // Optional constant to XOR
}

struct ShiftedValue {
    value_id: u32,       // Witness or temp ID
    shift_op: ShiftOp,   // None, Shl, Shr, Ror, etc.
    shift_amount: u8,    // 0-63
}
```

Operations on operands:
- XOR: Concatenate term lists, XOR constants
- Shifts: Apply to each term
- Constants: Set or XOR with existing constant

## Pattern Recognition and Rewriting

### Pattern Detection

Patterns are detected through structural matching on the expression tree:

```rust
fn detect_xor_of_ands_pattern(expr: &ExprNode) -> Option<(Rc<ExprNode>, Rc<ExprNode>, Rc<ExprNode>)> {
    // Match: (a & b) ⊕ (a & c) ⊕ (b & c)
    if let ExprNode::Xor(left, right) = expr {
        if let (Some((a1, b1)), Some((a2, c1))) = (extract_and(left), extract_and(right)) {
            if a1 == a2 { /* found pattern */ }
        }
    }
    None
}
```

### Rewriting Rules

Rewriting rules are transformations that replace expression patterns with semantically equivalent but structurally different forms. Rules are applied when the new form will generate fewer constraints or expose further optimization opportunities.

A rewrite rule consists of:
1. **Pattern**: The expression structure to match
2. **Guard**: Additional conditions that must hold
3. **Replacement**: The new expression structure

Example rule for XOR of ANDs pattern:
```rust
// Pattern: (a & b) ⊕ (a & c) ⊕ (b & c)
// Replacement: (a ⊕ c) & (b ⊕ c) ⊕ c
fn rewrite_xor_of_ands(a: Rc<ExprNode>, b: Rc<ExprNode>, c: Rc<ExprNode>) -> ExprNode {
    ExprNode::Xor(
        Rc::new(ExprNode::And(
            Rc::new(ExprNode::Xor(a, c.clone())),
            Rc::new(ExprNode::Xor(b, c.clone()))
        )),
        c
    )
}
```

The replacement form generates 2 constraints instead of 3, and creates the common subexpression `c` that CSE can exploit.

## Optimization Passes

### Pass 1: Canonicalization
- Flatten nested XORs: `(a ⊕ b) ⊕ c` → `XorChain([a, b, c])`
- Sort operands for consistent ordering
- Normalize constants to right side

### Pass 2: Boolean Simplifications
- `x ⊕ x` → `0`
- `x ⊕ 0` → `x`
- `x & 0` → `0`
- `x & 0xFF..FF` → `x`
- `~~x` → `x`

### Pass 3: XOR Chain Consolidation
Eliminates common terms in XOR chains:
```
(a ⊕ b) ⊕ (a ⊕ c) → b ⊕ c
```

### Pass 4: Pattern-Specific Rewrites

#### Masked AND-XOR (Keccak Chi)
```
a ⊕ ((~b) & c)
→ Single constraint: (b ⊕ 0xFF..) & c ⊕ (a ⊕ result) = 0
```

#### Binary Choice (SHA256 Ch)
```
(a & b) ⊕ ((~a) & c)
→ a & (b ⊕ c) ⊕ c
→ Single constraint: a & (b ⊕ c) ⊕ (result ⊕ c) = 0
```

#### XOR of ANDs Pattern
```
(a & b) ⊕ (a & c) ⊕ (b & c)
→ (a ⊕ c) & (b ⊕ c) ⊕ c
→ Two constraints (optimal for this pattern)
```

### Pass 5: Template Matching

Templates handle complex patterns that generate multiple constraints with specific structure. Unlike simple rewrites, templates directly generate optimized constraint sequences.

```rust
trait ConstraintTemplate {
    fn matches(&self, expr: &ExprNode) -> bool;
    fn generate(&self, expr: &ExprNode, next_temp: &mut u32) -> Vec<Constraint>;
}
```

Example - Carry Chain Template:
```rust
// Pattern: ((a + b) + c) + d  (chain of additions)
// Generates fused carry propagation constraints instead of separate additions

struct CarryChainTemplate;

impl ConstraintTemplate {
    fn matches(&self, expr: &ExprNode) -> bool {
        // Detect: Add(Add(Add(a, b), c), d)
        matches!(expr, ExprNode::Add32(
            box ExprNode::Add32(
                box ExprNode::Add32(_, _), _
            ), _
        ))
    }
    
    fn generate(&self, expr: &ExprNode, next_temp: &mut u32) -> Vec<Constraint> {
        // Extract operands: [a, b, c, d]
        let operands = extract_addition_chain(expr);
        
        // Generate single fused carry constraint
        // Instead of 6 constraints (3 additions × 2 each)
        generate_fused_carry_chain(operands, next_temp)
    }
}
```

Templates are checked before general constraint generation - if a template matches, its specialized generation is used instead of the default algorithm.

## Constraint Generation Details

### AND Constraints

Basic form: `A & B ⊕ C = 0`

Encoding patterns:
- Direct AND: `result = a & b` → `a & b ⊕ result = 0`
- AND with XOR: `result = (a & b) ⊕ c` → `a & b ⊕ (c ⊕ result) = 0`
- Masked AND: `result = a & (b ⊕ mask)` → `a & (b ⊕ mask) ⊕ result = 0`

### MUL Constraints

Form: `A × B = (hi << 64) | lo`

Used for:
- 64-bit multiplication
- Multi-word arithmetic with carry
- Field operations

### Operand Encoding

Within operands, these are "free" (no additional constraints):
- XOR of multiple values: `a ⊕ b ⊕ c ⊕ ...`
- Shifted values: `a >> 5`, `b << 3`, `c >>> 7`
- Constants: `0xFF00FF00`
- Combinations: `(a >> 2) ⊕ (b << 5) ⊕ 0x12345678`

## Implementation Structure

```
crates/beamish/src/
  expr.rs           - Expression tree types
  types.rs          - Type markers (Field64, U32, etc.)
  ops/              - Typed operations (xor, and, add, etc.)
  constraints.rs    - Core constraint types
  generate/         
    delayed_binding.rs - Constraint generation with delayed binding
  optimize/
    canonicalize.rs - Expression normalization
    rewrite.rs      - Pattern-based rewriting
    templates.rs    - Multi-constraint templates
    cse.rs          - Common subexpression elimination
  compute/
    expressions.rs  - Expression evaluation
    constraints.rs  - Constraint validation
```

## Usage Example

```rust
use binius_beamish::*;

// Build expression for Keccak chi step
let a = val::<Field64>(0);
let b = val::<Field64>(1); 
let c = val::<Field64>(2);
let chi = xor(&a, &and(&not(&b), &c));

// Generate optimized constraints
let constraints = to_constraints(&chi, &OptConfig::default());
// Result: 1 constraint instead of 3
```

## Configuration

Optimizations can be controlled via `OptConfig`:

```rust
let mut config = OptConfig::none_enabled();
config.xor_chain_consolidation = true;
config.masked_and_xor_rewrite = true;
config.cse_enabled = true;

let constraints = to_constraints(&expr, &config);
```

## Correctness

Each optimization preserves semantic equivalence. The test suite validates:
1. Optimized circuits produce identical results to unoptimized
2. Constraint counts match expected reductions

## U32 Operations in GF(2^64)

U32 operations are implemented as regular GF(2^64) operations with the constraint that values are masked to 32 bits:

- **Storage**: U32 values are stored in the lower 32 bits of 64-bit field elements
- **Operations**: All operations (XOR, AND, etc.) work identically on the lower 32 bits
- **Rotations**: `ror32(x, n)` = `(x & 0xFFFFFFFF).rotate_right(n) & 0xFFFFFFFF`
- **Shifts**: `shr32(x, n)` = `((x & 0xFFFFFFFF) >> n)`
- **Addition**: `add32(a, b)` = `(a + b) & 0xFFFFFFFF`

The key insight: We don't need separate constraint types - the same AND and MUL constraints work, we just ensure values stay within 32-bit range through masking in the witness generation.

## Appendix: Mathematical Foundations

### Field Axioms for GF(2^64)

In the binary field GF(2^64):
- **Addition = XOR**: `a + b = a ⊕ b`
- **Additive inverse**: `−a = a` (every element is its own inverse)
- **Characteristic 2**: `1 + 1 = 0`, therefore `a + a = 0`

### Formal Derivations of Rewriting Rules

#### XOR Chain Consolidation

**Pattern**: Sequential XOR constraints
```
C1: a & 0xFF..FF ⊕ (b ⊕ t1) = 0
C2: t1 & 0xFF..FF ⊕ (c ⊕ result) = 0
```

**Optimization**: Single operand `a ⊕ b ⊕ c` in consuming constraint

**Proof**: From C1: `a = b ⊕ t1`, so `t1 = a ⊕ b`. From C2: `t1 = c ⊕ result`, so `result = t1 ⊕ c = (a ⊕ b) ⊕ c = a ⊕ b ⊕ c`.

#### Masked AND-XOR Pattern (Keccak Chi)

**Pattern**: `a ⊕ ((~b) & c)`

**Naive**: 
```
C1: b & 0xFF..FF ⊕ (0xFF..FF ⊕ not_b) = 0
C2: not_b & c ⊕ temp = 0
C3: a & 0xFF..FF ⊕ (temp ⊕ result) = 0
```

**Optimized**: Single constraint `(b ⊕ 0xFF..FF) & c ⊕ (a ⊕ result) = 0`

**Proof**: From C1: `not_b = b ⊕ 0xFF..FF`. Substituting into C2: `(b ⊕ 0xFF..FF) & c = temp`. From C3: `result = a ⊕ temp = a ⊕ ((b ⊕ 0xFF..FF) & c)`.

#### Binary Choice Pattern (SHA256 Ch)

**Pattern**: `(a & b) ⊕ ((~a) & c)`

**Mathematical identity**: `a & (b ⊕ c) ⊕ c`

**Proof**: When `a = 1`: `(1 & b) ⊕ (0 & c) = b`. When `a = 0`: `(0 & b) ⊕ (1 & c) = c`. The identity `a & (b ⊕ c) ⊕ c` gives the same results.

#### XOR of ANDs Pattern

**Pattern**: `(a & b) ⊕ (a & c) ⊕ (b & c)`

**Mathematical identity**: `(a ⊕ c) & (b ⊕ c) ⊕ c`

**Proof**: Expanding `(a ⊕ c) & (b ⊕ c)` using distributivity over GF(2): equals `(a & b) ⊕ (a & c) ⊕ (c & b) ⊕ (c & c)`. Since `c & c = c` in GF(2), this becomes `(a & b) ⊕ (a & c) ⊕ (b & c) ⊕ c`. XORing with `c` gives the original majority expression.

## Appendix: Control Flow Design

### Overview

Control flow operations enable dynamic behavior in static circuits through predicated execution patterns. These operations allow circuits to handle variable-length operations and dynamic indexing without branching.

### Core Patterns

#### 1. Predicated Fold Pattern

The predicated fold pattern enables dynamic iteration in static circuits by unrolling all iterations and using conditional state updates.

**Key Insight**: Instead of branching, we compute all iterations and mask inactive ones.

```rust
pub fn dynamic_fold<S, F>(
    range: Range<Expr<U32>>,
    max_iterations: u32,
    init: S,
    body: F,
) -> S
```

**Properties**:
- All iterations exist in the circuit
- Each iteration conditionally updates state based on `index < end`
- Overhead is proportional to max_iterations, not actual iterations

#### 2. Dynamic Array Indexing

Dynamic array indexing allows selecting array[i] where i is a runtime value.

**Challenge**: Circuits can't have dynamic memory access - all paths must exist.

**Solution**: Build a multiplexer tree that selects based on index bits.

### Implementation Details

#### Understanding Building Blocks

From our ops modules, we have:
- `select(cond, true_val, false_val)` - Returns true_val when cond is ALL-1s, false_val when cond is ALL-0s
- `sar32(value, amount)` - Arithmetic shift right for U32 (sign-extends from bit 31)
- `and(a, b)` - Bitwise AND
- `shl(a, amount)` - Logical shift left
- `icmp_ult(a, b)` - Returns ALL-1s if a < b, ALL-0s otherwise

**Critical Requirement**: `select` requires its condition to be all-1s or all-0s, not just 1 or 0!

#### Binary Tree Array Indexing

For array of size N, we need ceil(log2(N)) bits from the index.

**Algorithm**:
```
Given array [a0, a1, a2, a3] and index=2 (binary 10):

Level 0 (bit 0=0): select(ALL-0s, a1, a0)=a0, select(ALL-0s, a3, a2)=a2
Level 1 (bit 1=1): select(ALL-1s, a2, a0)=a2 ✓
```

**Bit Broadcasting**: Convert single bit to all-1s or all-0s mask:
```rust
let bit = and(&shifted, &constant::<U32>(1));
let bit_msb = shl(&bit, 31);  // Move to MSB
let mask = sar32(&bit_msb, 31);  // Broadcast MSB to all bits
```

#### Final Implementation

```rust
pub fn array_index<T: BitType>(array: &[Expr<T>], index: &Expr<U32>) -> Expr<T> {
    use crate::ops::bitwise::{and, shr32, shl, sar32};
    
    let mut current_level = array.to_vec();
    let mut bit_pos = 0u8;
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        // Extract bit k and broadcast to all bits
        let shifted = if bit_pos > 0 {
            shr32(index, bit_pos)
        } else {
            index.clone()
        };
        
        let bit = and(&shifted, &constant::<U32>(1));
        let bit_msb = shl(&bit, 31);
        let mask_u32 = sar32(&bit_msb, 31);
        let mask_t: Expr<T> = Expr::wrap(mask_u32.inner);
        
        // Build next level of tree
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(select(&mask_t, &chunk[1], &chunk[0]));
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        
        current_level = next_level;
        bit_pos += 1;
    }
    
    current_level[0].clone()
}
```

**Constraint Count**: 2(N-1) AND constraints for N elements
- N-1 select operations 
- N-1 AND operations for bit extraction

### Performance Results

Tests show dynamic operations achieve reasonable overhead:

- **Array indexing**: Correctly selects elements (array[0]→0, array[3]→3, etc.)
- **Dynamic fold**: Correctly computes sums (0+1+2=3, sum 0..9=45)
- **Constraint overhead**: 9x for dynamic vs fixed iteration (180 vs 20 constraints for 10-element sum)

This provides an efficient foundation for dynamic message sizes in Keccak and other variable-length operations.
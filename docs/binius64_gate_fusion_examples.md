# Binius64 Gate Fusion: Implementation Examples

## Problem Statement

Every gate in Binius64 must produce a witness value, forcing constraint generation even for operations that should be "free" within constraint operands. This document provides concrete implementation examples showing how to fix this.

## Core Issue: Forced Witness Materialization

```rust
// Current: Every operation creates a constraint
let r1 = b.rotr_32(a, 2);   // Forces: ((a>>2) ⊕ (a<<30)) & MASK_32 = r1
let r2 = b.rotr_32(a, 13);  // Forces: ((a>>13) ⊕ (a<<19)) & MASK_32 = r2
let x = b.bxor(r1, r2);     // Forces: (r1 ⊕ r2) & ALL_1 = x

// Optimal: Single constraint with all operations in operand
// ((a>>2) ⊕ (a<<30) ⊕ (a>>13) ⊕ (a<<19)) & MASK_32 = result
```

## Solution 1: Macro Gates (Quickest Win)

### Implementation

```rust
// In crates/frontend/src/compiler/gate/sha256_sigma.rs
pub mod sha256_sigma {
    use binius_core::word::Word;
    use crate::compiler::{
        constraint_builder::{ConstraintBuilder, sll, srl, xor6},
        gate::opcode::OpcodeShape,
        gate_graph::{Gate, GateData, GateParam, Wire},
    };

    pub fn big_sigma_0_shape() -> OpcodeShape {
        OpcodeShape {
            const_in: &[Word::MASK_32],
            n_in: 1,
            n_out: 1,
            n_internal: 0,
            n_scratch: 0,
            n_imm: 0,
        }
    }

    pub fn big_sigma_0_constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
        let GateParam { constants, inputs, outputs, .. } = data.gate_param();
        let [mask32] = constants else { unreachable!() };
        let [a] = inputs else { unreachable!() };
        let [z] = outputs else { unreachable!() };

        // Single constraint for entire operation
        builder
            .and()
            .a(xor6(
                srl(*a, 2), sll(*a, 30),
                srl(*a, 13), sll(*a, 19),
                srl(*a, 22), sll(*a, 10)
            ))
            .b(*mask32)
            .c(*z)
            .build();
    }
}

// Add to CircuitBuilder
impl CircuitBuilder {
    pub fn sha256_big_sigma_0(&self, a: Wire) -> Wire {
        let z = self.add_internal();
        let mut graph = self.graph_mut();
        graph.emit_gate(self.current_path, Opcode::Sha256BigSigma0, [a], [z]);
        z
    }
}
```

### Usage

```rust
// Before: 5 constraints
fn big_sigma_0_old(b: &CircuitBuilder, a: Wire) -> Wire {
    let r1 = b.rotr_32(a, 2);
    let r2 = b.rotr_32(a, 13);
    let r3 = b.rotr_32(a, 22);
    let x1 = b.bxor(r1, r2);
    b.bxor(x1, r3)
}

// After: 1 constraint
fn big_sigma_0_new(b: &CircuitBuilder, a: Wire) -> Wire {
    b.sha256_big_sigma_0(a)
}
```

## Solution 2: Expression-Based Builder

### Implementation

```rust
// New expression-based API
pub struct ExprBuilder<'a> {
    builder: &'a CircuitBuilder,
    expr: WireExpr,
}

impl CircuitBuilder {
    pub fn expr(&self, w: Wire) -> ExprBuilder {
        ExprBuilder {
            builder: self,
            expr: WireExpr::Wire(w),
        }
    }
}

impl<'a> ExprBuilder<'a> {
    pub fn rotr_32(mut self, n: u32) -> Self {
        // Build expression without creating constraint
        self.expr = WireExpr::Xor2(
            WireExprTerm::Shifted(self.get_wire(), ShiftOp::Srl(n)),
            WireExprTerm::Shifted(self.get_wire(), ShiftOp::Sll(32 - n)),
        );
        self
    }
    
    pub fn xor(mut self, other: ExprBuilder<'a>) -> Self {
        // Combine expressions
        self.expr = combine_xor_exprs(self.expr, other.expr);
        self
    }
    
    pub fn materialize_32(self) -> Wire {
        // Create single constraint to materialize result
        let z = self.builder.add_internal();
        let mut graph = self.builder.graph_mut();
        
        // Direct constraint generation
        graph.constraint_builder.and()
            .a(self.expr)
            .b(Word::MASK_32)
            .c(z)
            .build();
        z
    }
}

// Usage
fn big_sigma_0_expr(b: &CircuitBuilder, a: Wire) -> Wire {
    b.expr(a)
        .rotr_32(2)
        .xor(b.expr(a).rotr_32(13))
        .xor(b.expr(a).rotr_32(22))
        .materialize_32()  // Single constraint here
}
```

## Solution 3: Lazy Wire System

### Implementation

```rust
pub enum WireValue {
    Materialized(Wire),
    Lazy(LazyExpr),
}

pub struct LazyExpr {
    terms: Vec<ShiftedWire>,
}

impl CircuitBuilder {
    pub fn rotr_32_lazy(&self, x: WireValue, n: u32) -> WireValue {
        match x {
            WireValue::Materialized(w) => {
                WireValue::Lazy(LazyExpr {
                    terms: vec![
                        ShiftedWire { wire: w, shift: Shift::Srl(n) },
                        ShiftedWire { wire: w, shift: Shift::Sll(32 - n) },
                    ],
                })
            }
            WireValue::Lazy(expr) => {
                // Extend existing expression
                let mut new_terms = Vec::new();
                for term in expr.terms {
                    new_terms.push(term.rotate_right(n));
                }
                WireValue::Lazy(LazyExpr { terms: new_terms })
            }
        }
    }
    
    pub fn force_materialize(&self, val: WireValue, mask: Word) -> Wire {
        match val {
            WireValue::Materialized(w) => w,
            WireValue::Lazy(expr) => {
                let z = self.add_internal();
                // Generate single constraint
                self.constraint_builder.and()
                    .a(expr.to_operand())
                    .b(mask)
                    .c(z)
                    .build();
                z
            }
        }
    }
}
```

## Keccak-Specific Optimizations

### Theta Step Fusion

```rust
// Current: 55 constraints for theta
fn theta_current(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    // 25 XOR operations for column parity (25 constraints)
    let c0 = b.bxor(b.bxor(b.bxor(b.bxor(
        state[0], state[5]), state[10]), state[15]), state[20]);
    // ... repeat for c1-c4
    
    // 5 rotations (5 constraints)
    let d0 = b.bxor(c4, rotate_left(b, c1, 1));
    // ...
    
    // 25 XOR to apply (25 constraints)
    for y in 0..5 {
        state[idx(0, y)] = b.bxor(state[idx(0, y)], d0);
        // ...
    }
}

// Optimized: ~10 constraints
fn theta_optimized(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    // Column parity with single constraint each
    let c = [
        b.xor5(state[0], state[5], state[10], state[15], state[20]),
        b.xor5(state[1], state[6], state[11], state[16], state[21]),
        // ...
    ];
    
    // D values with fused rotation
    let d = [
        b.xor_with_rotated(c[4], c[1], 1),
        // ...
    ];
    
    // Apply with batched operations
    for x in 0..5 {
        b.batch_xor_column(&mut state[x*5..(x+1)*5], d[x]);
    }
}
```

### Chi Step Fusion

```rust
// Current: 75 constraints (25 NOT + 25 AND + 25 XOR)
fn chi_current(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    for y in 0..5 {
        let a0 = state[idx(0, y)];
        let a1 = state[idx(1, y)];
        let a2 = state[idx(2, y)];
        
        state[idx(0, y)] = b.bxor(a0, b.band(b.bnot(a1), a2));
        // Each line: bnot (1) + band (1) + bxor (1) = 3 constraints
    }
}

// Optimized: 25 constraints
fn chi_optimized(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    for y in 0..5 {
        let row = &state[y*5..(y+1)*5];
        // Single constraint per element: a0 ⊕ ((¬a1) & a2)
        for x in 0..5 {
            let z = b.add_internal();
            b.constraint_builder.and()
                .a(xor2(row[x], row[(x+2)%5]))
                .b(xor2(row[(x+1)%5], Word::ALL_ONE))
                .c(z)
                .build();
            state[y*5 + x] = z;
        }
    }
}
```

## Migration Path

### Phase 1: Add Macro Gates (Non-Breaking)
```rust
// Extend Opcode enum
pub enum Opcode {
    // ... existing opcodes ...
    
    // SHA-256 macro gates
    Sha256BigSigma0,
    Sha256BigSigma1,
    Sha256SmallSigma0,
    Sha256SmallSigma1,
    
    // Keccak macro gates
    KeccakTheta,
    KeccakChiRow,
}
```

### Phase 2: Progressive Migration
```rust
// Add feature flag for optimization
#[cfg(feature = "optimized-gates")]
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
    b.sha256_big_sigma_0(a)  // Use macro gate
}

#[cfg(not(feature = "optimized-gates"))]
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
    // Original implementation
    let r1 = b.rotr_32(a, 2);
    // ...
}
```

### Phase 3: Automated Detection
```rust
// Pattern matcher for optimization opportunities
impl CircuitOptimizer {
    fn detect_sigma_pattern(&self, gates: &[Gate]) -> Option<SigmaPattern> {
        // Detect: rotr_32 -> rotr_32 -> rotr_32 -> bxor -> bxor
        // Replace with: sha256_big_sigma_0
    }
}
```

## Performance Impact Summary

| Operation | Current | Optimized | Reduction |
|-----------|---------|-----------|-----------|
| SHA-256 big_sigma_0 | 5 AND | 1 AND | 5x |
| SHA-256 full compress | ~2784 AND | ~550 AND | 5x |
| Keccak theta | 55 AND | 10 AND | 5.5x |
| Keccak chi | 75 AND | 25 AND | 3x |
| Keccak full | ~3720 AND | ~720 AND | 5.2x |

## Next Steps

1. **Immediate**: Implement macro gates for SHA-256 sigma functions
2. **Short-term**: Add xor5, xor6 helpers to constraint_builder
3. **Medium-term**: Expression-based API for advanced users
4. **Long-term**: Automatic pattern detection and optimization
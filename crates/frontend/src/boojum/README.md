# Boojum: A New Paradigm for ZK Proof Construction

## Core Insight

**Constraints are a compilation target, not a programming model.**

## Architecture

The Boojum architecture strictly separates:

1. **Witness Computation** - Pure imperative Rust code
2. **Constraint Compilation** - Declarative mapping to Binius64 primitives

## Fundamental Constraint Shape (CANNOT BE CHANGED)

The backend requires EXACTLY these constraint types:

### AND Constraint
```
(A ∧ B) ⊕ C = 0
```
Where A, B, C are operands that can be:
- Plain witness values
- XOR combinations of multiple values: `x ⊕ y ⊕ z ⊕ ...`
- Shifted values (FREE): `x << 5`, `y >> 3`, `z >>_arithmetic 7`
- Any combination: `(x << 3) ⊕ (y >> 5) ⊕ z`

Cost: 1 unit

### MUL Constraint  
```
A × B = (HI << 64) | LO
```
Where A, B, HI, LO are operands (same flexibility as AND)

Cost: ~200 units

### Key Innovation: Shifted Value Indices

Within any operand, we can use shifted values for FREE:
- `sll(value, 0..63)` - Logical left shift
- `srl(value, 0..63)` - Logical right shift  
- `sar(value, 0..63)` - Arithmetic right shift

This means `(x << 5) ⊕ (y >> 3) ⊕ (z >>_a 1)` is a single operand with no extra constraints!

## How Boojum Preserves This Shape

The compilation flow ensures we ALWAYS output valid Binius64 constraints:

```
Witness Operations → CircuitBuilder Gates → AND/MUL Constraints
```

Examples of compilation:
- `band(x, y)` → `x ∧ y = z` (1 AND constraint)
- `bxor(x, y)` → Optimized away or 1 AND with all_1
- `add_with_carry(a, b, cin)` → 2 AND constraints for carry propagation
- `imul(a, b)` → 1 MUL constraint
- `shl(x, 5)` → NO constraint (incorporated into operands)

## Example: 128-bit Addition

Witness computation:
```rust
let (sum_low, carry) = ctx.add_with_carry(a_low, b_low, zero);
let (sum_high, _) = ctx.add_with_carry(a_high, b_high, carry);
```

Compiles to 4 AND constraints:
1. Carry propagation for low limb (2 AND)
2. Carry propagation for high limb (2 AND)

The shifts and XORs within each constraint are FREE!

## Cost Model

When compiling, we optimize based on:
- AND constraint: 1 unit
- MUL constraint: 200 units  
- Witness value: ~0.2 units
- XOR/Shift in operands: FREE

The compiler chooses between equivalent formulations to minimize total cost.

## Why This Matters

1. **Guaranteed Valid Output** - Compiler can ONLY produce valid Binius64 constraints
2. **Optimization Freedom** - Can recognize patterns and choose optimal formulation
3. **Clear Separation** - Witness computation doesn't know about constraints
4. **Future Proof** - New optimizations can be added to compiler without changing witness code
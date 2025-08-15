# Binius64 Gate Optimization Analysis

## Executive Summary

The current Binius64 gate system forces unnecessary constraint generation due to witness materialization requirements. Even simple XOR operations require AND constraints to produce witness values. This analysis identifies **3-5x potential constraint reduction** in cryptographic circuits through constraint fusion and lazy evaluation.

## Critical Finding: XOR Requires Constraints

Contrary to the initial assumption that XORs are "free", the current implementation requires:
- **`bxor` gate**: `(x ⊕ y) ∧ all-1 = z` (1 AND constraint)
- **`shl` gate**: `(x << n) ∧ all-1 = z` (1 AND constraint)  
- **`rotr_32` gate**: `((x>>n) ⊕ (x<<(32-n))) ∧ MASK_32 = z` (1 AND constraint)

This happens because every gate must produce a witness value for its output Wire.

## Circuit Analysis Results

### SHA-256 Compression Function

**Current Implementation (per round, 64 rounds total):**

#### Sigma Functions (4 total per round)
- `big_sigma_0`: 3 rotr_32 + 2 bxor = **5 AND constraints**
- `big_sigma_1`: 3 rotr_32 + 2 bxor = **5 AND constraints**
- `small_sigma_0`: 2 rotr_32 + 1 shr_32 + 2 bxor = **5 AND constraints**
- `small_sigma_1`: 2 rotr_32 + 1 shr_32 + 2 bxor = **5 AND constraints**

#### Logic Functions (per round)
- `ch`: 2 bxor + 1 band = **3 AND constraints**
- `maj`: 2 bxor + 2 band = **4 AND constraints**

**Total per round**: ~27 AND constraints (excluding additions)
**Total for 64 rounds**: ~1,728 AND constraints

**Theoretical Optimal:**
- Each sigma function: **1 AND constraint** (all shifts/XORs in operand)
- `ch`/`maj`: **1-2 AND constraints** each

**Potential reduction: 1,728 → ~400 constraints (4.3x improvement)**

### Keccak-f[1600] Permutation

**Current Implementation (per round, 24 rounds total):**

#### Theta Step
- 25 XORs to compute C[x]: **25 AND constraints**
- 5 rotations for D[x]: **5 AND constraints**
- 25 XORs to apply D[x]: **25 AND constraints**

#### Rho-Pi Step  
- 25 rotations: **25 AND constraints**

#### Chi Step
- 25 NOT operations (XOR with all-1): **25 AND constraints**
- 25 AND operations: **25 AND constraints**
- 25 XOR operations: **25 AND constraints**

**Total per round**: ~155 AND constraints
**Total for 24 rounds**: ~3,720 AND constraints

**Theoretical Optimal:**
- Theta: Could be reduced to ~10 constraints with fusion
- Chi: Each row could be single constraint
- Potential: **3,720 → ~720 constraints (5x improvement)**

### Base64 Encoding/Decoding

Heavy use of:
- `band` for masking: Each requires 1 AND constraint
- `bor` operations: Each requires constraints
- Shift operations for byte extraction

**Potential optimization**: Byte extraction patterns could be fused into single constraints.

## Proposed Gate Designs

### 1. Expression Gates (Lazy Evaluation)

```rust
enum GateOutput {
    Materialized(Wire),      // Forces witness generation
    Expression(WireExpr),    // Defers constraint generation
}

// New gate variants
fn bxor_lazy(&self, a: Wire, b: Wire) -> Expression
fn rotr_32_lazy(&self, x: Wire, n: u32) -> Expression
fn big_sigma_0_fused(&self, x: Wire) -> Wire  // Single constraint
```

### 2. Macro Gates for Common Patterns

```rust
// SHA-256 specific
fn sha256_big_sigma_0(&self, x: Wire) -> Wire {
    // Generates single AND constraint:
    // ((x>>2) ⊕ (x<<30) ⊕ (x>>13) ⊕ (x<<19) ⊕ (x>>22) ⊕ (x<<10)) & MASK_32 = result
}

fn sha256_ch(&self, e: Wire, f: Wire, g: Wire) -> Wire {
    // Single constraint: (g ⊕ (e & (f ⊕ g))) & all-1 = result
}

// Keccak specific  
fn keccak_theta_column(&self, state: &[Wire; 5]) -> Wire {
    // Single constraint for 5-way XOR
}

fn keccak_chi_row(&self, row: &[Wire; 5]) -> [Wire; 5] {
    // 5 constraints instead of 55
}
```

### 3. Fusion Hints System

```rust
trait FusionContext {
    fn mark_fusable(&mut self, wire: Wire);
    fn force_materialize(&mut self, wire: Wire);
    fn try_fuse(&mut self) -> Option<FusedConstraint>;
}

// Usage
let r1 = b.rotr_32(a, 2).mark_fusable();
let r2 = b.rotr_32(a, 13).mark_fusable();
let result = b.fuse_xor(&[r1, r2, r3]); // Single constraint
```

### 4. Constraint Templates

```rust
enum ConstraintTemplate {
    RotateXorMask {
        input: Wire,
        rotations: Vec<(RotateDir, u32)>,
        mask: Word,
    },
    MultiXor {
        inputs: Vec<Wire>,
        shifts: Vec<Option<ShiftOp>>,
    },
    ChiPattern {
        row: [Wire; 5],
    },
}
```

## Implementation Strategy

### Phase 1: Non-Breaking Additions (Backward Compatible)
1. Add `_lazy` variants of existing gates
2. Implement macro gates for SHA-256 and Keccak
3. Keep existing gates unchanged

### Phase 2: Opt-in Fusion
1. Add `CircuitBuilder::with_fusion()` mode
2. Auto-detect fusable patterns in fusion mode
3. Provide diagnostics showing fusion opportunities

### Phase 3: Migration Tools
1. Automated rewriter for existing circuits
2. Linting for sub-optimal patterns
3. Performance benchmarks comparing approaches

## Quantified Impact

| Circuit | Current Constraints | Optimized | Reduction |
|---------|-------------------|-----------|-----------|
| SHA-256 (64 rounds) | ~1,728 AND | ~400 AND | 4.3x |
| Keccak-f[1600] | ~3,720 AND | ~720 AND | 5.2x |
| Base64 encode (per 3 bytes) | ~20 AND | ~6 AND | 3.3x |

## Design Decisions

### Should we have separate rotr_32_fusable vs rotr_32_materialized?
**Yes.** This provides explicit control while maintaining compatibility. The `_fusable` variants return expression handles rather than Wires.

### Can we detect patterns at compile time and auto-fuse?
**Yes, with limitations.** Local patterns (within a basic block) can be detected. Cross-block fusion requires more complex analysis.

### How do we balance optimization with debuggability?
- Keep materialized variants as default
- Add debug mode that forces materialization
- Provide introspection tools to see fusion decisions
- Generate fusion reports showing what was optimized

### Which circuits benefit most?
1. **Keccak** (5x reduction) - Heavy XOR usage in theta/chi
2. **SHA-256** (4x reduction) - Sigma functions are perfect fusion candidates
3. **Base64** (3x reduction) - Byte manipulation patterns

## Next Steps

1. Prototype `big_sigma_0_fused` gate for SHA-256
2. Measure actual constraint counts in test circuits
3. Implement expression-based constraint builder
4. Create migration guide for circuit authors

## Appendix: Fusion Examples

### Before (5 constraints):
```rust
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
    let r1 = b.rotr_32(a, 2);   // 1 constraint
    let r2 = b.rotr_32(a, 13);  // 1 constraint  
    let r3 = b.rotr_32(a, 22);  // 1 constraint
    let x1 = b.bxor(r1, r2);    // 1 constraint
    b.bxor(x1, r3)              // 1 constraint
}
```

### After (1 constraint):
```rust
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
    b.sha256_big_sigma_0(a)  // Single fused constraint
}
```

Or with expression API:
```rust
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
    b.constrain_and(
        xor6(
            srl(a, 2), sll(a, 30),
            srl(a, 13), sll(a, 19),
            srl(a, 22), sll(a, 10)
        ),
        MASK_32
    )
}
```
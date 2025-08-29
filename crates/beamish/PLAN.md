# Beamish Implementation Plan

## Overview

24-day implementation plan to build Beamish expression rewriting framework, achieving 2-4x constraint reduction for Binius64 circuits.

## Phase 1: Foundation (Days 1-4)

### Day 1: Core Types with Basic Operations
**Goal**: Implement Field64, U32, U64 with simple operations only

```rust
// Implement in crates/beamish/src/types/
pub struct Field64(Word);
pub struct U32(Word);
pub struct U64(Word);
pub struct Bool(Word);
```

**Tasks**:
- [ ] Create types module structure
- [ ] Implement Field64 with xor, and, not, ror operations
- [ ] Implement U32 with add, xor, ror operations  
- [ ] Implement U64 with add, add_with_carry operations
- [ ] Write basic operation tests

**Success Metrics**:
- Can express `a.xor(b).xor(c)`
- Can express `a.ror(7).xor(a.ror(18))`
- Type safety enforced (can't mix Field64 with U64)

### Day 2: Typed Expression AST
**Goal**: Build expression tree representation

```rust
pub enum TypedExpr {
    Field64Val(ValueId),
    Field64Xor(Box<TypedExpr>, Box<TypedExpr>),
    Field64And(Box<TypedExpr>, Box<TypedExpr>),
    // ... other basic operations
}
```

**Tasks**:
- [ ] Define TypedExpr enum with all basic operations
- [ ] Implement expression builders in types
- [ ] Add Display trait for debugging
- [ ] Test expression tree construction

**Success Metrics**:
- User code builds correct expression trees
- Trees are type-safe and well-formed

### Day 3: Pattern Matching Infrastructure
**Goal**: Build pattern recognition framework

```rust
pub trait Pattern {
    fn matches(&self, expr: &TypedExpr) -> Option<Bindings>;
}
```

**Tasks**:
- [ ] Create Pattern trait
- [ ] Implement Bindings for capturing matched sub-expressions
- [ ] Build pattern combinators (sequence, choice, repetition)
- [ ] Test pattern matching on simple expressions

### Day 4: Basic Constraint Generation
**Goal**: Compile expressions to constraints (without optimization)

**Tasks**:
- [ ] Implement naive constraint generation
- [ ] Test Field64 operations compile correctly
- [ ] Test U32/U64 arithmetic compiles correctly
- [ ] Verify constraint counts match expectations

**Deliverable**: Working type system that compiles to constraints
**Checkpoint**: All basic operations work end-to-end

## Phase 2: High-Impact Optimizations (Days 5-10)

### Day 5-6: XOR Chain Consolidation (Pass 1)
**Goal**: Eliminate all intermediate XOR constraints

**Implementation**:
```rust
pub struct XorChainPattern;
pub struct XorChainRewriter;
```

**Tasks**:
- [ ] Implement XOR chain pattern recognition
- [ ] Build XOR operand flattening algorithm
- [ ] Create OptimizedMultiXor expression node
- [ ] Test on nested XOR expressions

**Validation**:
```rust
// Test: a ^ b ^ c ^ d ^ e
// Before: 4 constraints
// After: 0 constraints (single operand)
```

**Impact**: 300-500 constraints eliminated per circuit

### Day 7-8: Keccak Chi Pattern (Pass 2)
**Goal**: 3x reduction for Keccak chi step

**Implementation**:
```rust
pub struct KeccakChiPattern;  // Recognizes a ^ ((~b) & c)
pub struct KeccakChiRewriter;
```

**Tasks**:
- [ ] Implement chi pattern matcher
- [ ] Create OptimizedKeccakChi node
- [ ] Implement optimized constraint generation
- [ ] Test on actual Keccak chi expressions

**Validation**:
```rust
// Test full Keccak chi step (5 elements)
// Before: 15 constraints
// After: 5 constraints
```

**Impact**: 1200 constraints eliminated in Keccak

### Day 9-10: Integration & Testing
**Goal**: Validate Pass 1-2 working together

**Tasks**:
- [ ] Build RewritePipeline to chain passes
- [ ] Test on partial Keccak implementation
- [ ] Benchmark constraint reductions
- [ ] Fix any pattern interaction issues

**Checkpoint**: Keccak showing 50%+ constraint reduction

## Phase 3: SHA Optimizations (Days 11-14)

### Day 11-12: Rotation XOR Pattern (Pass 3)
**Goal**: Recognize and optimize SHA Sigma functions

**Implementation**:
```rust
pub struct RotationXorPattern;  // (x>>>r1) ^ (x>>>r2) ^ (x>>>r3)
```

**Tasks**:
- [ ] Detect rotations of same base value
- [ ] Create OptimizedRotationXor node
- [ ] Generate zero additional constraints
- [ ] Test on SHA256 Sigma functions

**Validation**:
```rust
// SHA256 Σ0: x.ror(2).xor(x.ror(13)).xor(x.ror(22))
// Before: 2 constraints
// After: 0 constraints
```

**Impact**: 448 constraints eliminated per SHA256 block

### Day 13-14: SHA Ch/Maj Functions (Pass 4)
**Goal**: Optimize SHA mixing functions

**Tasks**:
- [ ] Implement Ch pattern: `(a & b) ^ ((~a) & c)`
- [ ] Implement Maj pattern: `(a & b) ^ (a & c) ^ (b & c)`
- [ ] Apply algebraic simplifications
- [ ] Test on SHA256 compression function

**Impact**: 256 constraints eliminated per SHA256 block

## Phase 4: Arithmetic Optimizations (Days 15-18)

### Day 15-16: Carry Chain Fusion (Pass 5)
**Goal**: Multi-precision arithmetic in single constraint

**Implementation**:
```rust
pub struct CarryChainPattern;
pub struct CarryChainRewriter;
```

**Tasks**:
- [ ] Detect sequential add_with_carry operations
- [ ] Build OptimizedCarryChain node
- [ ] Generate single MUL constraint
- [ ] Test on 128-bit addition

**Validation**:
```rust
// 128-bit addition
// Before: 4 constraints
// After: 1 constraint
```

**Impact**: 75% reduction in arithmetic operations

### Day 17-18: Conditional Fusion (Pass 6)
**Goal**: Optimize conditional arithmetic

**Tasks**:
- [ ] Detect condition → selection → arithmetic patterns
- [ ] Implement fused conditional operations
- [ ] Test on ECDSA-like operations
- [ ] Validate correctness preservation

**Impact**: 50% reduction in conditional operations

## Phase 5: Complete Integration (Days 19-21)

### Day 19: Full Keccak with All Optimizations
**Goal**: Implement complete Keccak-f1600 with typed API

**Tasks**:
- [ ] Implement all Keccak steps (theta, rho, pi, chi, iota)
- [ ] Apply all optimization passes
- [ ] Measure constraint count
- [ ] Compare against unoptimized version

**Success Metric**: 3000 → 1000 constraints (67% reduction)

### Day 20: Full SHA256 with All Optimizations
**Goal**: Implement SHA256 compression with typed API

**Tasks**:
- [ ] Implement message schedule
- [ ] Implement compression rounds
- [ ] Apply all optimization passes
- [ ] Measure constraint count

**Success Metric**: 2800 → 1200 constraints (57% reduction)

### Day 21: Performance Benchmarking
**Goal**: Validate all optimizations meet targets

**Benchmarks**:
```rust
pub fn benchmark_all_circuits() {
    benchmark("Keccak", keccak_typed, 3.0);  // Expect 3x
    benchmark("SHA256", sha256_typed, 2.0);  // Expect 2x
    benchmark("Add128", add128_typed, 4.0);  // Expect 4x
}
```

## Phase 6: Production Ready (Days 22-24)

### Day 22: Correctness Validation Suite
**Goal**: Comprehensive correctness testing

**Tests**:
- [ ] Property-based testing for each optimization
- [ ] Known test vectors for crypto functions
- [ ] Differential testing (optimized vs unoptimized)
- [ ] Edge case coverage

### Day 23: Documentation
**Goal**: Complete documentation package

**Deliverables**:
- [ ] API documentation for all types
- [ ] Optimization pass explanations
- [ ] Migration guide from untyped circuits
- [ ] Performance tuning guide

### Day 24: Final Review & Release
**Goal**: Production-ready release

**Checklist**:
- [ ] All tests passing
- [ ] Performance targets met:
  - Keccak: 67% reduction ✓
  - SHA256: 57% reduction ✓
  - Add128: 75% reduction ✓
- [ ] Zero clippy warnings
- [ ] Documentation complete
- [ ] Examples working

## Implementation Priorities

### Must Have (Week 1)
- XOR chain consolidation (Pass 1)
- Keccak chi pattern (Pass 2)
- Basic type system

### High Priority (Week 2)
- SHA rotation patterns (Pass 3)
- SHA Ch/Maj functions (Pass 4)
- Carry chain fusion (Pass 5)

### Medium Priority (Week 3)
- Conditional fusion (Pass 6)
- Full circuit integration
- Performance validation

### Nice to Have (If Time)
- Boolean simplification (Pass 7)
- Byte parallelization (Pass 8)
- Additional patterns

## Risk Mitigation

### Technical Risks
1. **Pattern conflicts**: Test passes in isolation first
2. **Correctness bugs**: Extensive property testing
3. **Performance regression**: Continuous benchmarking

### Schedule Risks  
1. **Scope creep**: Fixed pass list, no additions
2. **Integration issues**: Early integration testing
3. **Documentation debt**: Document as we go

## Success Criteria

### Quantitative
- [ ] Keccak: 3x constraint reduction
- [ ] SHA256: 2x constraint reduction
- [ ] Add128: 4x constraint reduction
- [ ] All tests passing
- [ ] Zero performance regressions

### Qualitative
- [ ] Clean, maintainable code
- [ ] Well-documented API
- [ ] Easy migration path
- [ ] Extensible design

## Daily Standup Template

```markdown
**Day N: [Phase] - [Task]**
- Completed: [What was finished]
- Blocked: [Any blockers]
- Today: [What will be done]
- Metrics: [Constraint counts, test results]
```

## Conclusion

This plan provides a methodical path to implementing Beamish, with:
- Clear daily objectives
- Measurable success metrics
- Risk mitigation strategies
- Prioritized feature development

The focus is on delivering the highest-impact optimizations first while maintaining correctness and clean design throughout.
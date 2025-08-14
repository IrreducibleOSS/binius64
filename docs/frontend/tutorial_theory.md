# Binius64 Circuit Building: Theory and Foundations

This document explains why we build circuits in zero-knowledge systems and how circuits express computations through constraints in Binius64.

## Why Circuits in Zero-Knowledge Proofs?

Zero-knowledge proofs require expressing computations as circuits rather than in programming languages like Rust.
In this tutorial, we focus on understanding circuits directly.

A circuit in this context is not quite the same as a digital circuit - we'll clarify this distinction as we go.

## Part 1: Universal Logic Gates

### What Makes a Gate Universal?

In digital logic, a **universal gate** is one that can implement any Boolean function. The most common universal gates are:

1. **NAND**: `¬(A ∧ B)` - NOT of AND
2. **NOR**: `¬(A ∨ B)` - NOT of OR

Why are these universal? Because you can build any other gate from them:
- NOT from NAND: `NAND(A, A) = ¬A`
- AND from NAND: `NAND(NAND(A, B), NAND(A, B)) = A ∧ B`
- OR from NAND: `NAND(NAND(A, A), NAND(B, B)) = A ∨ B`

### The AND-XOR Universal System

Binius64 uses a different universal system: **AND** and **XOR** gates. Here's why this is also universal:

1. **XOR acts as binary addition**: In the context of binary computation
2. **AND provides non-linearity**: Needed for multiplication
3. Together they can express any Boolean function

Proof of universality:
- NOT: `A ⊕ 1 = ¬A` (XOR with all-1)
- OR: `A ∨ B = (A ∧ B) ⊕ A ⊕ B` (De Morgan's law in GF(2))
- Any function: Can be expressed as sum of products (XOR of ANDs)

## Part 2: From Bits to 64-bit Words

### The Problem with Bit-Level Circuits

A standard ZK circuit over GF(2) would support the AND + XOR gate set at the bit level:
```
// To add two 64-bit numbers in a bit-level circuit:
// Need 64 full adders, each with ~5 gates
// Total: ~320 constraints
```

This is incredibly inefficient for common computations that work with 64-bit words, which are now standard on modern processors.

### The Binius64 Insight

Instead of decomposing everything to bits, Binius64 works directly with 64-bit words:

1. **Native word operations**: One constraint instead of 64
2. **CPU-friendly**: Maps directly to machine instructions
3. **64x efficiency gain**: For word-level operations

But how do we handle bit manipulation within words? This is where shifted value indices come in.

## Part 3: The Three Phases of Zero-Knowledge Circuits

### Why Circuits Work Differently in ZK

In traditional circuit design, you build gates that compute outputs from inputs. But zero-knowledge circuits have a fundamentally different structure because of their purpose: proving you know something without revealing what you know.

This leads to three distinct phases:

#### Phase 1: Witness Generation (The Prover's Work)
The **witness** is the complete assignment of values to all wires in the circuit. Think of it as:
- A vector containing the value at every edge in the circuit graph
- Includes public inputs, private inputs, and all intermediate values
- The prover computes all these values using regular computation

Example:
```
// Prover knows secret x=5, wants to prove x² = 25
witness = [
  x = 5,        // private input
  y = 25,       // public output  
  x_squared = 25 // internal wire
]
```

#### Phase 2: Constraint Generation (The Circuit's Structure)
The **constraint system** is a set of mathematical equations that the witness must satisfy. This defines:
- What relationships must hold between wires
- The "rules" that valid witnesses must follow
- No computation happens here - just rule definition

Example:
```
// Constraints for x² = y
constraints = [
  x * x = x_squared,     // MUL constraint
  x_squared ⊕ y = 0     // Equality check (AND constraint)
]
```

#### Phase 3: Constraint Satisfaction (The Verifier's Check)
The **verification** checks if a given witness satisfies all constraints:
- Take the witness vector
- Plug values into each constraint equation  
- Verify all equations evaluate to true

This is just checking math equations - no computation of new values.

### Why This Three-Phase Structure?

The separation exists for zero-knowledge purposes:

1. **Proving without revealing**: The prover can show they know a valid witness without revealing the witness itself
2. **Succinct verification**: The verifier only checks equations, doesn't redo computation
3. **Non-interactive proofs**: The constraint system enables creating proofs that can be verified without back-and-forth interaction

### How CircuitBuilder Bridges the Phases

The `CircuitBuilder` API cleverly handles multiple phases at once:

```rust
// This single line does two things:
let (sum, _carry_out) = builder.iadd_cin_cout(a, b, carry_in);

// 1. Defines constraints (Phase 2): "sum must equal a + b + carry_in"
// 2. Creates wire references for later witness generation (Phase 1)
```

When you later fill the witness:
```rust
w[a] = Word(10);
w[b] = Word(20);
// The circuit computes: w[sum] = Word(30)
```

The builder tracks both:
- **Structure**: What constraints exist between wires
- **Computation**: How to compute intermediate values during witness generation

### The Complete Picture

```
1. Circuit Building Time
   ├── Define wire variables (x, y, intermediate)
   └── Define constraints (x * x = y)

2. Proving Time  
   ├── Prover supplies private inputs
   ├── CircuitBuilder computes all intermediate values
   └── Complete witness vector is generated

3. Verification Time
   ├── Receive constraint system (public)
   ├── Receive proof (derived from witness)
   └── Verify all constraints are satisfied
```

This separation is why we say "circuits verify, not compute" - the actual computation happens during witness generation, while the circuit just defines what properties the computation must satisfy.

## Part 4: Shifted Value Indices - A Key Innovation

### The Challenge

Consider implementing a simple bit rotation:
```rust
// Rotate left by 13 bits
let rotated = (value << 13) | (value >> 51);
```

In a bit-level circuit, this requires:
- 64 constraints to decompose to bits
- 64 constraints to rearrange bits
- 64 constraints to recombine

In a word-level circuit without shifts, you'd need separate constraints for shifting.

### The Solution: Shifted Value Indices

Binius64's breakthrough: **encode shifts directly in value references**.

A shifted value index is a tuple: `(value_id, shift_op, shift_amount)`

Example:
- `(v0, sll, 13)` means "value 0 shifted left by 13"
- `(v1, srl, 5)` means "value 1 shifted right by 5"

### Why This Works

The insight: In constraint systems, we need to express relationships between values. By allowing shifted references, we can express bit manipulations **for free** within constraints.

Example - Rotate left by 13:
```
// Traditional: needs multiple constraints
t1 = v0 << 13
t2 = v0 >> 51
result = t1 | t2

// Binius64: single constraint
result = (v0 sll 13) XOR (v0 srl 51)
```

## Part 5: Gates vs Computations vs Constraints

### Understanding the Hierarchy

Before diving into the constraint system, let's clarify three key concepts that often cause confusion:

#### 1. Gates (Physical/Logical Level)
A **gate** is a basic logical operation:
- AND gate: outputs `a ∧ b`
- XOR gate: outputs `a ⊕ b`
- OR gate: outputs `a ∨ b`

Gates represent actual computations that happen.

#### 2. Computations (What We Want to Do)
A **computation** is the actual calculation we perform:
- `z = x + y` (addition)
- `z = x << 5` (shift)
- `z = SHA256(message)` (hash function)

Computations are built from gates but represent higher-level operations.

#### 3. Constraints (What We Verify)
A **constraint** is a mathematical relationship that must hold true:
- `x + y - z = 0` (verifies addition)
- `(x & mask) ⊕ result = 0` (verifies masking)
- `computed_hash ⊕ expected_hash = 0` (verifies hash)

In zero-knowledge proofs, circuits express relationships that must be satisfied. The prover demonstrates knowledge of inputs that satisfy these relationships, and the circuit defines what valid relationships look like. More specifically: we don't compute - we verify. The prover does the computation and provides the result. The circuit just checks it's correct.

### Example: Understanding the Difference

Let's say we want to compute `z = x + y` (mod 2^64):

**Traditional Circuit (Computing)**:
```
// 64 full adders, each doing:
sum_bit[i] = a[i] ⊕ b[i] ⊕ carry[i-1]
carry[i] = (a[i] ∧ b[i]) ∨ (carry[i-1] ∧ (a[i] ⊕ b[i]))
// Total: ~320 gates to compute the sum
```

**ZK Circuit (Verifying)**:
```
// Prover provides x, y, and z
// Circuit just checks: does x + y = z?
// In Binius64: single constraint using iadd_cin_cout
```

The prover computed `z = x + y` outside the circuit. The circuit only verifies it's correct.

## Part 6: The Constraint System

### AND Constraints

Format: `A & B ^ C = 0`

Where A, B, C are operands (XOR combinations of shifted values).

This constraint verifies: `C = A & B`

Examples:
```
// Verify: v1 contains lower 32 bits of v0
v0 & 0xFFFFFFFF ^ v1 = 0

// Verify: result is conditional selection
(condition & option1) ^ ((~condition) & option2) ^ result = 0
```

Note: We're not computing the AND - we're verifying the result equals the AND.

### MUL Constraints

Format: `A * B = (HI << 64) | LO`

This constraint verifies that `HI:LO` is the 128-bit product of `A * B`.

Again, the multiplication happens outside - we just verify it's correct.

### Free Operations (No Constraints Needed)

Some operations don't need constraints because they're just different ways of referencing data:

1. **XOR**: Just combining references
2. **Shifts**: Just accessing data differently
3. **Constants**: Known values

These are "almost free" because they require minimal verification resources compared to AND/MUL - they're primarily data manipulation operations.
These are "free" because they don't require verification - they're just data manipulation.

### Why These Two Constraint Types?

1. **AND constraints verify bitwise operations**
2. **MUL constraints verify arithmetic**
3. **Everything else is data manipulation** (free)
4. **Together they can verify any computation**

### Example: How iadd_cin_cout Works with Only AND Constraints

You might wonder: if we only have AND and MUL constraints, how does `iadd_cin_cout` (64-bit addition with carry) work? Let's build up from first principles.

#### Understanding Binary Addition

Let's add two 4-bit numbers to see the pattern:
```
  0101  (5)
+ 0011  (3)
------
  1000  (8)
```

Bit by bit:
- Bit 0: 1 + 1 = 10 (binary), so sum=0, carry=1
- Bit 1: 0 + 1 + carry(1) = 10, so sum=0, carry=1  
- Bit 2: 1 + 0 + carry(1) = 10, so sum=0, carry=1
- Bit 3: 0 + 0 + carry(1) = 01, so sum=1, carry=0

#### The Rules for Each Bit Position

For each bit position i:
```
sum[i] = a[i] ⊕ b[i] ⊕ carry_in[i]
carry_out[i] = (a[i] AND b[i]) OR ((a[i] ⊕ b[i]) AND carry_in[i])
```

The carry formula says:
- Carry when both inputs are 1: `a[i] AND b[i]`
- OR carry when exactly one is 1 AND previous carry: `(a[i] ⊕ b[i]) AND carry_in[i]`

#### The Problem: OR is Not Free

In Binius64, we only have AND constraints. XOR is free (just combining wire references), but OR is not. So how do we express the carry formula without OR?

#### The GF(2) Field Connection

In GF(2) (binary field):
- Addition is XOR: `a + b = a ⊕ b`
- Multiplication is AND: `a × b = a ∧ b`
- Note: `1 + 1 = 0` (since `1 ⊕ 1 = 0`)

In GF(2), we can rewrite Boolean operations:
```
a OR b = a ⊕ b ⊕ (a AND b)
```

Why? OR gives 1 when at least one input is 1, while XOR gives 1 when exactly one is 1. The AND term "fixes" the case when both are 1.

#### The Verification Trick: Non-deterministic Witnesses

Instead of computing carry_out, what if the prover just gives us all the carry bits? Then we only need to VERIFY they're correct.

This is a common pattern in ZK circuits called **non-deterministic witnesses** - the prover provides intermediate computation values that would be expensive to compute in-circuit, and the circuit just verifies they're correct. Other examples:
- Integer division: provide quotient and remainder, verify `a = q*b + r`
- Square root: provide the root, verify `r² = a`
- Modular inverse: provide inverse, verify `a * a⁻¹ ≡ 1 (mod p)`

For our addition case: If `cout` contains the correct carry bits at each position, then this relationship must hold:
```
(a ⊕ (cout << 1) ⊕ cin_msb) AND (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb
```

Where:
- `cout << 1` shifts carries to affect the next bit position
- `cin_msb` is the initial carry-in (from the MSB of cin wire)

This constraint captures the essence of carry propagation without computing it.

#### The Complete iadd_cin_cout Implementation

```
// Two constraints verify 64-bit addition:

// Constraint 1: Carry propagation
(a ⊕ (cout << 1) ⊕ cin_msb) & (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb

// Constraint 2: Sum verification  
(a ⊕ b ⊕ (cout << 1) ⊕ cin_msb) & all-1 = sum
```

The result:
- Prover computes `sum` and `cout` outside the circuit
- Circuit verifies they're correct with just 2 constraints
- No need for 64 full adders (320+ gates)

This is a perfect example of the verify-not-compute principle in action.

### Example: Field Multiplication and the MUL Constraint

Now let's see why we need the MUL constraint for arithmetic operations beyond simple AND.

#### The MUL Constraint Format

The MUL constraint format is:
```
A * B = (HI << 64) | LO
```

This gives us the full 128-bit product of two 64-bit integers, split into high and low words. This is standard in ZK circuits because:
- We often need the full precision for cryptographic operations (RSA, elliptic curves)
- Providing both parts allows the circuit to verify modular arithmetic correctly
- The prover can efficiently compute this outside the circuit

#### Clarification: Binary Field vs Integer Arithmetic

It's important not to confuse two different types of multiplication:

1. **Binary Field Multiplication (GF(2^n))**: Used for the underlying proof system
   - Elements are polynomials over GF(2)
   - Addition is XOR (no carries)
   - Multiplication followed by reduction with irreducible polynomial
   - This is what Binius64 uses internally for its cryptographic security

2. **Integer Multiplication (what MUL constraint does)**: Used for application-level arithmetic
   - Regular integer multiplication you learned in school
   - Produces carries, can overflow
   - This is what your circuit uses to implement algorithms

The MUL constraint performs **integer multiplication**, not field multiplication. This is what applications need for:
- RSA operations (modular exponentiation over integers)
- Elliptic curve arithmetic (coordinate calculations)
- General bignum computations

In Binius64 circuits, you're working with 64-bit values that can be interpreted as:
- Unsigned integers (0 to 2^64-1) 
- Bit patterns for bitwise operations
- Binary field elements in GF(2^64)

The interpretation depends on the operation:
- `band`, `bor`, `bxor`, shifts: Treat values as bit patterns
- `iadd_cin_cout`, `imul`: Treat values as unsigned integers
- Field operations (if needed): Would treat values as elements of GF(2^64)

Most application circuits work with integers and bit patterns. The underlying proof system uses field arithmetic, but that's hidden from the circuit writer.

#### Example: Integer Modular Reduction

Let's say we want to verify `(a * b) mod p = r` where a, b, p, r are all integers (not field elements). This is common in RSA and other cryptographic protocols.

```rust
// Circuit setup:
let a = builder.add_witness();        // Private input
let b = builder.add_witness();        // Private input  
let p = builder.add_inout();          // Public modulus
let r = builder.add_inout();          // Public result

// The prover also provides these non-deterministic witnesses:
let quotient = builder.add_witness(); // How many times p fits in a*b

// How the circuit verifies:
// Step 1: Compute a * b
let (lo1, hi1) = builder.imul(a, b);           // a * b = (hi1:lo1)

// Step 2: Compute quotient * p  
let (lo2, hi2) = builder.imul(quotient, p);    // quotient * p = (hi2:lo2)

// Step 3: Verify the equation: a * b = quotient * p + remainder
// First add quotient*p + remainder
let (sum_lo, carry) = builder.iadd_cin_cout(lo2, r, builder.add_constant(Word::ZERO));
let (sum_hi, _) = builder.iadd_cin_cout(hi2, builder.add_constant(Word::ZERO), carry);

// Step 4: Check that a*b equals quotient*p + r
builder.assert_eq("verify_lo", lo1, sum_lo);
builder.assert_eq("verify_hi", hi1, sum_hi);

// What happens at proving time:
// 1. Prover knows a, b, and computes product = a * b
// 2. Prover computes quotient = product / p and remainder = product % p  
// 3. Prover provides all values to the circuit
// 4. Circuit verifies the mathematical relationship holds
```

#### Why This Matters

Without the MUL constraint providing 128-bit output:
- We'd need to decompose to bits (128 constraints)
- Implement schoolbook multiplication (8,192 AND gates)
- Handle carry propagation explicitly

With MUL constraint:
- 2 MUL constraints for the multiplications
- 2 ADD constraints for verification
- Total: ~20 constraints instead of 8,000+

This is another example of the verify-not-compute principle: the prover does the hard work of division, the circuit just verifies the mathematical relationship holds.

## Part 7: Understanding Through Examples

### Example 1: Equality Check

To check if `a == b`:

This equality check method is a modification of the Binius64 addition constraint, described in the Binius64 writeup. The underlying addition constraint originates from work in Succinct Arguments Over Towers of Binary Fields, where a ripple-carry addition (a classical CPU/ALU design in which each bit's carry-out feeds the next bit's carry-in; see e.g. Digital Design and Computer Architecture, or Computer Organization and Design) is adapted to a non-deterministic ZK setting. The zero-detection step of adding all-1 to a ⊕ b and observing the carry is in the spirit of known CPU/ALU tricks (see Hacker's Delight for related carry/overflow tests).

The key insight:
- If `diff = a ⊕ b` is 0 (meaning a == b): Adding all-1 gives all-1 with no carry out
- If `diff ≠ 0`: Adding all-1 wraps around and produces a carry out

Implementation:
1. Compute `diff = x ⊕ y` (0 if equal, non-zero if different)
2. Add all-1 to diff and track carry propagation using constraint:
   `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout` where `cin = cout << 1`
3. Check MSB of carry out: 0 means equal, 1 means not equal
4. Broadcast result: `out_mask = ¬(cout >> 63)` using arithmetic shift

This uses just 2 AND constraints instead of ~64 gates for bit-level comparison.

### Example 2: Bit Extraction

Extract bit N from value V:

In traditional circuits, you'd decompose the entire value to bits (64 constraints) to access one bit.

In Binius64:
```rust
// Using CircuitBuilder API:
let shifted = builder.shr(V, N);           // Shift right by N (free - shifted index)
let bit_n = builder.band(shifted, one);    // AND with 1 (one AND constraint)

// Or more directly:
let bit_n = builder.extract_bit(V, N);    // Convenience method
```

This is just ONE AND constraint because the shift is encoded in the shifted value index `(V, shr, N)` and doesn't need a separate constraint.

### Example 3: SHA-256 Sigma Function

SHA-256's σ₀ function: `ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22)`

```
// Bit-level: ~192 constraints (3 rotations × 64 bits)

// Binius64: Just XOR shifted values (free)
s0 = (x srl 2) XOR (x sll 62) XOR 
     (x srl 13) XOR (x sll 51) XOR
     (x srl 22) XOR (x sll 42)
```


# Building

Tutorial on the building of ZK applications using Binius64.

## Foundations

In this section, we explain why we build circuits in ZK systems, how circuits express computations, and how constraints come into play.

### Circuit Requirements in Zero-Knowledge Systems

Applications built for ZK proving must express computations as circuits rather than as imperative code in languages like Rust. This tutorial focuses on understanding these ZK circuits, without going into the theory of why they are needed for ZK. A circuit in this context is not quite the same as a digital circuit - this distinction will be clarified throughout.

### Part 1: Universal Logic Gates

#### Universal Gate Definition

In digital logic, a **universal gate** is one that can implement any Boolean function. Since any computable function can be expressed as Boolean logic operations, a universal gate set gives us Turing completeness—the ability to compute anything that is computationally possible, just as a Turing machine can.

The most common universal gates are:

1. **NAND**: `¬(A ∧ B)` - NOT of AND
2. **NOR**: `¬(A ∨ B)` - NOT of OR

Why are these universal? Because you can build any other gate from them:
- NOT from NAND: `NAND(A, A) = ¬A`
- AND from NAND: `NAND(NAND(A, B), NAND(A, B)) = A ∧ B`
- OR from NAND: `NAND(NAND(A, A), NAND(B, B)) = A ∨ B`

#### The AND-XOR Universal System

Binius64 uses a different universal system: **AND** and **XOR** gates in GF(2). GF(2) is a low-level mathematical type (a field) used internally by the proof system—the details aren't essential for building circuits.

Proof of universality:
- NOT: `A ⊕ 1 = ¬A` (XOR with all-1)
- OR: `A ∨ B = (A ∧ B) ⊕ A ⊕ B` (De Morgan's law in GF(2))
- Any function: Can be expressed as sum of products (XOR of ANDs)

### Part 2: From Bits to 64-bit Words

#### Efficiency of Bit-Level Circuits

Typical ZK frameworks support the AND + XOR gate set at the bit level:
```
// To add two 64-bit numbers in a bit-level circuit:
// Need 64 full adders, each with ~5 gates
// Total: ~320 constraints
```

This is inefficient for common computations that work with 64-bit words, which are now standard on modern processors.

#### The Binius64 Insight

Instead of decomposing everything to bits, Binius64 works directly with 64-bit words:

1. **Native word operations**: One constraint instead of 64
2. **CPU-friendly**: Maps directly to machine instructions
3. **64x efficiency gain**: For some of the operations

This word-level approach delivers efficiency gains, but real-world circuits need bit manipulations too. Shifted value indices (see below) bridge this gap.

### Part 3: The Three Phases of Zero-Knowledge Circuits

#### Zero-Knowledge Circuit Structure

In traditional circuit design, gates compute outputs from inputs. Zero-knowledge circuits have a fundamentally different structure because of their purpose: proving knowledge of something without revealing what is known. For ZK-SNARKs such as Binius64, the problem needs to be transformed into a circuit satisfiability (SAT) problem.

This leads to three distinct phases:

##### Phase 1: Constraint Generation (The Circuit's Structure)
The **constraint system** is a set of mathematical equations that define what constitutes a valid computation. These equations will later be checked against actual values (the witness).\This phase defines:
- What relationships must hold between wires (the individual values in the witness)
- The "rules" that valid witnesses must follow
- No computation happens here - only rule definition

Example:
```
// Constraints for x² = y
constraints = [
  x * x = x_squared,     // MUL constraint
  x_squared - y = 0,     // Equality constraint: x_squared must equal y
]
```

##### Phase 2: Witness Generation (The Prover's Work)
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

##### Phase 3: Constraint Satisfaction (The Verifier's Check)
The **verification** checks if a given witness satisfies all constraints:
- Take the witness vector
- Plug values into each constraint equation
- Verify all equations evaluate to true

This is checking math equations - no computation of new values.

#### Gates vs Computations vs Constraints

Three key concepts require clarification:

##### 1. Gates (Physical/Logical Level)
A **gate** is a basic logical operation:
- AND gate: outputs `a ∧ b`
- XOR gate: outputs `a ⊕ b`
- OR gate: outputs `a ∨ b`

Gates represent actual computations that happen.

##### 2. Computations (What We Want to Do)
A **computation** is the actual calculation we perform:
- `z = x + y` (addition)
- `z = x << 5` (shift)
- `z = SHA256(message)` (hash function)

Computations are built from gates but represent higher-level operations.

##### 3. Constraints (What We Verify)
A **constraint** is a mathematical relationship that must hold true:
- `x + y - z = 0` (verifies addition)
- `(x & mask) ⊕ result = 0` (verifies masking)
- `computed_hash ⊕ expected_hash = 0` (verifies hash)

In zero-knowledge proofs, circuits express relationships that must be satisfied through constraints. The CircuitBuilder API translates your circuit operations into these constraints. The prover generates a witness (all wire values) that satisfies these constraints, while the verifier checks the proof without seeing private witness values.

#### Intuition for The Complete Picture

```
1. Development (User writes code)
   └── Express algorithm as circuit using CircuitBuilder API

2. Circuit Building (Compile Time)
   ├── Define wire variables (x, y, intermediate)
   ├── Define constraints (x * x = y)
   └── Output: Constraint system

3. Proving (Runtime)
   ├── Prover supplies all inputs (public and private)
   ├── Prover computes all intermediate values
   ├── Complete witness vector is generated
   └── Create proof from witness (using cryptographic protocol)

4. Verification (Runtime)
   ├── Receive constraint system (public)
   ├── Receive public inputs and proof
   └── Verify proof is valid (without seeing private witness values)
```

### Part 4: Constraint Forms in Binius64

The formal structure of constraints in Binius64 must be understood before examining shifts.

#### The Two Constraint Types

Binius64 has exactly two types of constraints:

**AND Constraint:**
```
(A₀ ⊕ A₁ ⊕ ... ⊕ Aₙ) ∧ (B₀ ⊕ B₁ ⊕ ... ⊕ Bₘ) = C₀ ⊕ C₁ ⊕ ... ⊕ Cₖ
```

**MUL Constraint:**
```
(A₀ ⊕ A₁ ⊕ ... ⊕ Aₙ) × (B₀ ⊕ B₁ ⊕ ... ⊕ Bₘ) =
    (HI₀ ⊕ HI₁ ⊕ ... ⊕ HIₚ) · 2⁶⁴ + (LO₀ ⊕ LO₁ ⊕ ... ⊕ LOᵧ)
```

Where each term (A₀, B₀, etc.) can be:
- A wire reference: `vᵢ` (value at index i in the witness vector)
- A constant: any 64-bit value

Each operand is a XOR combination of these terms. Since XOR is addition in GF(2⁶⁴), these combinations are "free"—they don't require additional constraints. This flexibility becomes even more powerful when terms are extended to include shifted values.

### Part 5: Understanding Shifted Value Indices

#### Constraint System Extension for Shifts

Consider implementing a bit rotation:
```rust
// Rotate left by 13 bits
let rotated = (value << 13) | (value >> 51);
```

In a bit-level circuit (the traditional approach we mentioned), this rotation requires:
- 64 constraints to decompose the word to bits
- 64 constraints to rearrange the bits
- 64 constraints to recombine into a word

With the 64-bit word approach from Part 2, separate constraints would still be needed to express the shifts themselves.

#### Shifted Value Indices

Binius64 extends the constraint terms from Part 4 by encoding shifts directly into value references.

Each term in a constraint could be a wire reference (`vᵢ`) or a constant. This is now extended: a term can also be a **shifted value index** - a tuple `(value_id, shift_op, shift_amount)`.

Examples:
- `(v0, sll, 13)` means "value 0 shifted left by 13"
- `(v1, srl, 5)` means "value 1 shifted right by 5"

This means our constraint operands can now freely mix regular and shifted references:
```
(v0, sll, 13) ⊕ (v0, srl, 51) ⊕ v1 ⊕ 0xFF
```
All within a single operand, still "free" with no additional constraints.

#### Mechanism

In constraint systems, relationships between values must be expressed. By allowing shifted references, bit manipulations can be expressed **for free** within constraints.

Example - Rotate left by 13:
```
// Traditional: needs multiple constraints
t1 = v0 << 13
t2 = v0 >> 51
result = t1 | t2

// Binius64: single constraint
result = (v0 sll 13) XOR (v0 srl 51)
```

### Part 6: Control Flow in Circuits

#### Circuit Control Flow Constraints

Unlike imperative programming, circuits have no runtime control flow. All paths execute, all loops unroll at compile time, and all allocations are statically bounded. This fundamental constraint shapes how algorithms are expressed in circuits.

Where traditional code uses `if`, `for`, and dynamic arrays, circuits use:
- **Masking** instead of branching
- **Unrolling** instead of loops
- **Fixed allocation with length tracking** instead of dynamic arrays
- **Selection/multiplexing** instead of conditionals and array indexing

#### Conditional Logic via Selection

Circuits compute all branches and select the result. The `select` operation (1 AND constraint) replaces if-else:

```rust
// Traditional: only one branch executes
let result = if condition { compute_a() } else { compute_b() };

// Circuit: both execute, result selected
let result_a = compute_a(builder);
let result_b = compute_b(builder);
let result = builder.select(result_a, result_b, condition);
```

The `select` operation uses a single AND constraint: `out = a ⊕ ((cond >> 63) ∧ (b ⊕ a))`

#### Array Indexing as Multiplexing

Dynamic array indexing `array[index]` is a special case of conditional selection - choosing one element from many based on an index. This requires a multiplexer tree.

The frontend provides multiplexer circuits in `circuits/multiplexer.rs`:

```rust
use binius_frontend::circuits::multiplexer::single_wire_multiplex;

// Select one wire from an array based on index
let selected = single_wire_multiplex(&builder, &array_of_wires, index);

// For selecting groups of wires (e.g., structs)
use binius_frontend::circuits::multiplexer::multi_wire_multiplex;
let selected_group = multi_wire_multiplex(&builder, &groups, selector);
```

Implementation for a 4-element array uses a binary decision tree with 3 select operations:

```
                    selector bits
                   bit1    bit0
                    ╱        ╲
                  0/          \1
                 ╱              ╲
           [0,1]                [2,3]
          ╱    ╲               ╱    ╲
        0/      \1           0/      \1
    arr[0]    arr[1]     arr[2]    arr[3]
```

The multiplexer builds an optimal binary tree, processing level by level:
- Each level uses one bit from the selector
- For N inputs, requires ceil(log2(N)) levels
- Total cost: N-1 select operations (AND constraints)

#### Loop Unrolling with Conditional Masking

Loops with early exit conditions require unrolling with masking to handle the conditional logic:

```rust
// Traditional: early exit with break
fn sum_until_zero(data: &[u64]) -> u64 {
    let mut sum = 0;
    for &val in data {
        if val == 0 { break; }
        sum += val;
    }
    sum
}

// Circuit: fully unrolled with masking
fn sum_until_zero_circuit(builder: &CircuitBuilder, data: &[Wire; MAX_LEN]) -> Wire {
    let mut sum = builder.add_constant(Word::ZERO);
    let mut found_zero = builder.add_constant(Word::ZERO);

    for i in 0..MAX_LEN {
        // Check if current element is zero
        let is_zero = builder.icmp_eq(data[i], builder.add_constant(Word::ZERO));

        // Update found_zero flag (sticky - once set, stays set)
        found_zero = builder.bor(found_zero, is_zero);

        // Mask the addition: only add if haven't found zero
        let mask = builder.bnot(found_zero);
        let masked_val = builder.band(data[i], mask);
        let (sum_new, _) = builder.iadd_cin_cout(sum, masked_val, builder.add_constant(Word::ZERO));
        sum = sum_new;
    }

    sum
}
```

Properties:
- Loop always runs MAX_LEN iterations
- Conditional becomes masking (multiply by 0 or all-1)
- State tracking with sticky flags

#### Variable-Length Data Patterns

Variable-length data requires fixed allocation with length tracking and masking:

```rust
const MAX_ARRAY_SIZE: usize = 1000;

struct VariableLengthArray {
    values: [Wire; MAX_ARRAY_SIZE],  // Allocate maximum
    length: Wire,                    // Actual length
}

impl VariableLengthArray {
    fn sum(&self, builder: &CircuitBuilder) -> Wire {
        let mut sum = builder.add_constant(Word::ZERO);
        let mut carry = builder.add_constant(Word::ZERO);

        for i in 0..MAX_ARRAY_SIZE {
            // Check if index is within actual bounds
            let is_active = builder.icmp_ult(
                builder.add_constant(Word(i as u64)),
                self.length
            );

            // is_active is already a mask (all-0s or all-1s)
            // Mask the value for this position
            let masked_value = builder.band(self.values[i], is_active);

            // Add to running sum with carry
            let (new_sum, new_carry) = builder.iadd_cin_cout(sum, masked_value, carry);
            sum = new_sum;
            carry = new_carry;
        }

        sum
    }
}
```

Wire allocation impact for MAX_ARRAY_SIZE = 1000:
- 1000 wires for array values
- 1 wire for length
- 1000+ intermediate wires for comparisons and masks
- Total: ~3000+ wires regardless of actual array size

### Part 7: Circuit Composition

**TODO**

- Managing witness data flow between circuits
- Best practices for modular circuit design

## Part 8: Building Your First Circuits

This section provides practical examples using the CircuitBuilder API. Prerequisites: Understanding of wire types, constraints, and the witness generation process from previous sections.

### Wire Types Quick Reference

```rust
// Public input/output wires
let input = builder.add_inout();

// Private witness wires (zero-knowledge)
let secret = builder.add_witness();

// Constant values
let zero = builder.add_constant(Word::ZERO);
let one = builder.add_constant(Word::ONE);
let all_ones = builder.add_constant(Word::ALL_ONE);
let value = builder.add_constant_64(0x1234567890ABCDEF);

// Internal computation wires
let temp = builder.add_internal();
```

### Example 1: Simple Equality Check Circuit

```rust
use binius_frontend::circuit::Circuit;
use binius_frontend::compiler::CircuitBuilder;
use binius_core::word::Word;
use binius_frontend::wire::Wire;

fn build_equality_circuit() -> (Circuit, Wire, Wire, Wire) {
    // Create a new circuit builder
    let builder = CircuitBuilder::new();

    // Add two public inputs
    let a = builder.add_inout();
    let b = builder.add_inout();

    // Add output wire for result
    let result = builder.add_inout();

    // Check if a == b (returns all-1 if equal, all-0 if not)
    let eq_mask = builder.icmp_eq(a, b);

    // Assert that our result matches the equality check
    builder.assert_eq("check_result", eq_mask, result);

    // Build the circuit and return wire references
    let circuit = builder.build();
    (circuit, a, b, result)
}

// Using the circuit for proving
fn prove_equality() {
    let (circuit, a_wire, b_wire, result_wire) = build_equality_circuit();

    // Create witness filler
    let mut w = circuit.new_witness_filler();

    // Set input values using the wire references
    w[a_wire] = Word(42);
    w[b_wire] = Word(42);
    w[result_wire] = Word(u64::MAX); // all-1 means equal

    // Populate internal wires (fills non-deterministic values)
    circuit.populate_wire_witness(&mut w).unwrap();

    // Witness is ready for proof generation
}
```

### Example 2: Zero-Knowledge Hash Preimage

This example demonstrates private witnesses - proving knowledge of a preimage without revealing it:

```rust
fn build_hash_preimage_circuit() -> (Circuit, Wire, Wire) {
    let builder = CircuitBuilder::new();

    // Public input: the hash to check against
    let expected_hash = builder.add_inout();

    // Private witness: the secret preimage
    let preimage = builder.add_witness();

    // Simple hash function (demonstration only - not cryptographically secure)
    // Real circuits would use SHA256 or similar
    let rotated = builder.rotl64(preimage, 13);
    let mixed = builder.bxor(rotated, builder.add_constant_64(0x1234567890ABCDEF));
    let hash = builder.bxor(mixed, builder.shr(preimage, 7));

    // Assert the computed hash matches expected
    builder.assert_eq("verify_hash", hash, expected_hash);

    let circuit = builder.build();
    (circuit, expected_hash, preimage)
}

// Proving knowledge of preimage
fn prove_preimage_knowledge() {
    let (circuit, expected_hash_wire, preimage_wire) = build_hash_preimage_circuit();
    let mut w = circuit.new_witness_filler();

    // Secret preimage (only prover knows this)
    let secret = Word(0xDEADBEEFCAFEBABE);
    w[preimage_wire] = secret;

    // Compute the hash (same logic as in circuit)
    let rotated = secret.rotl(13);
    let mixed = rotated ^ Word(0x1234567890ABCDEF);
    let hash = mixed ^ secret.shr(7);

    // Public hash value
    w[expected_hash_wire] = hash;

    circuit.populate_wire_witness(&mut w).unwrap();

    // Generate proof - proves knowledge of preimage without revealing it
}
```

### Common Operations Reference

| Operation | Method | Returns | Notes |
|-----------|--------|---------|-------|
| Equality | `icmp_eq(a, b)` | all-1 if equal, all-0 if not | 2 AND constraints |
| Less than (unsigned) | `icmp_ult(a, b)` | all-1 if a < b, all-0 if not | 2 AND constraints |
| Addition with carry | `iadd_cin_cout(a, b, cin)` | (sum, cout) | 2 AND constraints |
| Addition (32-bit) | `iadd_32(a, b)` | sum | 32-bit addition |
| Subtraction with borrow | `isub_bin_bout(a, b, bin)` | (diff, bout) | With borrow in/out |
| Multiplication | `imul(a, b)` | (hi, lo) | 1 MUL constraint (~200x cost) |
| Bitwise AND | `band(a, b)` | a & b | 1 AND constraint |
| Bitwise OR | `bor(a, b)` | a \| b | 1 AND constraint |
| Bitwise XOR | `bxor(a, b)` | a ^ b | Free (no constraints) |
| Shift left | `shl(a, n)` | a << n | n must be 0-63, 1 AND constraint |
| Shift right | `shr(a, n)` | a >> n | Logical, n must be 0-63, 1 AND constraint |
| Rotate left | `rotl(a, n)` | rotate_left(a, n) | n must be 0-63 |
| Rotate right | `rotr(a, n)` | rotate_right(a, n) | n must be 0-63 |

### Proving and Verifying: The Complete Flow

After building your circuit, you need to generate and verify proofs. Here's the complete process:

```rust
use binius_prover::{OptimalPackedB128, Prover};
use binius_verifier::{Verifier, config::StdChallenger, hash::{StdCompression, StdDigest}};
use binius_verifier::transcript::ProverTranscript;

// Step 1: Build your circuit
let builder = CircuitBuilder::new();
// ... add wires and constraints ...
let circuit = builder.build();

// Step 2: Set up the constraint system
let cs = circuit.constraint_system().clone();
let log_inv_rate = 1; // Security parameter (typically 1-2)

// Step 3: Create verifier and prover
let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, StdCompression::default())?;
let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone())?;

// Step 4: Generate witness
let mut filler = circuit.new_witness_filler();
// Set your input values
filler[input_wire] = Word(42);
// Populate internal wires (non-deterministic computation)
circuit.populate_wire_witness(&mut filler)?;
let witness = filler.into_value_vec();

// Step 5: Generate proof
let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
prover.prove(witness.clone(), &mut prover_transcript)?;

// Step 6: Verify proof
let mut verifier_transcript = prover_transcript.into_verifier();
verifier.verify(witness.public(), &mut verifier_transcript)?;
verifier_transcript.finalize()?;
```

Key concepts:
- **Constraint System**: The compiled representation of your circuit
- **log_inv_rate**: Security parameter controlling proof size/verification time tradeoff
- **Witness**: Complete assignment of values to all wires (public and private)
- **Transcript**: Fiat-Shamir transformation for non-interactive proofs

### Testing Circuits Without Full Proving

For development and testing, you can verify constraint satisfaction without generating proofs:

```rust
#[test]
fn test_my_circuit() {
    let builder = CircuitBuilder::new();
    let a = builder.add_inout();
    let b = builder.add_inout();
    let result = builder.icmp_eq(a, b);

    let circuit = builder.build();
    let mut w = circuit.new_witness_filler();

    // Test specific values
    w[a] = Word(42);
    w[b] = Word(42);

    // This will fail if constraints are violated
    circuit.populate_wire_witness(&mut w).unwrap();

    // Verify the result
    assert_eq!(w[result], Word(u64::MAX)); // all-1 for equal
}
```

### Practical Tips

- Test circuits with edge cases (0, u64::MAX values)
- Use descriptive names in `assert_eq` for debugging
- Remember: comparisons return all-1 or all-0, not 1 or 0
- `populate_wire_witness` must be called to fill non-deterministic values
- For testing, `populate_wire_witness` failing indicates constraint violations
- **TODO**: update after Ben's refactor (bool)

### Exercise: Build Your Own Circuit

Try building a circuit that:
1. Takes two private inputs `x` and `y`
2. Computes `z = (x + y) ^ (x - y)`
3. Outputs only `z` as public

This combines arithmetic and bitwise operations while keeping inputs private.

### Part 9: Appendix

## Integer vs Binary Field Arithmetic: Understanding the MUL Constraint

The MUL constraint is necessary for arithmetic operations beyond simple AND.

### The MUL Constraint Format

The MUL constraint format is:
```
A * B = (HI << 64) | LO
```

This gives us the full 128-bit product of two 64-bit integers, split into high and low words. This is standard in ZK circuits because:
- We often need the full precision for cryptographic operations (RSA, elliptic curves)
- Providing both parts allows the circuit to verify modular arithmetic correctly
- The prover can efficiently compute this outside the circuit

### Clarification: Binary Field vs Integer Arithmetic

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

## Non-deterministic Witnesses

A common pattern in ZK circuits is using **non-deterministic witnesses** - the prover provides intermediate computation values that would be expensive to compute in-circuit, and the circuit verifies they're correct.

### Common Applications

This pattern appears throughout circuit design:
- **Integer division**: Provide quotient and remainder, verify `a = q*b + r`
- **Square root**: Provide the root, verify `r² = a`
- **Modular inverse**: Provide inverse, verify `a * a⁻¹ ≡ 1 (mod p)`
- **Addition with carry**: Provide carry bits, verify carry propagation (as shown in the next section)

### Detailed Example: Integer Modular Reduction

To verify `(a * b) mod p = r` where a, b, p, r are all integers (common in RSA and other cryptographic protocols):

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

// Step 3: Verify the equation: a * b = quotient * p + r
// First add quotient*p + r
let (sum_lo, carry) = builder.iadd_cin_cout(lo2, r, builder.add_constant(Word::ZERO));
let (sum_hi, _) = builder.iadd_cin_cout(hi2, builder.add_constant(Word::ZERO), carry);

// Step 4: Check that a*b equals quotient*p + r
builder.assert_eq("verify_lo", lo1, sum_lo);
builder.assert_eq("verify_hi", hi1, sum_hi);

// What happens at proving time:
// 1. Prover knows a, b, and computes product = a * b
// 2. Prover computes quotient = product / p and r = product % p
// 3. Prover provides all values to the circuit
// 4. Circuit verifies the mathematical relationship holds
```

### Performance Impact

Without non-deterministic witnesses and the MUL constraint:
- We'd need to decompose to bits (128 constraints)
- Implement schoolbook multiplication (8,192 AND gates)
- Implement division algorithm (thousands more constraints)
- Handle carry propagation explicitly

With non-deterministic witnesses:
- 2 MUL constraints for the multiplications
- 2 ADD constraints for verification
- Total: ~20 constraints instead of 10,000+

The prover performs division outside the circuit, and the circuit verifies the mathematical relationship holds.

## Implementation: iadd_cin_cout

With only AND and MUL constraints, `iadd_cin_cout` (64-bit addition with carry) is implemented using the following approach.

### Binary Addition Fundamentals

Consider adding two 4-bit numbers to illustrate the pattern:
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

### The Rules for Each Bit Position

For each bit position i:
```
sum[i] = a[i] ⊕ b[i] ⊕ carry_in[i]
carry_out[i] = (a[i] AND b[i]) OR ((a[i] ⊕ b[i]) AND carry_in[i])
```

The carry formula says:
- Carry when both inputs are 1: `a[i] AND b[i]`
- OR carry when exactly one is 1 AND previous carry: `(a[i] ⊕ b[i]) AND carry_in[i]`

### The Problem: OR is Not Free

In Binius64, only AND constraints are available. XOR is free (combining wire references), while OR is not. The carry formula must be expressed without OR.

### The GF(2) Field Connection

In GF(2) (binary field):
- Addition is XOR: `a + b = a ⊕ b`
- Multiplication is AND: `a × b = a ∧ b`
- Note: `1 + 1 = 0` (since `1 ⊕ 1 = 0`)

In GF(2), we can rewrite Boolean operations:
```
a OR b = a ⊕ b ⊕ (a AND b)
```

This works because OR gives 1 when at least one input is 1, while XOR gives 1 when exactly one is 1. The AND term corrects for the case when both are 1.

### Using Non-deterministic Witnesses for Carry Bits

Instead of computing carry_out, the prover provides all the carry bits as witness values. Then we only need to verify they're correct.

For our addition case: If `cout` contains the correct carry bits at each position, then this relationship must hold:
```
(a ⊕ (cout << 1) ⊕ cin_msb) AND (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb
```

Where:
- `cout << 1` shifts carries to affect the next bit position
- `cin_msb` is the initial carry-in (from the MSB of cin wire)

This constraint captures the essence of carry propagation without computing it.

### The Complete iadd_cin_cout Implementation

```
// Two constraints verify 64-bit addition:

// Constraint 1: Carry propagation
(a ⊕ (cout << 1) ⊕ cin_msb) & (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb

// Constraint 2: Sum verification
(a ⊕ b ⊕ (cout << 1) ⊕ cin_msb) & all-1 = sum
```

The result:
- Prover computes `sum` and `cout` outside the circuit
- Circuit verifies they're correct with only 2 constraints
- No need for 64 full adders (320+ gates)

## Practical Examples

### Example 1: Equality Check

To check if `a == b`:

This equality check method is a modification of the Binius64 addition constraint, described in the Binius64 writeup. The underlying addition constraint originates from work in Succinct Arguments Over Towers of Binary Fields, where a ripple-carry addition (a classical CPU/ALU design in which each bit's carry-out feeds the next bit's carry-in; see e.g. Digital Design and Computer Architecture, or Computer Organization and Design) is adapted to a non-deterministic ZK setting. The zero-detection step of adding all-1 to a ⊕ b and observing the carry is in the spirit of known CPU/ALU tricks (see Hacker's Delight for related carry/overflow tests).

The principle:
- If `diff = a ⊕ b` is 0 (meaning a == b): Adding all-1 gives all-1 with no carry out
- If `diff ≠ 0`: Adding all-1 wraps around and produces a carry out

Implementation:
1. Compute `diff = x ⊕ y` (0 if equal, non-zero if different)
2. Add all-1 to diff and track carry propagation using constraint:
   `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout` where `cin = cout << 1`
3. Check MSB of carry out: 0 means equal, 1 means not equal
4. Broadcast result: `out_mask = ¬(cout >> 63)` using arithmetic shift

This uses only 2 AND constraints instead of ~64 gates for bit-level comparison.

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

This requires only ONE AND constraint because the shift is encoded in the shifted value index `(V, shr, N)` and doesn't need a separate constraint.

### Example 3: SHA-256 Sigma Function

SHA-256's σ₀ function: `ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22)`

```
// Bit-level: ~192 constraints (3 rotations × 64 bits)

// Binius64: XOR shifted values (free)
s0 = (x srl 2) XOR (x sll 62) XOR
     (x srl 13) XOR (x sll 51) XOR
     (x srl 22) XOR (x sll 42)
```

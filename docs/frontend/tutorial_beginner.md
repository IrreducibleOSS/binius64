# Binius64 Circuit Writing Tutorial: Beginner Level

This tutorial teaches you how to write circuits using the Binius64 builder API through practical examples.

**Prerequisites**: Read the [theory tutorial](tutorial_theory.md) first to understand why we use circuits and how constraints work.

## Quick Reference

**Wire Types:**
- `add_inout()`: Public input/output wires
- `add_witness()`: Private witness wires  
- `add_constant_64(value)`: Constant values
- `add_internal()`: Internal computation wires

## Example 1: Simple Equality Check

Let's start with a basic circuit that checks if two numbers are equal:

```rust
use binius_frontend::compiler::CircuitBuilder;
use binius_core::word::Word;

fn build_equality_circuit() -> (Circuit, Wire, Wire, Wire) {
    // Create a new circuit builder
    let builder = CircuitBuilder::new();
    
    // Add two public inputs
    let a = builder.add_inout();
    let b = builder.add_inout();
    
    // Add output wire for result
    let result = builder.add_inout();
    
    // Check if a == b
    let eq_mask = builder.icmp_eq(a, b);
    
    // Assert that our result matches the equality check
    builder.assert_eq("check_result", eq_mask, result);
    
    // Build the circuit and return wire references
    let circuit = builder.build();
    (circuit, a, b, result)
}

// Using the circuit
fn prove_equality() {
    let (circuit, a_wire, b_wire, result_wire) = build_equality_circuit();
    
    // Create witness filler
    let mut w = circuit.new_witness_filler();
    
    // Set input values using the wire references
    w[a_wire] = Word(42);
    w[b_wire] = Word(42);
    w[result_wire] = Word(u64::MAX); // all-1 means equal
    
    // Populate internal wires
    circuit.populate_wire_witness(&mut w).unwrap();
    
    // Now you can generate a proof with this witness
}
```

Note: `icmp_eq` returns all-1 if equal, all-0 if not equal.

## Example 2: Comparison Circuit

Let's build a circuit that checks if one number is less than another:

```rust
fn build_comparison_circuit() -> (Circuit, Wire, Wire, Wire) {
    let builder = CircuitBuilder::new();
    
    // Three inputs: a, b, and expected result
    let a = builder.add_inout();
    let b = builder.add_inout();
    let expected = builder.add_inout();
    
    // Check if a < b (unsigned comparison)
    let lt_result = builder.icmp_ult(a, b);
    
    // Assert the result matches expected
    builder.assert_eq("verify_comparison", lt_result, expected);
    
    let circuit = builder.build();
    (circuit, a, b, expected)
}

#[test]
fn test_comparison() {
    let (circuit, a, b, expected) = build_comparison_circuit();
    let mut w = circuit.new_witness_filler();
    
    // Test case: 10 < 20 should be true
    w[a] = Word(10);
    w[b] = Word(20);
    w[expected] = Word(u64::MAX); // all-1 means true
    
    circuit.populate_wire_witness(&mut w).unwrap();
}
```

## Example 3: Basic Arithmetic

Now let's create a circuit that performs addition with carry:

```rust
fn build_addition_circuit() -> (Circuit, Wire, Wire, Wire, Wire) {
    let builder = CircuitBuilder::new();
    
    // Inputs
    let a = builder.add_inout();
    let b = builder.add_inout();
    
    // Outputs
    let sum = builder.add_inout();
    let carry = builder.add_inout();
    
    // Perform addition with carry
    let (computed_sum, computed_carry) = builder.iadd_cin_cout(
        a, 
        b, 
        builder.add_constant(Word::ZERO) // No carry in
    );
    
    // Assert outputs match
    builder.assert_eq("check_sum", computed_sum, sum);
    builder.assert_eq("check_carry", computed_carry, carry);
    
    let circuit = builder.build();
    (circuit, a, b, sum, carry)
}

#[test]
fn test_addition_overflow() {
    let (circuit, a, b, sum, carry) = build_addition_circuit();
    let mut w = circuit.new_witness_filler();
    
    // Test overflow: MAX + MAX
    w[a] = Word(u64::MAX);
    w[b] = Word(u64::MAX);
    w[sum] = Word(u64::MAX - 1); // 0xFFFFFFFFFFFFFFFE
    w[carry] = Word(u64::MAX);   // Carry is all-1
    
    circuit.populate_wire_witness(&mut w).unwrap();
}
```

## Example 4: Bitwise Operations

Binius64 excels at bitwise operations. Here's how to use them:

```rust
fn build_bitwise_circuit() -> Circuit {
    let builder = CircuitBuilder::new();
    
    let a = builder.add_inout();
    let b = builder.add_inout();
    
    // Bitwise AND
    let and_result = builder.band(a, b);
    
    // Bitwise OR
    let or_result = builder.bor(a, b);
    
    // Bitwise XOR
    let xor_result = builder.bxor(a, b);
    
    // Shift operations
    let shl_result = builder.shl(a, 5);  // Shift left by 5
    let shr_result = builder.shr(a, 3);  // Logical shift right by 3
    
    // Rotation
    let rotl_result = builder.rotl64(a, 16); // Rotate left by 16
    
    // Add output wires to verify
    let expected_and = builder.add_inout();
    let expected_or = builder.add_inout();
    let expected_xor = builder.add_inout();
    
    builder.assert_eq("check_and", and_result, expected_and);
    builder.assert_eq("check_or", or_result, expected_or);
    builder.assert_eq("check_xor", xor_result, expected_xor);
    
    builder.build()
}
```

## Example 5: Using Private Witnesses

So far we've used public inputs (`add_inout`). Here's how to use private witnesses:

```rust
fn build_hash_preimage_circuit() -> (Circuit, Wire, Wire) {
    let builder = CircuitBuilder::new();
    
    // Public input: the hash we're checking against
    let expected_hash = builder.add_inout();
    
    // Private witness: the secret preimage
    let preimage = builder.add_witness();
    
    // Simulate a simple "hash" (just for example - not cryptographically secure!)
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
    
    // Compute the "hash" (same logic as in circuit)
    let rotated = secret.rotl(13);
    let mixed = rotated ^ Word(0x1234567890ABCDEF);
    let hash = mixed ^ secret.shr(7);
    
    // Public hash value
    w[expected_hash_wire] = hash;
    
    circuit.populate_wire_witness(&mut w).unwrap();
    
    // Generate proof - this proves we know a preimage without revealing it!
}
```

## Tips

- Test circuits with various inputs including edge cases (0, MAX values)
- Use descriptive names in `assert_eq` for easier debugging
- Remember: comparisons return all-1 or all-0, not 1 or 0

## Common Operations Reference

| Operation | Method | Returns | Notes |
|-----------|--------|---------|-------|
| Equality | `icmp_eq(a, b)` | all-1 if equal, all-0 if not | 64-bit comparison |
| Less than | `icmp_ult(a, b)` | all-1 if a < b, all-0 if not | Unsigned comparison |
| Addition | `iadd_cin_cout(a, b, cin)` | (sum, cout) | With carry in/out |
| Bitwise AND | `band(a, b)` | a & b | Direct bitwise operation |
| Bitwise OR | `bor(a, b)` | a \| b | Direct bitwise operation |
| Bitwise XOR | `bxor(a, b)` | a ^ b | Direct bitwise operation |
| Shift left | `shl(a, n)` | a << n | n must be 0-63 |
| Shift right | `shr(a, n)` | a >> n | Logical (fills with 0) |
| Rotate left | `rotl64(a, n)` | rotate_left(a, n) | 64-bit rotation |

## Exercise: Build Your Own Circuit

Try building a circuit that:
1. Takes two private inputs `x` and `y`
2. Computes `z = (x + y) ^ (x - y)`
3. Outputs only `z` as public

This combines arithmetic and bitwise operations while keeping inputs private!


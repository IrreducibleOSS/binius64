# Circuit Control Flow: From Software to Constraints

This document describes techniques for translating control flow patterns from traditional programming into zero-knowledge circuits in Binius64. The code snippets are for meant for conceptual understanding, they are simplified and are not guaranteed to compile. 

## Introduction

Circuits differ from traditional programming in their control flow capabilities:

1. **No runtime branching**: Every path must be computed
2. **Fixed size**: All allocations must be compile-time bounded
3. **No early returns**: Every operation executes
4. **Deterministic indexing**: Array access must be predictable

The following sections describe transformations from standard control flow patterns to circuit-compatible implementations.

## Part 1: Loop Unrolling - From Dynamic to Static

### Standard Pattern

Consider a simple loop in regular code:
```rust
// Regular Rust: Dynamic iteration
fn sum_until_zero(data: &[u64]) -> u64 {
    let mut sum = 0;
    for &val in data {
        if val == 0 { break; }
        sum += val;
    }
    sum
}
```

Circuit limitations:
1. Loop bound depends on runtime data
2. Early exit via `break` creates conditional control flow

### Circuit Implementation

Loops are unrolled completely at compile time:

```rust
// Circuit version: Fully unrolled with masking
fn sum_until_zero_circuit(builder: &CircuitBuilder, data: &[Wire; MAX_LEN]) -> Wire {
    let mut sum = builder.add_constant(Word::ZERO);
    let mut found_zero = builder.add_constant(Word::ZERO);

    for i in 0..MAX_LEN {
        // Check if current element is zero
        let is_zero = builder.eq(data[i], builder.add_constant(Word::ZERO));

        // Update found_zero flag (sticky - once set, stays set)
        found_zero = builder.bor(found_zero, is_zero);

        // Mask the addition: only add if we haven't found zero yet
        let mask = builder.bnot(found_zero);
        let masked_val = builder.band(data[i], mask);
        sum = builder.iadd(sum, masked_val);
    }

    sum
}
```

Properties:
- **Fixed iterations**: Loop always runs MAX_LEN times
- **Conditional becomes masking**: Instead of `if`, we multiply by 0 or 1
- **State tracking**: Use flags to remember conditions

### Example: Keccak Permutation

From `keccak/permutation.rs`:
```rust
pub fn keccak_f1600(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    for round in 0..24 {  // Compile-time constant bound
        Self::keccak_permutation_round(b, state, round);
    }
}
```

Requirements:
- Keccak always performs exactly 24 rounds
- No data-dependent iteration count
- Each round modifies state in-place

### Applicable Cases

Loop unrolling is appropriate when:
1. **Fixed bounds**: Maximum iterations known at compile time
2. **Small bounds**: Unrolling won't explode circuit size
3. **No early exit**: Or early exit can be masked

Applications:
- Hash functions (fixed rounds)
- Matrix operations (fixed dimensions)
- Polynomial evaluation (fixed degree)

## Part 2: Variable-Length Data Handling

### Standard Pattern

Many algorithms work with variable-length inputs:
```rust
// Regular Rust: Dynamic allocation
fn hash_message(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);  // msg can be any length
    hasher.finalize()
}
```

### Circuit Implementation

Variable-length data is handled through:
1. Allocating for maximum possible size
2. Tracking actual length
3. Masking/padding unused portions

#### Simple Example: Sum of Variable-Length Array

Consider summing a variable-length array:

```rust
// Regular Rust: Dynamic length
fn sum_array(values: &[u64]) -> u64 {
    values.iter().sum()
}

// Circuit version: Fixed allocation with length tracking
const MAX_ARRAY_SIZE: usize = 1000;

struct VariableLengthArray {
    values: [Wire; MAX_ARRAY_SIZE],  // Allocate maximum
    length: Wire,                    // Actual length (0 to MAX_ARRAY_SIZE)
}

impl VariableLengthArray {
    fn sum(&self, builder: &CircuitBuilder) -> Wire {
        let mut sum = builder.add_constant(Word::ZERO);

        for i in 0..MAX_ARRAY_SIZE {
            // Check if this index is within actual array bounds
            let is_active = builder.lt(
                builder.add_constant(Word(i as u64)),
                self.length
            );

            // Convert boolean to mask (0x0 or 0xFFFFFFFFFFFFFFFF)
            let mask = builder.select(
                builder.add_constant(Word::ZERO),
                builder.add_constant(Word::MAX),
                is_active
            );

            // Mask the value (zero if outside bounds)
            let masked_value = builder.band(self.values[i], mask);

            // Add to sum (adds zero for out-of-bounds elements)
            sum = builder.iadd(sum, masked_value);
        }

        sum
    }
}

// Usage during witness generation:
fn populate_array(array: &VariableLengthArray,
                  witness: &mut WitnessFiller,
                  actual_values: &[u64]) {
    // Set actual length
    witness[array.length] = Word(actual_values.len() as u64);

    // Fill actual values
    for (i, &val) in actual_values.iter().enumerate() {
        witness[array.values[i]] = Word(val);
    }

    // Pad remaining with zeros (or any value - will be masked)
    for i in actual_values.len()..MAX_ARRAY_SIZE {
        witness[array.values[i]] = Word::ZERO;
    }
}
```

##### Understanding Wire Allocation

All MAX_ARRAY_SIZE elements require wire allocation at circuit compilation time.

For MAX_ARRAY_SIZE = 1000:
- 1000 wires for array values
- 1 wire for length
- 1000+ intermediate wires for comparisons, masks, and additions
- Total: ~3000+ wires even if actual array has only 3 elements!

##### Circuit Structure Visualization

Circuit structure for MAX_ARRAY_SIZE = 4:

```
                    Variable-Length Array Sum Circuit
    ════════════════════════════════════════════════════════════════════

     len ──●────●────●────●                      Legend:
           │    │    │    │                       ═══ accumulator flow
           ▼    ▼    ▼    ▼                       ─── data wire
    v[0]──[M0]  │    │    │                       ●── wire split
    v[1]───────[M1]  │    │                       [M] mask module
    v[2]────────────[M2]  │                       [+] addition
    v[3]─────────────────[M3]                     ▼▲  flow direction
           │    │    │    │
           ▼    ▼    ▼    ▼
      0═══[+]══[+]══[+]══[+]═══▶ sum


    Each Mask Module [Mi]:
    ┌─────────────────┐
    │  i < len ?      │
    │     ↓           │
    │  [0x0 : 0xFF]   │  ← select mask
    │     ↓           │
    │   v[i] & mask   │  ← apply mask
    └────────▼────────┘
           output
```

#### More Complex Example: Message Padding

```rust
struct VariableLengthMessage {
    data: [Wire; MAX_BLOCKS * BLOCK_SIZE],  // Maximum allocation
    length: Wire,                           // Actual length in bytes
}

impl VariableLengthMessage {
    fn process_blocks(&self, builder: &CircuitBuilder) -> Wire {
        let mut result = builder.add_constant(INITIAL_STATE);

        // Process all blocks (even empty ones)
        for block_idx in 0..MAX_BLOCKS {
            // Check if this block is within actual length
            let block_start = block_idx * BLOCK_SIZE;
            let is_active = builder.lt(
                builder.add_constant(Word(block_start as u64)),
                self.length
            );

            // Process block (result unchanged if inactive)
            let block_result = self.process_single_block(
                builder,
                &self.data[block_start..block_start + BLOCK_SIZE]
            );

            // Conditionally update result
            result = builder.select(
                result,           // Keep old if inactive
                block_result,     // Use new if active
                is_active
            );
        }

        result
    }
}
```

## Part 3: Conditional Logic via Multiplexing

### Standard Pattern

Circuits lack traditional conditional branching:
```rust
// Regular Rust: Branching control flow
let result = if condition {
    expensive_computation_a()
} else {
    expensive_computation_b()
};
```

### Circuit Implementation

All branches are computed with the result selected:

```rust
// Circuit version: Multiplexing
let result_a = expensive_computation_a(builder);
let result_b = expensive_computation_b(builder);
let result = builder.select(result_a, result_b, condition);
```

### The Select Operation

The `select` operation is fundamental. From `select.rs`:
```rust
// Returns: MSB(cond) ? b : a
// Using single AND constraint: out = a ⊕ ((cond >> 63) ∧ (b ⊕ a))
```

Implementation:
1. **Arithmetic shift** broadcasts MSB to all bits
2. **AND with difference** creates conditional mask
3. **XOR applies mask** to perform selection

Cost: 1 AND constraint

### Nested Conditionals: Multiplexer Trees

#### Array Indexing

In regular code, array indexing is trivial:
```rust
let value = array[index];  // O(1) operation
```

Circuits require selecting from all possibilities rather than using dynamic indexing.

#### Multiplexer Operation

The frontend library comes with a multiplexer gadget. A **multiplexer** (mux) selects one value from multiple inputs based on a selector signal. 
For 2 inputs (2-to-1 mux):
```rust
// If selector is 0, output = input0
// If selector is 1, output = input1
output = selector ? input1 : input0
```

#### 4-to-1 Multiplexer Construction

Array indexing as a binary decision tree:

```
                        root
                     bit1 = MSB
                    ╱          ╲
                  0/            \1
                 ╱                ╲
           [0,1]                  [2,3]
           bit0                   bit0
          ╱    ╲                 ╱    ╲
        0/      \1             0/      \1
        ╱        ╲             ╱        ╲
    arr[0]     arr[1]      arr[2]     arr[3]
     (00)       (01)        (10)       (11)
```

Each bit controls one level:
- bit1 (MSB): Choose between lower half [0,1] or upper half [2,3]
- bit0 (LSB): Choose even or odd within the selected half

```rust
fn mux4(builder: &CircuitBuilder, options: [Wire; 4], index: Wire) -> Wire {
    // Step 1: Extract the two bits from index
    // bit0 = index & 0x1 (least significant bit)
    // bit1 = (index >> 1) & 0x1 (second bit)
    let bit0 = builder.band(index, builder.add_constant(Word(1)));
    let bit1 = builder.band(builder.shr(index, 1), builder.add_constant(Word(1)));

    // Step 2: First level - use bit0 to select within pairs
    // If bit0 = 0: select even indices (0 or 2)
    // If bit0 = 1: select odd indices (1 or 3)
    let option_01 = builder.select(options[0], options[1], bit0);  // Selects from [0,1]
    let option_23 = builder.select(options[2], options[3], bit0);  // Selects from [2,3]

    // Step 3: Second level - use bit1 to select between pairs
    // If bit1 = 0: select from lower pair [0,1]
    // If bit1 = 1: select from upper pair [2,3]
    builder.select(option_01, option_23, bit1)
}
```

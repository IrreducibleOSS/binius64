# Binius64 Circuit Writing Tutorial: Intermediate Level

This tutorial covers more advanced circuit patterns including gadget composition, working with byte arrays, and building reusable components.

## Circuit Composition and Gadgets

In Binius64, we organize complex circuits using "gadgets" - reusable components that encapsulate functionality. Here's the standard pattern:

### The Gadget Pattern

```rust
use binius_frontend::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

struct MyGadget {
    // Public interface - wires that users interact with
    pub input_a: Vec<Wire>,
    pub input_b: Vec<Wire>,
    pub output: Vec<Wire>,
    
    // Internal state
    internal_wires: Vec<Wire>,
    max_len: usize,
}

impl MyGadget {
    pub fn new(
        circuit: &CircuitBuilder, 
        input_a: Vec<Wire>,
        input_b: Vec<Wire>,
        max_len: usize
    ) -> Self {
        // Build constraints here
        let output = vec![circuit.add_internal(); max_len];
        
        // ... constraint logic ...
        
        Self {
            input_a,
            input_b, 
            output,
            internal_wires: vec![],
            max_len,
        }
    }
    
    // Helper methods for populating witness data
    pub fn populate_input_a(&self, w: &mut WitnessFiller, data: &[u8]) {
        // Pack data into wires
    }
}
```

Key principles:
- Gadgets don't create their own input wires - the caller decides if they're public/private
- Use subcircuits for namespacing: `circuit.subcircuit("gadget_name")`
- Provide populate methods for user-friendly witness filling

## Example 1: Variable-Length Byte Arrays

Many circuits work with variable-length data. Let's first see how this would work in regular Rust:

### Rust Version
```rust
// Regular Rust implementation
struct ByteString {
    data: Vec<u8>,
    max_len: usize,
}

impl ByteString {
    fn new(data: Vec<u8>, max_len: usize) -> Result<Self, String> {
        // Runtime check
        if data.len() > max_len {
            return Err("Data exceeds maximum length".to_string());
        }
        Ok(Self { data, max_len })
    }
    
    fn len(&self) -> usize {
        self.data.len()
    }
}
```

### Circuit Version
```rust
use binius_core::word::Word;
use crate::util::pack_bytes_into_wires_le;

struct ByteString {
    pub len: Wire,
    pub data: Vec<Wire>,
    pub max_len: usize,
}

impl ByteString {
    pub fn new(circuit: &CircuitBuilder, max_len: usize) -> Self {
        assert_eq!(max_len % 8, 0, "max_len must be multiple of 8");
        
        let len = circuit.add_witness();
        let data = (0..max_len/8)
            .map(|_| circuit.add_witness())
            .collect();
            
        // Verify length is valid
        let max_len_const = circuit.add_constant_64(max_len as u64);
        let too_large = circuit.icmp_ult(max_len_const, len);
        circuit.assert_0("length_check", too_large);
        
        Self { len, data, max_len }
    }
    
    pub fn populate(&self, w: &mut WitnessFiller, bytes: &[u8]) {
        assert!(bytes.len() <= self.max_len);
        
        // Set length
        w[self.len] = Word(bytes.len() as u64);
        
        // Pack bytes into 64-bit words (little-endian)
        pack_bytes_into_wires_le(w, &self.data, bytes);
    }
}
```

### Key Differences:
- **Rust**: Stores actual data, checks happen at runtime with `Result` type
- **Circuit**: Stores wire references, allocates max space upfront, verifies constraints at proving time
- **Circuit Insight**: We must allocate maximum space since circuit structure is fixed, but we verify actual length doesn't exceed bounds using `icmp_ult` (unsigned less-than comparison)

## Example 2: Conditional Logic

Let's compare how conditional logic works in regular Rust vs circuits:

### Rust Version
```rust
// Regular Rust - branching execution
fn conditional_select(condition: bool, if_true: u64, if_false: u64) -> u64 {
    if condition {
        if_true
    } else {
        if_false
    }
}

// Or using ternary-like syntax
fn conditional_select_v2(condition: bool, if_true: u64, if_false: u64) -> u64 {
    match condition {
        true => if_true,
        false => if_false,
    }
}
```

### Circuit Version

Binius64 uses masking for conditional operations (no branching allowed in circuits):

```rust
struct ConditionalSelect {
    condition: Wire,
    if_true: Wire,
    if_false: Wire,
    result: Wire,
}

impl ConditionalSelect {
    pub fn new(
        circuit: &CircuitBuilder,
        condition: Wire,  // Should be all-1 or all-0
        if_true: Wire,
        if_false: Wire,
    ) -> Self {
        // result = (condition & if_true) | (~condition & if_false)
        let masked_true = circuit.band(condition, if_true);
        let not_condition = circuit.bxor(condition, circuit.add_constant(Word::ALL_ONE));
        let masked_false = circuit.band(not_condition, if_false);
        let result = circuit.bor(masked_true, masked_false);
        
        Self { condition, if_true, if_false, result }
    }
}
```

### Key Differences:
- **Rust**: Uses branching (`if`/`else`), only executes one path
- **Circuit**: Computes both branches, uses bitwise operations to select result
- **Circuit Insight**: Since circuits have fixed structure, we can't have conditional execution paths. Instead, we compute both possibilities and use masking to select the correct one. The condition must be all-1 (true) or all-0 (false) for the bitwise operations to work correctly.

## Example 3: Array Operations - Slice Extraction

Let's look at how slice extraction differs between Rust and circuits:

### Rust Version
```rust
// Regular Rust - simple slice operation
fn extract_slice(input: &[u8], offset: usize, length: usize) -> Result<Vec<u8>, String> {
    // Bounds check
    if offset + length > input.len() {
        return Err("Slice out of bounds".to_string());
    }
    
    // Direct slice extraction
    Ok(input[offset..offset + length].to_vec())
}

// Working with aligned words (more efficient)
fn extract_slice_aligned(input: &[u64], word_offset: usize, word_count: usize) -> Vec<u64> {
    input[word_offset..word_offset + word_count].to_vec()
}
```

### Circuit Version

The circuit must handle both aligned and unaligned extraction:

```rust
struct SliceExtractor {
    input: Vec<Wire>,
    output: Vec<Wire>,
    offset: Wire,
    len_input: Wire,
    len_output: Wire,
}

impl SliceExtractor {
    pub fn new(
        b: &CircuitBuilder,
        max_input_len: usize,
        max_output_len: usize,
    ) -> Self {
        // Create wires
        let input = (0..max_input_len/8).map(|_| b.add_witness()).collect();
        let output = (0..max_output_len/8).map(|_| b.add_witness()).collect();
        let offset = b.add_witness();
        let len_input = b.add_witness();
        let len_output = b.add_witness();
        
        // Verify bounds: offset + len_output <= len_input
        let end_pos = b.iadd_32(offset, len_output);
        let overflow = b.icmp_ult(len_input, end_pos);
        b.assert_0("bounds_check", overflow);
        
        // Extract each output word
        for out_idx in 0..output.len() {
            let b = b.subcircuit(format!("word[{}]", out_idx));
            
            // Calculate which input word(s) we need
            // This handles both aligned and unaligned cases
            extract_word_at_offset(&b, &input, &output, offset, out_idx);
        }
        
        Self { input, output, offset, len_input, len_output }
    }
}
```

### Key Differences:
- **Rust**: Direct array indexing with `[offset..offset+length]` syntax
- **Circuit**: Must handle byte-level offsets in 64-bit word arrays, requiring bit shifting and masking
- **Circuit Insight**: Since we work with 64-bit words but need byte-level precision, unaligned extraction requires combining parts of two adjacent words using shifts and masks. This is why the circuit version is more complex - it must handle all possible alignments within the fixed circuit structure.

## Example 4: Building a Merkle Tree Verifier

Let's compare Merkle proof verification in Rust vs circuits:

### Rust Version
```rust
use sha2::{Sha256, Digest};

// Regular Rust implementation
struct MerkleProof {
    leaf: [u8; 32],
    path: Vec<[u8; 32]>,     // Sibling hashes
    indices: Vec<bool>,       // true = right, false = left
}

impl MerkleProof {
    fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut current = self.leaf;
        
        for (sibling, is_right) in self.path.iter().zip(&self.indices) {
            // Branch based on position
            let (left, right) = if *is_right {
                (sibling, &current)
            } else {
                (&current, sibling)
            };
            
            // Hash the pair
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            current = hasher.finalize().into();
        }
        
        // Simple comparison
        current == *expected_root
    }
}
```

### Circuit Version

The circuit version must avoid branching and use masking:

```rust
struct MerkleProof {
    leaf: Wire,
    root: Wire,
    path: Vec<Wire>,      // Sibling hashes
    indices: Vec<Wire>,   // 0 = left, all-1 = right
    depth: usize,
}

impl MerkleProof {
    pub fn verify(
        b: &CircuitBuilder,
        leaf: Wire,
        root: Wire,
        path: Vec<Wire>,
        indices: Vec<Wire>,
    ) -> Self {
        assert_eq!(path.len(), indices.len());
        let depth = path.len();
        
        let mut current = leaf;
        
        for i in 0..depth {
            let b = b.subcircuit(format!("level[{}]", i));
            
            // Select order based on index
            // if index = 0 (left): hash(current, sibling)
            // if index = all-1 (right): hash(sibling, current)
            let is_left = b.icmp_eq(indices[i], b.add_constant(Word::ZERO));
            
            // Conditional swap without branching
            let left = select(&b, is_left, current, path[i]);
            let right = select(&b, is_left, path[i], current);
            
            // Hash the pair (simplified - real implementation would use SHA256)
            current = simple_hash(&b, left, right);
        }
        
        // Verify computed root matches expected
        b.assert_eq("verify_root", current, root);
        
        Self { leaf, root, path, indices, depth }
    }
}

fn select(b: &CircuitBuilder, condition: Wire, if_true: Wire, if_false: Wire) -> Wire {
    let masked_true = b.band(condition, if_true);
    let not_cond = b.bxor(condition, b.add_constant(Word::ALL_ONE));
    let masked_false = b.band(not_cond, if_false);
    b.bor(masked_true, masked_false)
}

fn simple_hash(b: &CircuitBuilder, left: Wire, right: Wire) -> Wire {
    // Simplified hash for example - real circuits use SHA256
    let mixed = b.bxor(left, right);
    let rotated = b.rotl64(mixed, 17);
    b.bxor(rotated, b.add_constant_64(0x123456789ABCDEF0))
}
```

### Key Differences:
- **Rust**: Uses tuple destructuring with `if` to swap positions, returns boolean
- **Circuit**: Uses conditional selection with masking, enforces equality with constraint
- **Circuit Insight**: The circuit's `select` function computes both `(current, sibling)` and `(sibling, current)` orderings, then uses bitwise masking to choose the correct one. This is more expensive than Rust's branching but maintains the fixed circuit structure required for zero-knowledge proofs.

## Example 5: Working with Multiple Data Formats

Let's see how Base64 encoding verification differs between Rust and circuits:

### Rust Version
```rust
use base64::{Engine as _, engine::general_purpose};

// Regular Rust - using library
fn verify_base64(data: &[u8]) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| e.to_string())
}

// Manual implementation for comparison
fn encode_base64_manual(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = Vec::new();
    
    // Process 3-byte chunks
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        
        // Extract 6-bit values
        output.push(TABLE[(b0 >> 2) as usize]);
        output.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize]);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0x3F) as usize]);
        }
    }
    
    output
}
```

### Circuit Version

The circuit must verify the encoding relationship without using lookup tables:

```rust
struct Base64Verifier {
    decoded: Vec<Wire>,  // Raw bytes
    encoded: Vec<Wire>,  // Base64 characters
    len_decoded: Wire,
}

impl Base64Verifier {
    pub fn new(
        b: &CircuitBuilder,
        max_decoded_len: usize,
    ) -> Self {
        // Must be multiple of 24 for alignment
        assert!(max_decoded_len % 24 == 0);
        
        let decoded = (0..max_decoded_len/8).map(|_| b.add_witness()).collect();
        let encoded = (0..max_decoded_len/6).map(|_| b.add_witness()).collect();
        let len_decoded = b.add_witness();
        
        // Process each group: 3 bytes -> 4 base64 chars
        for group_idx in 0..max_decoded_len/3 {
            let b = b.subcircuit(format!("group[{}]", group_idx));
            verify_base64_group(&b, &decoded, &encoded, group_idx);
        }
        
        Self { decoded, encoded, len_decoded }
    }
}

fn verify_base64_group(
    b: &CircuitBuilder,
    decoded: &[Wire],
    encoded: &[Wire],
    group_idx: usize,
) {
    // Extract 3 bytes from decoded
    let byte0 = extract_byte(b, decoded, group_idx * 3);
    let byte1 = extract_byte(b, decoded, group_idx * 3 + 1);
    let byte2 = extract_byte(b, decoded, group_idx * 3 + 2);
    
    // Extract 4 base64 characters
    let char0 = extract_byte(b, encoded, group_idx * 4);
    let char1 = extract_byte(b, encoded, group_idx * 4 + 1);
    let char2 = extract_byte(b, encoded, group_idx * 4 + 2);
    let char3 = extract_byte(b, encoded, group_idx * 4 + 3);
    
    // Compute expected base64 values (6-bit chunks)
    let val0 = b.shr(byte0, 2);  // Top 6 bits of byte0
    let val1 = {
        let b0_low = b.band(byte0, b.add_constant_64(0x03));
        let b1_high = b.shr(byte1, 4);
        b.bor(b.shl(b0_low, 4), b1_high)
    };
    // ... continue for val2, val3
    
    // Verify each character maps to correct value
    // This uses conditional selection rather than table lookup
    verify_base64_char(b, char0, val0);
    verify_base64_char(b, char1, val1);
    verify_base64_char(b, char2, val2);
    verify_base64_char(b, char3, val3);
}

fn extract_byte(b: &CircuitBuilder, words: &[Wire], byte_idx: usize) -> Wire {
    let word_idx = byte_idx / 8;
    let byte_in_word = byte_idx % 8;
    
    let word = words[word_idx];
    let shifted = b.shr(word, byte_in_word * 8);
    b.band(shifted, b.add_constant_64(0xFF))
}
```

### Key Differences:
- **Rust**: Uses array indexing for lookup table, handles variable-length chunks with `.get()`
- **Circuit**: Must verify character-to-value mapping using conditional logic instead of lookups
- **Circuit Insight**: Lookup tables don't work well in circuits because array indexing with a witness value would require checking all possible indices. Instead, we use a series of conditional checks or range verifications to ensure each base64 character maps to the correct 6-bit value.

## Optimization Techniques

### 1. Minimize Constraint Count

Remember the cost model:
- AND constraint: 1x cost
- MUL constraint: ~8x cost  
- Committing one word: ~0.2x cost

```rust
// Bad: Multiple operations
let a_plus_b = circuit.iadd_32(a, b);
let b_plus_c = circuit.iadd_32(b, c);
let result = circuit.iadd_32(a_plus_b, c);

// Better: Combine when possible
let sum = circuit.iadd_32(a, circuit.iadd_32(b, c));
```

### 2. Use Free Operations Inside Constraints

XORs and shifts are free inside a single constraint:

```rust
// This is essentially free - one AND constraint
let result = circuit.band(
    circuit.bxor(a, b),
    circuit.bxor(c, circuit.shr(d, 5))
);

// This costs more - multiple constraints
let xor1 = circuit.bxor(a, b);
let xor2 = circuit.bxor(c, circuit.shr(d, 5));
let result = circuit.band(xor1, xor2);
```

### 3. Batch Operations

When performing similar operations on arrays:

```rust
// Process multiple items in parallel
for i in 0..n {
    let b = circuit.subcircuit(format!("item[{}]", i));
    // Constraints here run independently
}
```

## Common Patterns

### Pattern 1: Length-Prefixed Arrays

#### Rust Version
```rust
// Regular Rust with dynamic allocation
struct VarLenArray<T> {
    data: Vec<T>,  // Dynamically sized
}

impl<T> VarLenArray<T> {
    fn new(data: Vec<T>) -> Self {
        Self { data }
    }
    
    fn len(&self) -> usize {
        self.data.len()
    }
}
```

#### Circuit Version
```rust
struct VarLenArray {
    len: Wire,
    data: Vec<Wire>,
    max_len: usize,
}

impl VarLenArray {
    pub fn new(b: &CircuitBuilder, max_len: usize) -> Self {
        let len = b.add_witness();
        let data = (0..max_len).map(|_| b.add_witness()).collect();
        
        // Bounds check
        let overflow = b.icmp_ult(b.add_constant_64(max_len as u64), len);
        b.assert_0("len_check", overflow);
        
        Self { len, data, max_len }
    }
}
```

**Key Insight**: Circuits must pre-allocate maximum space since structure is fixed at compile time, while Rust can dynamically resize. The circuit enforces `len <= max_len` as a constraint.

### Pattern 2: Accumulator/Reduce

#### Rust Version
```rust
// Regular Rust - can use iterator methods
fn sum_array(values: &[u64]) -> Option<u64> {
    values.iter().try_fold(0u64, |acc, &val| {
        acc.checked_add(val)  // Returns None on overflow
    })
}

// Or panic on overflow
fn sum_array_unwrap(values: &[u64]) -> u64 {
    values.iter().sum()  // Panics on overflow in debug mode
}
```

#### Circuit Version
```rust
fn sum_array(b: &CircuitBuilder, values: &[Wire]) -> Wire {
    let mut acc = b.add_constant(Word::ZERO);
    
    for (i, &val) in values.iter().enumerate() {
        let b = b.subcircuit(format!("sum[{}]", i));
        let (new_acc, carry) = b.iadd_cin_cout(acc, val, b.add_constant(Word::ZERO));
        
        // Assert no overflow
        b.assert_0("no_overflow", carry);
        acc = new_acc;
    }
    
    acc
}
```

**Key Insight**: Rust can handle overflow with `Option` or panic, but circuits must explicitly check the carry output and assert it's zero. This makes overflow checking part of the proof.

### Pattern 3: Lookup Tables

#### Rust Version
```rust
// Regular Rust - direct array indexing
fn lookup_4bit(index: usize, table: &[u64; 16]) -> u64 {
    table[index & 0x0F]  // Mask to ensure in bounds
}

// Or with bounds checking
fn lookup_4bit_safe(index: usize, table: &[u64; 16]) -> Option<u64> {
    table.get(index).copied()
}
```

#### Circuit Version

For small lookup tables, use conditional selection:

```rust
fn lookup_4bit(b: &CircuitBuilder, index: Wire, table: &[Wire; 16]) -> Wire {
    // Build binary tree of selections
    let is_high = b.icmp_ult(b.add_constant_64(7), index);
    
    let low_half = select_8(b, index, &table[0..8]);
    let high_half = select_8(b, index, &table[8..16]);
    
    select(b, is_high, high_half, low_half)
}
```

**Key Insight**: Direct array indexing with a witness value doesn't work in circuits. Instead, we build a binary tree of conditional selections, comparing the index against constants. For a 16-element table, this requires log₂(16) = 4 levels of selection.

## Testing Your Circuits

Always test with edge cases:

```rust
#[test]
fn test_edge_cases() {
    let circuit = build_my_circuit();
    
    // Test with zeros
    test_with_input(&circuit, &[0; 32]);
    
    // Test with max values
    test_with_input(&circuit, &[0xFF; 32]);
    
    // Test boundary conditions
    test_with_length(&circuit, 0);
    test_with_length(&circuit, MAX_LEN);
    
    // Test random inputs
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..1000 {
        let input = random_input(&mut rng);
        test_with_input(&circuit, &input);
    }
}
```

## Next Steps

You're now ready for advanced circuits! The advanced tutorial covers:
- Cryptographic primitives (SHA256, Keccak)
- RSA signature verification
- Complex protocols like JWT verification
- Performance optimization strategies
- Building production-ready circuits
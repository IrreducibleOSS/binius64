# Composing Circuits: Building Applications from Components

This tutorial covers how to compose multiple circuits into complete applications in Binius64, demonstrating patterns for circuit interaction, data flow, and witness management.

## Critical Design Insight for Circuit Composition

### The Wire Type Choice Determines Composition Complexity

The fundamental issue making circuit composition difficult in Binius64 is the choice between `add_witness()` and `add_inout()` for intermediate values:

**`add_inout()` wires:**
- Must be populated externally before evaluation
- Cannot be computed by the circuit's evaluation form
- Force external computation of intermediate values
- Create the "population dance" in circuit composition

**`add_witness()` wires:**
- Can be computed during circuit evaluation
- Populated automatically by the evaluation form's bytecode interpreter
- Enable true computational chaining

### The Technical Problem: Misuse of Input/Output Wires

The current SHA256 implementation demonstrates the problem:

```rust
// Current: digest declared as input/output
let digest: [Wire; 4] = std::array::from_fn(|_| b.add_inout());

// This forces users to:
// 1. Compute SHA256 externally
// 2. Populate the digest manually
// 3. Have the circuit redundantly verify the computation
```

A better design for composition:

```rust
// Better: digest as witness (computed internally)
let digest: [Wire; 4] = std::array::from_fn(|_| b.add_witness());

// Now the circuit's evaluation form computes the digest
// No external SHA256 implementation needed
// Chaining becomes automatic
```

### How This Solves the Composition Problem

With proper wire type choices:

1. **SHA256(SHA256(x)) becomes trivial**: First circuit computes intermediate hash, second circuit reads it directly
2. **No duplicate wires needed**: Output wires of one circuit ARE input wires of the next
3. **No external computation**: The evaluation form's bytecode handles all intermediate values
4. **Single population point**: Only populate the initial input; everything else is computed

The evaluation form has a complete instruction set (arithmetic, bitwise, shifts) and can compute any intermediate value. The choice to use `add_inout()` for computed values is what creates composition complexity, not any fundamental limitation of the system.

## Part 1: Introduction to Circuit Composition

### Why Circuit Composition Matters

// REVIEW "In practice"
In zero-knowledge proof systems, we rarely work with single, isolated circuits. Real applications require:
- **JWT verification**: Base64 decoding → JSON parsing → RSA signature verification
- **Blockchain transactions**: ECDSA signatures → Merkle tree updates → State transitions
- **Identity proofs**: Hash chains → Commitment schemes → Range proofs

Circuit composition is the practice of connecting these individual components into working systems while managing the complexity of data flow and witness coordination.

### Understanding Circuit Boundaries

Before composing circuits, we need to identify natural boundaries. A circuit boundary should exist where:

1. **Data format changes**: e.g., base64-encoded → raw bytes
2. **Algorithm switches**: e.g., hashing → signature verification
3. **Responsibility shifts**: e.g., parsing → validation
4. **Reusability emerges**: e.g., SHA256 used by multiple components

Example: In JWT verification, natural boundaries are:
- Base64 decoder (format change)
- JSON parser (algorithm switch)
- Claim validator (responsibility shift)
- RSA verifier (reusable component)

### Core Concepts

**Wire**: A 64-bit value that carries data between circuit operations. Think of it as a register that holds intermediate computation results.

**Witness**: The complete set of values for all wires in a circuit. This includes public inputs, private inputs, and all intermediate values computed during circuit execution.

**Subcircuit**: A namespaced, reusable circuit component. Like functions in programming, subcircuits encapsulate logic and can be instantiated multiple times with different inputs.

## Part 2: Witness Management (Critical Foundation)

### The Witness Lifecycle

Understanding witness management is crucial because it's where most circuit composition errors occur. To understand why, we need to examine the complete lifecycle of witness data as it flows through a circuit system.

#### The Three-Phase Process

When you work with circuits in Binius64, witness data moves through three distinct phases. These phases are strictly ordered and cannot be interleaved - you must complete each phase before moving to the next. This rigid structure is what enables zero-knowledge proofs to work, but it's also what makes circuit composition challenging.

**Phase 1: Declaration (Circuit Building)**

During the declaration phase, you're defining the structure of your circuit - like drawing a blueprint. No actual computation happens yet; you're just reserving space for values that will come later. Think of it as declaring variables in a program, but these variables represent wires that will carry data through your circuit.

```rust
// This happens at compile time when building the circuit structure
let mut builder = CircuitBuilder::new();

// Declare wires that will hold values later
let input = builder.add_witness();       // Private input wire
let output = builder.add_witness();      // Will be computed
let public = builder.add_inout();        // Public input/output

// Create circuits that reference these wires
let hasher = Sha256::new(&builder, input, output);

// Build the final circuit structure
let circuit = builder.build();
```

At this point, we have a circuit structure with "empty" wires - placeholders waiting for actual values. The circuit knows how wires connect and what constraints must be satisfied, but no actual data flows yet.

**Phase 2: Population (Witness Filling)**

The population phase is where you provide actual values for the input wires. This is like filling in a form - you can only write to each field once, and you must know which fields are yours to fill versus which will be computed automatically.

```rust
// Create a witness filler for this specific proof instance
let mut w = circuit.new_witness_filler();

// Populate input values (you must know which wires are inputs!)
w[input] = Word(42);                     // Set input value
w[public] = Word(100);                   // Set public value

// Note: We do NOT set 'output' - it will be computed
// Trying to set it would cause an error: "wire already set"

// Some circuits provide helper methods for population
hasher.populate_message(&mut w, b"hello world");
// This internally does: w[hasher.message_wires[i]] = ...
```

The tricky part: you must know which wires to populate and which to leave for computation. This knowledge is often implicit and inconsistent across different circuits.

**Phase 3: Evaluation (Circuit Execution)**

The evaluation phase is where the magic happens - the circuit computes all intermediate and output values based on the inputs you provided. This phase traverses the circuit graph, evaluating each gate and propagating values forward.

```rust
// Execute the circuit to compute all intermediate values
circuit.populate_wire_witness(&mut w)?;

// After evaluation:
// - All intermediate wires have values
// - All output wires are computed
// - All constraints are checked

// Now you can extract computed values
let computed_output = w[output];  // This now has a value!

// The circuit has verified all constraints:
// - If evaluation succeeds, all constraints are satisfied
// - If it fails, you get an error indicating which constraint failed
```

#### Why This Matters for Composition

The three-phase structure creates several challenges when composing circuits:

1. **No Partial Evaluation**: In Binius64, you cannot partially evaluate circuits. The entire witness must be populated before ANY evaluation occurs. This means if circuit B depends on circuit A's computed output, you're stuck - there's no way to get A's output without fully populating and evaluating the entire circuit.
   - Finally evaluate B (Phase 3 again)

2. **Ownership Ambiguity**: When multiple circuits share wires, it's unclear:
   - Who declares the wire? (Phase 1)
   - Who populates it? (Phase 2)
   - Who depends on it being computed? (Phase 3)

3. **Hidden State**: The witness filler (`w`) carries state between phases, but:
   - You can't query which wires are already set
   - You can't "undo" a wire assignment
   - Errors only appear during evaluation, not population

#### Complete Example: Two-Circuit Pipeline

Here's how the three phases work in a real composition scenario:

```rust
// PHASE 1: Declaration - Build circuit structure
let mut builder = CircuitBuilder::new();

// Declare all wires upfront
let message = builder.add_witness();
let hash_output = [(); 4].map(|_| builder.add_witness());
let signature = builder.add_witness();
let is_valid = builder.add_witness();

// Build subcircuits that reference these wires
let hasher = Sha256::new(&builder, message, hash_output);
let verifier = SignatureVerifier::new(&builder, hash_output, signature, is_valid);

let circuit = builder.build();

// PHASE 2: Population - Provide input values
let mut w = circuit.new_witness_filler();

// Populate primary inputs
w[message] = Word(encode_message(b"Hello"));
w[signature] = Word(load_signature());

// Note: We don't populate hash_output or is_valid - they're computed

// PHASE 3: Evaluation - Compute everything
circuit.populate_wire_witness(&mut w)?;

// After evaluation, all wires have values:
// - hasher read 'message', computed 'hash_output'
// - verifier read 'hash_output' and 'signature', computed 'is_valid'

// Extract final result
let verification_result = w[is_valid];
assert_eq!(verification_result, Word(1)); // Signature is valid
```

This rigid three-phase structure is why consistent circuit interfaces are so important - they make it clear which phase each operation belongs to and who is responsible for each wire.

### Witness Dependencies and Order

Witnesses form a dependency graph. You must populate values in topological order:

```rust
pub struct DependentCircuits {
    // Dependency graph: input → hasher → verifier
    input: Wire,
    hash_output: [Wire; 4],
    verification_result: Wire,

    hasher: Sha256,
    verifier: SignatureVerify,
}

impl DependentCircuits {
    pub fn populate_witness(&self, w: &mut WitnessFiller, data: &[u8], signature: &[u8]) {
        // Step 1: Populate primary inputs (no dependencies)
        pack_bytes_into_wires_le(w, &[self.input], data);

        // Step 2: Hash computation needs input to be populated
        // The hasher will read self.input and write to hash_output
        // (This happens during circuit evaluation)

        // Step 3: Verifier needs hash_output, so populate signature
        // after circuit evaluation computes the hash
        self.verifier.populate_signature(w, signature);

        // Step 4: Circuit evaluation will compute verification_result
    }
}
```

**Key Principle**: A wire can only be written once. If multiple circuits need the same value, they must reference the same wire, not create duplicates.

### Sharing Witnesses Between Circuits

When circuits share data, use the same wire references:

```rust
pub struct SharedDataCircuits {
    // Single nonce used by multiple circuits
    shared_nonce: [Wire; 4],

    // Both circuits read from shared_nonce
    auth_circuit: AuthVerifier,
    timestamp_circuit: TimestampChecker,
}

impl SharedDataCircuits {
    pub fn new(builder: &mut CircuitBuilder) -> Self {
        // Create shared wires once
        let shared_nonce = array::from_fn(|_| builder.add_witness());

        // Pass same wires to both circuits
        let auth_circuit = AuthVerifier::new(builder, shared_nonce);
        let timestamp_circuit = TimestampChecker::new(builder, shared_nonce);

        Self { shared_nonce, auth_circuit, timestamp_circuit }
    }

    pub fn populate(&self, w: &mut WitnessFiller, nonce: [u64; 4]) {
        // Populate shared witness exactly once
        for (i, &val) in nonce.iter().enumerate() {
            w[self.shared_nonce[i]] = Word(val);
        }
        // Both circuits will read these values during evaluation
    }
}
```

### Debugging Witness Issues

Common witness problems and solutions:

```rust
fn debug_witness_population(circuit: &Circuit, w: &WitnessFiller) {
    match circuit.populate_wire_witness(w) {
        Ok(_) => println!("Success!"),
        Err(e) => {
            // Common errors:
            match e {
                Error::WireAlreadySet(wire_id) => {
                    println!("Wire {} was written twice", wire_id);
                    // Solution: Ensure only one circuit writes to each wire
                }
                Error::UninitializedWire(wire_id) => {
                    println!("Wire {} was never populated", wire_id);
                    // Solution: Check population order and completeness
                }
                Error::ConstraintViolation(constraint_id) => {
                    println!("Constraint {} failed", constraint_id);
                    // Solution: Verify computation logic and input values
                }
            }
        }
    }
}
```

## Part 3: Data Representation and Wire Packing

### The Type System Failure: Untyped Wires in a Multi-Protocol World

Imagine a CPU where every instruction expects data in a different endianness, but the registers have no type information. That's the wire packing problem in Binius64.

#### The Missing Type Information

Every wire is just a `Wire` - an opaque index with no type information:

```rust
// All these are just "Wire" - no type safety!
let utf8_string: Wire = builder.add_witness();      // UTF-8 bytes packed LE
let network_data: Wire = builder.add_witness();     // Network bytes in BE
let sha256_state: Wire = builder.add_witness();     // 32-bit BE words packed as 64-bit BE
let base64_chunk: Wire = builder.add_witness();     // 6-bit values packed LE
let rsa_limb: Wire = builder.add_witness();         // Multi-precision integer limb

// The type system can't prevent this disaster:
sha256.populate(w, network_data);  // WRONG! SHA256 expects different packing
base64.decode(utf8_string);         // WRONG! Base64 expects different format
```

#### The CPU Analogy: Instructions with Incompatible Formats

It's like having a CPU where:
- `SHA256` instruction expects 32-bit BE words packed into 64-bit BE registers
- `BASE64` instruction expects 8-bit LE bytes packed into 64-bit LE registers  
- `RSA` instruction expects 64-bit LE limbs of a big integer
- `AES` instruction expects 128-bit BE blocks split across two 64-bit registers

But all you have are untyped 64-bit registers, and **you must manually convert between formats** with no compiler help:

```rust
// Manual conversion hell - no type checking!
let message_bytes = "hello".as_bytes();

// For SHA256: Pack as 32-bit BE words into 64-bit BE wire
let sha_wire = pack_for_sha256(message_bytes);  // Custom packing function

// For Base64: Pack as 8-bit LE bytes into 64-bit LE wire  
let b64_wire = pack_for_base64(message_bytes);  // Different packing!

// For RSA: Pack as 64-bit LE limbs
let rsa_wire = pack_for_rsa(message_bytes);     // Yet another format!
```

#### The Protocol Mismatch Problem

Each circuit has its own "wire protocol" but there's no way to express or enforce it:

### Little-Endian Packing (Binius64 Default)

Little-endian packing places the least significant byte first. This matches x86/ARM processor conventions and provides efficient processing:

```rust
/// Pack up to 8 bytes into a single 64-bit wire using little-endian ordering
///
/// Why LE packing?
/// 1. Matches CPU byte order on most platforms (x86, ARM)
/// 2. Allows efficient byte extraction using shift operations
/// 3. Natural for incremental data processing
///
/// Wire layout (bit positions):
/// | Bits 56-63 | Bits 48-55 | ... | Bits 8-15 | Bits 0-7 |
/// | byte[7]    | byte[6]    | ... | byte[1]   | byte[0]  |
///
pub fn pack_bytes_le(bytes: &[u8]) -> u64 {
    let mut word = 0u64;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        // byte[i] goes to bits [i*8 .. i*8+7]
        word |= (byte as u64) << (i * 8);
    }
    word
}

// Example: Packing "hello" (0x68, 0x65, 0x6C, 0x6C, 0x6F)
// Result: 0x0000006F6C6C6568
//         | padding | 'o' | 'l' | 'l' | 'e' | 'h' |
```

### Big-Endian Numbers in Cryptography

Cryptographic standards (RSA, ECDSA) use big-endian representation for mathematical reasons:
- Natural for modular arithmetic
- Standard in cryptographic specifications (RFC, NIST)
- Direct correspondence to mathematical notation

However, we still pack bytes into wires using little-endian for consistency:

```rust
/// BigUint representation with mixed endianness:
/// - Limbs array: little-endian (limbs[0] is least significant)
/// - Each limb: represents a big-endian 64-bit number
/// - Bytes within limb: need reversal when converting from LE wires
///
/// This dual convention arises because:
/// 1. Circuit wires use LE packing (Binius64 convention)
/// 2. Cryptographic math uses BE numbers (industry standard)
pub struct BigUint {
    limbs: Vec<Wire>,  // limbs[0] = least significant 64 bits
}

/// Convert from LE-packed wire format to BE number format
/// Used when interfacing with cryptographic circuits (RSA, ECDSA)
fn fixedbytevec_le_to_biguint(builder: &mut CircuitBuilder, byte_vec: &FixedByteVec) -> BigUint {
    // Why this complexity?
    // 1. Input: LE-packed wires (Binius64 standard)
    // 2. Output: BE number for cryptographic operations
    // 3. Requires: Wire reversal AND byte reversal within each wire

    let mut limbs = Vec::new();

    // Process wires in reverse order (LE → BE conversion for limb array)
    for packed_wire in byte_vec.data.clone().into_iter().rev() {
        // Extract bytes from LE-packed wire
        let mut bytes = Vec::with_capacity(8);
        for i in 0..8 {
            // Extract byte at position i (LE position)
            let byte = builder.shr(packed_wire, (i * 8) as u32);
            let byte_masked = builder.band(byte, builder.add_constant_64(0xFF));
            bytes.push(byte_masked);
        }

        // Repack bytes in reverse order (LE → BE within limb)
        let mut swapped_limb = bytes[7];  // Start with MSB
        for i in 1..8 {
            let shifted = builder.shl(bytes[7 - i], (i * 8) as u32);
            swapped_limb = builder.bor(swapped_limb, shifted);
        }
        limbs.push(swapped_limb);
    }

    BigUint { limbs }
}

// Visual Example: Converting 16-byte value
// Input LE wires:  [0x0807060504030201, 0x100F0E0D0C0B0A09]
// After reversal:  [0x0102030405060708, 0x090A0B0C0D0E0F10]
// As BE number:    0x0102030405060708090A0B0C0D0E0F10
```

### The FixedByteVec Pattern

> Note: FixedByteVec is a specific circuit pattern for handling variable-length data. It's included here because understanding how it packs data is essential for circuit composition.

For variable-length data with compile-time maximum bounds:

```rust
/// FixedByteVec: Handles variable-length byte arrays in circuits
///
/// Why needed?
/// - Circuits require fixed structure at compile time
/// - Real data has variable length at runtime
/// - Solution: Fixed capacity with runtime length tracking
pub struct FixedByteVec {
    pub len: Wire,           // Runtime: actual byte count
    pub data: Vec<Wire>,      // Compile-time: fixed wire count
    pub max_len: usize,       // Compile-time: maximum byte capacity
}

impl FixedByteVec {
    /// Create a new FixedByteVec for input/output data
    pub fn new_inout(b: &mut CircuitBuilder, max_len: usize) -> Self {
        assert_eq!(max_len % 8, 0, "max_len must be word-aligned");

        Self {
            len: b.add_inout(),  // Public input: actual length
            data: (0..max_len / 8).map(|_| b.add_inout()).collect(),
            max_len,
        }
    }

    /// Populate with actual data at runtime
    pub fn populate(&self, w: &mut WitnessFiller, bytes: &[u8]) {
        assert!(bytes.len() <= self.max_len);

        // Set actual length
        w[self.len] = Word(bytes.len() as u64);

        // Pack bytes into wires (using existing utility)
        pack_bytes_into_wires_le(w, &self.data, bytes);
        // Note: pack_bytes_into_wires_le handles zero-padding automatically
    }
}

// Usage Example: JWT payload with variable length
// max_len = 512 bytes (compile-time bound)
// actual_len = 247 bytes (runtime value)
// Wires allocated: 512/8 = 64 wires
// Wires used: ceil(247/8) = 31 wires
// Wires zeroed: 33 wires
```

## Part 4: Circuit Interfaces - The Object-Oriented Analogy

### Understanding Circuits as Classes

If we think of circuits as classes in object-oriented programming, we can identify common "method" patterns that circuits expose. However, unlike traditional OOP where interfaces are well-defined, Monbijou's circuits have evolved organically, leading to inconsistent patterns that could benefit from refactoring.

### Current Circuit Method Patterns

Looking at existing circuits, we can identify several method categories:

```rust
/// Conceptual Circuit "Interface" (not actually enforced)
trait Circuit {
    // === Constructor Methods ===
    fn new(builder: &CircuitBuilder, ...) -> Self;
    fn new_inout(builder: &CircuitBuilder, ...) -> Self;
    fn new_witness(builder: &CircuitBuilder, ...) -> Self;
    fn new_constant(builder: &CircuitBuilder, ...) -> Self;

    // === Population Methods ===
    fn populate(&self, w: &mut WitnessFiller, data: &[u8]);
    fn populate_len(&self, w: &mut WitnessFiller, len: usize);
    fn populate_<field>(&self, w: &mut WitnessFiller, value: T);

    // === Conversion Methods ===
    fn to_le_wires(&self, builder: &CircuitBuilder) -> Vec<Wire>;
    fn from_be_bytes(builder: &CircuitBuilder, bytes: &[u8]) -> Self;

    // === Query Methods ===
    fn is_zero(&self, builder: &CircuitBuilder) -> Wire;
    fn equals(&self, builder: &CircuitBuilder, other: &Self) -> Wire;
}
```

### The Inconsistency Problem

Different circuits expose different subsets of these methods with inconsistent naming:

```rust
// SHA256: Has specific populate methods
impl Sha256 {
    pub fn populate_len(&self, w: &mut WitnessFiller, len: usize);
    pub fn populate_digest(&self, w: &mut WitnessFiller, digest: [u8; 32]);
    pub fn populate_message(&self, w: &mut WitnessFiller, message: &[u8]);
}

// RS256: Different naming convention
impl Rs256Verify {
    pub fn populate_message_len(&self, w: &mut WitnessFiller, len: usize);
    pub fn populate_rsa(&self, w: &mut WitnessFiller, sig: &[u8], mod: &[u8]);
    pub fn populate_intermediates(&self, w: &mut WitnessFiller, ...);
}

// FixedByteVec: Yet another pattern
impl FixedByteVec {
    pub fn populate_bytes_le(&self, w: &mut WitnessFiller, bytes: &[u8]);
    // No populate_len - it's done inside populate_bytes_le
}

// Base64: No populate methods at all!
impl Base64UrlSafe {
    pub fn new(...) -> Self;
    // User must manually populate decoded, encoded, and len_decoded
}
```

### Composition Challenges

#### Understanding Witness Ownership and Population

Before examining specific problems, it's crucial to understand witness management in composed circuits. The challenge stems from a fundamental question: when multiple circuits share wires, who is responsible for populating them with values? This seemingly simple question becomes complex when circuits are composed together, as ownership boundaries blur and responsibilities become ambiguous.

**Witness Ownership Rules**

In an ideal world, witness ownership would follow clear, consistent patterns. In practice, Binius64 circuits follow these implicit rules that developers must internalize:

1. **Single Writer Rule**: Each wire can only be written to once during witness population
2. **Construction vs Population**: Wires are declared during circuit construction but populated later with actual values
3. **Explicit Ownership**: The circuit that creates a wire typically "owns" its population responsibility

**The Two-Phase Process**

Circuit composition happens in two distinct phases that cannot be mixed. Understanding this separation is critical for managing witness data flow:

```rust
// Phase 1: Circuit Construction (compile-time)
let wire = builder.add_witness();  // Declare wire existence
let circuit = SomeCircuit::new(builder, wire);  // Pass wire reference

// Phase 2: Witness Population (runtime)
w[wire] = Word(42);  // Assign actual value
// OR
circuit.populate_something(w, value);  // Circuit handles population
```

**Population Strategies**

Different circuits adopt different strategies for witness population, leading to the inconsistency problems we'll explore:

1. **Owner Populates**: The circuit that creates the wire populates it
2. **Delegated Population**: A circuit provides a populate method for its wires
3. **Manual Coordination**: Parent circuit manually populates child circuit wires

With this context, let's examine how inconsistent interfaces create problems:

```rust
// Problem 1: Unclear data flow and ownership
let sha256 = Sha256::new(&builder, ...);
let rs256 = Rs256Verify::new(&builder, message, ...);
// Which circuit "owns" the message witness population?
// Do I call sha256.populate_message() or rs256.populate_message()?
// If both circuits reference the same message wires, who populates them?
// Current answer: You must trace through constructors to understand ownership

// Problem 2: Hidden dependencies and missing abstractions
let base64 = Base64UrlSafe::new(&builder, decoded, encoded, len);
// Base64 doesn't provide populate methods - it assumes you know:
// - That decoded, encoded, and len are YOUR responsibility
// - The correct order of population (len before data)
// - The correct packing format (LE, with zero padding)
// This breaks encapsulation - internal details leak to users

// Problem 3: Duplicate population logic and coordination burden
impl JwtVerifier {
    fn populate_witness(&self, w: &mut WitnessFiller, jwt: &str) {
        // Parent must understand child circuit internals
        self.header_b64.populate_bytes_le(w, header);  // FixedByteVec handles its own

        // But base64 decoder has no populate method!
        // Parent must manually populate base64's wires, knowing internal structure
        w[self.header_decoder.len_decoded] = Word(header.len() as u64);
        pack_bytes_into_wires_le(w, &self.header_decoder.decoded, header);
        // This violates abstraction - parent shouldn't need to know base64 internals
    }
}
```

The core issue: **witness ownership and population responsibility are implicit and inconsistent**, forcing developers to understand internal implementation details of every circuit they compose.

### Proposed Circuit Interface Standard

To improve composability, circuits should follow a consistent interface pattern:

```rust
/// Standard circuit trait (could be enforced or just conventional)
trait StandardCircuit {
    /// Associated type for circuit-specific parameters
    type Config;

    /// Constructor always takes builder and config
    fn new(builder: &CircuitBuilder, config: Self::Config) -> Self;

    /// Single populate method for all inputs
    fn populate_inputs(&self, w: &mut WitnessFiller, inputs: Self::Inputs);

    /// Query methods for circuit properties
    fn input_wires(&self) -> &[Wire];
    fn output_wires(&self) -> &[Wire];
    fn wire_count(&self) -> usize;
    fn constraint_count(&self) -> (usize, usize); // (AND, MUL)
}

// Example: Refactored SHA256
pub struct Sha256Config {
    pub max_len: usize,
}

pub struct Sha256Inputs<'a> {
    pub message: &'a [u8],
    pub expected_digest: Option<[u8; 32]>, // Optional for verification
}

impl StandardCircuit for Sha256 {
    type Config = Sha256Config;
    type Inputs = Sha256Inputs<'_>;

    fn new(builder: &CircuitBuilder, config: Sha256Config) -> Self {
        // Consistent construction
    }

    fn populate_inputs(&self, w: &mut WitnessFiller, inputs: Sha256Inputs) {
        // Single entry point for witness population
        self.populate_len(w, inputs.message.len());
        self.populate_message(w, inputs.message);
        if let Some(digest) = inputs.expected_digest {
            self.populate_digest(w, digest);
        }
    }
}
```

### Refactoring Opportunities

Based on this analysis, several refactoring opportunities emerge:

#### 1. Standardize Constructor Patterns
```rust
// Current: Inconsistent constructors
BigUint::new_inout(builder, num_limbs)
BigUint::new_witness(builder, num_limbs)
BigUint::new_constant(builder, &num_bigint::BigUint)

// Proposed: Builder pattern
BigUint::builder()
    .wire_type(WireType::Witness)
    .num_limbs(4)
    .build(builder)
```

#### 2. Unify Population Methods
```rust
// Current: Circuit-specific population
sha256.populate_message(w, msg);
sha256.populate_len(w, len);
sha256.populate_digest(w, digest);

// Proposed: Single struct for inputs
sha256.populate(w, &Sha256Inputs {
    message: msg,
    digest: Some(digest),
});
```

#### 3. Extract Common Wire Management
```rust
// Current: Repeated pattern in many circuits
pub struct SomeCircuit {
    data: Vec<Wire>,
    len: Wire,
    max_len: usize,
}

// Proposed: Reusable component
pub struct VariableLengthWires {
    data: Vec<Wire>,
    len: Wire,
    max_len: usize,
}

impl VariableLengthWires {
    pub fn populate(&self, w: &mut WitnessFiller, bytes: &[u8]) {
        // Centralized population logic
    }
}
```

#### 4. Create Circuit Composition Helpers
```rust
// Proposed: Composition builder
pub struct CircuitPipeline {
    stages: Vec<Box<dyn StandardCircuit>>,
}

impl CircuitPipeline {
    pub fn add_stage<C: StandardCircuit>(mut self, circuit: C) -> Self {
        self.stages.push(Box::new(circuit));
        self
    }

    pub fn connect(&mut self, from_output: usize, to_input: usize) {
        // Wire connection logic
    }

    pub fn populate_sequential(&self, w: &mut WitnessFiller, inputs: Vec<Box<dyn Any>>) {
        // Coordinate population across stages
    }
}
```

### Migration Path

To avoid breaking existing code while improving consistency:

1. **Phase 1**: Add new standardized methods alongside existing ones
2. **Phase 2**: Mark old methods as deprecated
3. **Phase 3**: Migrate examples and tests to new patterns
4. **Phase 4**: Remove deprecated methods in next major version

This refactoring would significantly improve circuit composability and reduce the learning curve for new developers.

### The Function-Calling Analogy: Are Circuits Just Stateless Functions?

At first glance, circuit composition might seem like simple function composition. After all, circuits transform inputs to outputs with no internal state. So why is composition challenging? Let's explore whether circuits are truly just functions with wires as parameters, or if witness population fundamentally changes the model.

#### The Ideal: Circuits as Pure Functions

In an ideal world, circuits would compose like pure functions:

```rust
// Hypothetical pure function model
fn sha256(input: Vec<u64>) -> [u64; 4] {
    // Compute hash
    hash_result
}

fn rs256_verify(message_hash: [u64; 4], signature: Vec<u64>) -> bool {
    // Verify signature
    is_valid
}

// Simple composition
fn verify_signed_message(message: Vec<u64>, signature: Vec<u64>) -> bool {
    let hash = sha256(message);
    rs256_verify(hash, signature)
}
```

This is beautifully simple: outputs become inputs, no coordination needed.

#### The Reality: Wires and Witness Population

But circuits in Binius64 don't work this way. Instead of values, we have wires (references to future values), and computation happens in two separate phases:

```rust
// Phase 1: Circuit Construction (no values yet!)
fn build_sha256(b: &mut CircuitBuilder) -> Sha256Circuit {
    let input_wires = (0..MAX_LEN).map(|_| b.add_witness()).collect();
    let output_wires = [b.add_witness(); 4];

    // Add constraints that relate input_wires to output_wires
    // But we don't know the actual values yet!
    add_sha256_constraints(b, &input_wires, &output_wires);

    Sha256Circuit { input_wires, output_wires }
}

// Phase 2: Witness Population (actual values)
fn populate_sha256(circuit: &Sha256Circuit, w: &mut WitnessFiller, message: &[u8]) {
    // Now we have actual values to work with
    populate_input(w, &circuit.input_wires, message);
    // But wait - who populates output_wires?
    // The constraint system will compute them during evaluation!
}
```

#### Why This Breaks the Function Model

The function-calling analogy breaks down for several reasons:

**1. Split Personality: Construction vs Population**

Functions have a single execution phase. Circuits have two completely separate phases that happen at different times with different information available:

```rust
// Construction time: We know structure but not values
let hash_circuit = Sha256::new(builder);  // No message yet!

// Population time: We know values but can't change structure
hash_circuit.populate(w, actual_message);  // Can't add new wires!
```

**2. The Witness Population Dance**

Unlike function parameters that flow naturally, witness values must be carefully choreographed:

```rust
// Problem: Who populates what and when?
struct PipelineCircuit {
    sha256: Sha256Circuit,
    verifier: VerifierCircuit,
    // These wires connect the circuits, but who fills them?
    intermediate_hash: [Wire; 4],
}

impl PipelineCircuit {
    fn populate(&self, w: &mut WitnessFiller, message: &[u8], signature: &[u8]) {
        // sha256 needs its input
        self.sha256.populate_input(w, message);

        // But sha256's OUTPUT wires are verifier's INPUT wires!
        // Do we:
        // - Have sha256 populate them? (But it doesn't know the signature)
        // - Have verifier populate them? (But it doesn't know the message)
        // - Populate them here? (Breaking encapsulation)

        // The answer depends on whether intermediate_hash is:
        // - Computed by constraints (witness wires)
        // - Known in advance (input/output wires)
    }
}
```

**3. The Verification-Only Model (Why Outputs Need Population)**

Here's the surprising truth: **SHA256 circuits in Binius64 don't compute hashes - they verify them!** This is why outputs need population:

```rust
// SHA256 is a VERIFIER circuit, not a COMPUTER circuit
let sha256 = Sha256::new(builder, max_len, len, digest_wires, message_wires);

// It contains constraints that verify: SHA256(message) == digest
// But it doesn't compute digest from message!

// So you must:
sha256.populate_message(w, message);  // Provide the input
sha256.populate_digest(w, expected_hash);  // Provide the expected output

// The circuit then VERIFIES that SHA256(message) == expected_hash
// It doesn't COMPUTE the hash
```

This is fundamental to zero-knowledge proofs: circuits verify relationships, they don't compute results. The prover knows both inputs and outputs and proves they satisfy the relationship. This creates the wire "ownership" problem - both circuits need the same value populated, but neither computes it.

#### The Fundamental Mismatch

The core issue is that **circuits aren't really functions** - they're **constraint systems** that happen to have function-like interfaces. The witness population mechanism adds essential complexity because:

1. **Constraints compute values**: Some wires get their values from constraint evaluation, not direct population
2. **Timing matters**: Population order affects what values are available when
3. **Single assignment rule**: Each wire can only be written once, but may be read many times
4. **Separation of concerns**: The circuit that uses a value may not be the circuit that computes it

#### Can We Fix This?

Some approaches to make circuits more function-like:

**Option 1: Explicit Data Flow Types**

```rust
enum WireSource {
    Input,      // Populated externally
    Computed,   // Populated by constraint evaluation
    Constant,   // Known at construction time
}

struct TypedWire {
    wire: Wire,
    source: WireSource,
    owner: CircuitId,  // Who can write to this wire
}
```

**Option 2: Continuation-Passing Style**

```rust
impl Sha256Circuit {
    fn populate_with_continuation(
        &self,
        w: &mut WitnessFiller,
        input: &[u8],
        on_complete: impl FnOnce(&mut WitnessFiller, [u64; 4])
    ) {
        self.populate_input(w, input);
        // After evaluation completes...
        let hash = self.read_output(w);
        on_complete(w, hash);
    }
}
```

**Option 3: Builder Pattern with Explicit Wiring**

```rust
CircuitPipeline::new()
    .add_stage("sha256", Sha256::new)
    .add_stage("verify", Rs256::new)
    .connect("sha256.output", "verify.message_hash")
    .build(builder)
```

#### The Bottom Line

While it's tempting to think of circuits as functions where wires are just variables passed between them, **the witness population mechanism fundamentally changes the programming model**. The two-phase construction/population split, combined with the constraint evaluation system, creates a unique paradigm that requires its own patterns and best practices.

The challenge isn't just "wires as variables vs arguments" - it's that:
- **Construction** happens without knowing values
- **Population** happens without ability to change structure
- **Evaluation** happens implicitly between populations
- **Ownership** of wires is distributed and temporal

This is why circuit composition requires careful design patterns rather than simple function composition. The witness mechanism isn't an implementation detail - it's fundamental to how zero-knowledge proofs maintain their security properties while allowing efficient verification.

### A Better Design? The Input-Wire-Only Model

The REVIEW comment suggests an alternative design: circuits should take input wires and only populate their own constants. In theory:

```rust
// Hypothetical better design
struct Sha256Better {
    input_wires: Vec<Wire>,     // Provided by caller
    output_wires: [Wire; 4],    // Provided by caller
    // Circuit only manages internal constants
}

impl Sha256Better {
    fn new(builder: &CircuitBuilder, input: Vec<Wire>, output: [Wire; 4]) -> Self {
        // Add constraints connecting input to output
        // Only the circuit knows its internal algorithm
        Self { input_wires: input, output_wires: output }
    }
    
    fn populate(&self, w: &mut WitnessFiller) {
        // Only populate internal constants, not inputs/outputs
        // Inputs are populated by caller
        // Outputs are... wait, who computes them?
    }
}
```

This design has a fatal flaw: **circuits in ZK systems verify, they don't compute**. The output wires still need to be populated by someone who knows the correct output. The circuit can't compute it during population because:

1. **Population is value assignment, not computation**
2. **Constraints verify relationships, not compute results**
3. **The prover must know ALL values before verification**

So even with this design, you'd still need:
```rust
// Caller still needs to compute and populate outputs!
let hash = compute_sha256_externally(input_data);
populate_wires(w, output_wires, hash);  // Still needed!
```

The fundamental issue remains: **ZK circuits are verifiers, not computers**.

### Real-World Example: The SHA256 Chaining Problem

Let's examine a real test case from the codebase that perfectly illustrates these challenges. This test, aptly named `this_is_difficult`, attempts to compute SHA256(SHA256(data)) - a seemingly simple operation that reveals the full complexity of circuit composition:

```rust
#[test]
fn this_is_difficult() {
    let builder = CircuitBuilder::new();

    // Problem 1: Manual wire allocation for every intermediate value
    let input_0: [Wire; 10] = array::from_fn(|_| builder.add_witness());
    let output_0: [Wire; 4] = array::from_fn(|_| builder.add_witness());
    let input_1: [Wire; 4] = array::from_fn(|_| builder.add_witness());
    let output_1: [Wire; 4] = array::from_fn(|_| builder.add_witness());

    // Create two SHA256 circuits
    let sha256_0 = Sha256::new(&builder, 80, builder.add_constant_64(80),
                               output_0, input_0.to_vec());
    let sha256_1 = Sha256::new(&builder, 32, builder.add_constant_64(32),
                               output_1, input_1.to_vec());

    // Problem 2: Manual constraint connections
    let output_data = sha256_0.digest_to_le_wires(&builder);
    let input_data = sha256_1.message_to_le_wires(&builder);

    for i in 0..4 {
        builder.assert_eq("check intermediate hash", output_data[i], input_data[i]);
    }

    // Problem 3: Redundant witness population
    let mut filler = circuit.new_witness_filler();

    // Populate first SHA256
    sha256_0.populate_message(&mut filler, &block_header);
    let intermediate_hash: [u8; 32] = sha2::Sha256::digest(block_header).into();
    sha256_0.populate_digest(&mut filler, intermediate_hash);

    // Populate second SHA256 with THE SAME intermediate value
    sha256_1.populate_message(&mut filler, &intermediate_hash);
    sha256_1.populate_digest(&mut filler, final_hash);
}
```

#### Why Is This Difficult?

**The Conceptual Simplicity:**
```
block_header → SHA256 → intermediate → SHA256 → final_hash
```

**The Implementation Reality:**

1. **Wire Duplication at the Type System Level**
   ```
   output_0: [Wire; 4]  // SHA256_0 writes here (witness indices 10-13)
   input_1:  [Wire; 4]  // SHA256_1 reads here (witness indices 14-17)
   ```
   These are **distinct witness polynomial coefficients** in the constraint system. The SHA256 circuit constructor takes ownership of wire slices and has no mechanism to express "these wires are aliases." The type system enforces strict boundaries - SHA256_0 owns indices 10-13, SHA256_1 owns indices 14-17. There's no way to tell the compiler or constraint system that `w[10] == w[14]`, `w[11] == w[15]`, etc. without explicit constraints.

2. **Constraint Overhead for Wire Equality**
   ```rust
   for i in 0..4 {
       builder.assert_eq("check intermediate hash", output_data[i], input_data[i]);
   }
   ```
   Each `assert_eq` generates an AND constraint in the R1CS: `(output_0[i] ⊕ input_1[i]) & 1 = 0`. That's **4 additional gates** just to express that the output of one circuit equals the input of another. In a 64-bit word system, these constraints consume ~4x the baseline AND gate cost - pure overhead with no computational value, solely to work around the lack of wire aliasing.

3. **The Triple Population Requirement**

   The witness filler must receive three separate populations for the same 32-byte value:
   ```rust
   // Population 1: The actual input
   sha256_0.populate_message(&mut filler, &block_header);

   // Population 2: SHA256_0's output (computed externally!)
   let intermediate_hash = sha2::Sha256::digest(block_header).into();
   sha256_0.populate_digest(&mut filler, intermediate_hash);

   // Population 3: SHA256_1's input (same value as Population 2)
   sha256_1.populate_message(&mut filler, &intermediate_hash);
   ```

   Why? Because the SHA256 circuit contains internal constraints that verify the correctness of the hash computation. It needs both input AND output populated to satisfy its constraints. But since we're chaining SHA256s, the first's output IS the second's input, yet we must:
   - Compute the intermediate hash **outside the constraint system** using a separate SHA256 implementation
   - Populate it into witness indices 10-13 (as SHA256_0's digest)
   - Populate it AGAIN into witness indices 14-17 (as SHA256_1's message)
   - Add 4 equality constraints to ensure indices 10-13 equal indices 14-17

#### The Fundamental Architectural Mismatch

This exposes a deep architectural problem in how circuits are composed:

**The Constraint System is Declarative, Not Procedural**

The constraint system defines algebraic relationships between witness polynomial coefficients:
- `w[10] = SHA256_compress(w[0..10])` (simplified - actually ~25,000 constraints)
- `w[14] = w[10]` (our manual equality constraint)
- `w[18] = SHA256_compress(w[14..18])` (another ~25,000 constraints)

But it cannot express: "compute SHA256_0, then pipe its output to SHA256_1." The system has no concept of data flow or sequencing. All constraints exist simultaneously in the polynomial space.

**The Witness Population is Procedural, Not Declarative**

Meanwhile, witness population is purely imperative:
```rust
filler[wire_id] = value;  // One-shot assignment
```

The filler doesn't understand constraint dependencies. It can't deduce that `w[10]` should equal `w[14]`. It can't compute `w[10]` from `w[0..10]` using the SHA256 constraints - that's what the constraint VERIFIER does, not what the witness POPULATOR does.

**The Evaluation Model is Neither**

Circuit evaluation (constraint satisfaction checking) happens in a third model entirely:
1. All witnesses must be populated
2. All constraints are checked simultaneously
3. No intermediate computation happens - only verification

This creates an **impossible trinity**:
- **Construction** defines structure without values
- **Population** assigns values without computation
- **Evaluation** verifies relationships without assignment

#### The Missing Abstraction Layer

What's needed is a fourth layer that understands:
- **Wire Aliasing**: `output_0[i]` and `input_1[i]` are the same witness coefficient
- **Computed Witnesses**: Some wires are derived from others via constraint relationships
- **Data Flow Dependencies**: SHA256_1 depends on SHA256_0's output
- **Automatic Population Propagation**: Computing w[0..10] should automatically derive w[10..14]

Without this layer, every circuit composition requires:
- **2N wire declarations** (N for outputs, N for inputs)
- **N equality constraints** (pure overhead)
- **External computation** of all intermediate values
- **2N witness populations** (outputs and inputs separately)

For a pipeline of K circuits, this becomes O(K²) complexity in manual wiring, when it should be O(K).

The test name "this_is_difficult" understates the problem - it reveals that **circuit composition in Binius64 lacks fundamental abstractions for modular design**.

## Part 5: Circuit Composition Patterns

### Pipeline Pattern: Sequential Processing

The most common pattern chains circuits in sequence, where each stage processes the output of the previous:

```rust
/// Example: Signed Message Verification Pipeline
/// Flow: Message → SHA256 → RS256 Signature Verification
pub struct SignedMessagePipeline {
    message: FixedByteVec,
    sha256: Sha256,
    rs256: Rs256Verify,
}

impl SignedMessagePipeline {
    pub fn new(b: &mut CircuitBuilder, max_msg_len: usize) -> Self {
        // Stage 1: Message input
        let message = FixedByteVec::new_inout(b, max_msg_len);

        // Stage 2: Hash the message
        // Note: digest wires are intermediate, not input
        let digest: [Wire; 4] = array::from_fn(|_| b.add_witness());

        let sha256 = Sha256::new(
            &b.subcircuit("sha256"),  // Namespace for debugging
            max_msg_len,
            message.len,              // Variable length support
            digest,                   // Output wires
            message.data.clone(),     // Input wires (shared reference)
        );

        // Stage 3: Verify signature over hash
        let signature = FixedByteVec::new_inout(b, 256);
        let modulus = FixedByteVec::new_inout(b, 256);

        // RS256 needs the original message for padding verification
        // and uses the SHA256 digest internally
        let rs256 = Rs256Verify::new(
            &b.subcircuit("rs256"),
            message.clone(),          // Original message
            signature,                // RSA signature
            modulus,                  // Public key modulus
        );

        Self { message, sha256, rs256 }
    }
}
```

### Subcircuit Namespacing: Organizing Complex Applications

Use hierarchical namespaces to organize large applications:

```rust
/// Namespacing provides:
/// 1. Clear debugging output (constraint violations show namespace)
/// 2. Reusable component instantiation
/// 3. Logical organization of complex systems
pub fn build_complex_jwt_verifier(b: &mut CircuitBuilder) {
    // Top-level logical groups
    let auth = b.subcircuit("auth");
    let data = b.subcircuit("data_processing");

    // Authentication subsystems
    let jwt = auth.subcircuit("jwt");

    // JWT has three base64-encoded parts
    let header_b64 = jwt.subcircuit("header_decoder");
    let payload_b64 = jwt.subcircuit("payload_decoder");
    let signature_b64 = jwt.subcircuit("signature_decoder");

    // Build decoders with clear namespace hierarchy
    // Errors will show: "auth.jwt.header_decoder: constraint violation"
    let header_decoder = Base64UrlSafe::new(&header_b64, /* ... */);
    let payload_decoder = Base64UrlSafe::new(&payload_b64, /* ... */);
    let signature_decoder = Base64UrlSafe::new(&signature_b64, /* ... */);

    // Data processing can have its own hierarchy
    let transform = data.subcircuit("transform");
    let validate = data.subcircuit("validate");

    // Benefits:
    // - Constraint #1234 fails → "auth.jwt.payload_decoder.padding_check"
    // - Can instantiate multiple validators with different namespaces
    // - Circuit statistics show breakdown by subsystem
}
```

## Part 5: Case Study - JWT Verifier

Let's build a complete JWT verifier showing circuit composition in practice:

```rust
/// JWT Verification Pipeline:
/// 1. Base64 decode three components (header.payload.signature)
/// 2. Parse and validate JSON claims
/// 3. Reconstruct signing input (header + "." + payload)
/// 4. Verify RSA signature
pub struct SimpleJwtVerifier {
    // === Public Inputs ===
    jwt_header_b64: FixedByteVec,     // Base64-encoded header
    jwt_payload_b64: FixedByteVec,    // Base64-encoded payload
    jwt_signature_b64: FixedByteVec,  // Base64-encoded signature
    rsa_modulus: FixedByteVec,        // RSA public key (2048-bit)
    expected_issuer: FixedByteVec,    // Expected "iss" claim value

    // === Subcircuits ===
    header_decoder: Base64UrlSafe,    // Converts base64 → bytes
    payload_decoder: Base64UrlSafe,
    signature_decoder: Base64UrlSafe,
    payload_parser: JwtClaims,        // Validates JSON claims
    signing_payload_concat: Concat,   // Rebuilds signed message
    signature_verifier: Rs256Verify,  // RSA-SHA256 verification
}

impl SimpleJwtVerifier {
    pub fn new(b: &mut CircuitBuilder) -> Self {
        // Circuit configuration (compile-time bounds)
        const MAX_HEADER: usize = 256;    // Typical: {"alg":"RS256","typ":"JWT"}
        const MAX_PAYLOAD: usize = 512;   // User claims
        const MAX_SIGNATURE: usize = 256; // 2048-bit RSA = 256 bytes
        const MAX_ISSUER: usize = 64;     // e.g., "accounts.google.com"

        // === Create public input wires ===
        let jwt_header_b64 = FixedByteVec::new_inout(b, MAX_HEADER);
        let jwt_payload_b64 = FixedByteVec::new_inout(b, MAX_PAYLOAD);
        let jwt_signature_b64 = FixedByteVec::new_inout(b, MAX_SIGNATURE);
        let rsa_modulus = FixedByteVec::new_inout(b, 256);
        let expected_issuer = FixedByteVec::new_inout(b, MAX_ISSUER);

        // === Stage 1: Base64 Decoding ===
        // Create intermediate wires for decoded data
        let jwt_header = FixedByteVec::new_witness(b, MAX_HEADER);
        let jwt_payload = FixedByteVec::new_witness(b, MAX_PAYLOAD);
        let jwt_signature = FixedByteVec::new_witness(b, MAX_SIGNATURE);

        // Base64 decoders verify: encode(decoded) == input
        // This ensures the decoded values are correct
        let header_decoder = Base64UrlSafe::new(
            &b.subcircuit("decode_header"),
            MAX_HEADER,
            jwt_header.data.clone(),      // Output: decoded bytes
            jwt_header_b64.data.clone(),  // Input: base64 string
            jwt_header.len,                // Output length
        );

        let payload_decoder = Base64UrlSafe::new(
            &b.subcircuit("decode_payload"),
            MAX_PAYLOAD,
            jwt_payload.data.clone(),
            jwt_payload_b64.data.clone(),
            jwt_payload.len,
        );

        let signature_decoder = Base64UrlSafe::new(
            &b.subcircuit("decode_signature"),
            MAX_SIGNATURE,
            jwt_signature.data.clone(),
            jwt_signature_b64.data.clone(),
            jwt_signature.len,
        );

        // === Stage 2: Claims Validation ===
        // Verify the JWT payload contains expected issuer
        let issuer_attribute = Attribute {
            name: "iss",
            len_value: expected_issuer.len,      // Variable length
            value: expected_issuer.data.clone(), // Expected value
        };

        // This circuit verifies jwt_payload contains: "iss":"<expected_issuer>"
        let payload_parser = JwtClaims::new(
            &b.subcircuit("parse_claims"),
            MAX_PAYLOAD,
            jwt_payload.len,
            jwt_payload.data.clone(),
            vec![issuer_attribute],  // Can verify multiple claims
        );

        // === Stage 3: Signature Verification ===
        // JWT signing input is: base64(header) + "." + base64(payload)
        // Note: We use the base64 versions, not decoded

        let max_signing_len = MAX_HEADER + 1 + MAX_PAYLOAD;
        let signing_payload = (0..max_signing_len / 8)
            .map(|_| b.add_witness())
            .collect();
        let signing_len = b.add_witness();

        // Create the dot separator constant
        let dot_wire = b.add_constant_64(0x2E); // ASCII '.'

        // Concatenate: header.payload
        let signing_payload_concat = Concat::new(
            &b.subcircuit("signing_payload"),
            max_signing_len,
            signing_len,                    // Output: total length
            signing_payload,                 // Output: concatenated data
            vec![
                Term {
                    data: jwt_header_b64.data.clone(),
                    len: jwt_header_b64.len,
                    max_len: MAX_HEADER,
                },
                Term {
                    data: vec![dot_wire],
                    len: b.add_constant_64(1),  // Dot is always 1 byte
                    max_len: 8,                 // Minimum wire size
                },
                Term {
                    data: jwt_payload_b64.data.clone(),
                    len: jwt_payload_b64.len,
                    max_len: MAX_PAYLOAD,
                },
            ],
        );

        // Create message structure for RS256 verifier
        let message = FixedByteVec {
            len: signing_len,
            data: signing_payload_concat.joined.clone(),
            max_len: max_signing_len,
        };

        // RS256 verifier:
        // 1. Computes SHA256(message)
        // 2. Verifies RSA signature matches
        // 3. ~50K AND constraints + 256 MUL constraints
        let signature_verifier = Rs256Verify::new(
            &b.subcircuit("rs256_verify"),
            message,
            jwt_signature.clone(),
            rsa_modulus.clone(),
        );

        Self {
            jwt_header_b64,
            jwt_payload_b64,
            jwt_signature_b64,
            rsa_modulus,
            expected_issuer,
            header_decoder,
            payload_decoder,
            signature_decoder,
            payload_parser,
            signing_payload_concat,
            signature_verifier,
        }
    }

    pub fn populate_witness(
        &self,
        w: &mut WitnessFiller,
        jwt: &str,
        rsa_modulus: &[u8],
        expected_issuer: &str,
    ) {
        // === Parse JWT string ===
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have three parts");

        // === Populate public inputs ===
        // These are the actual values the verifier will check
        self.jwt_header_b64.populate(w, parts[0].as_bytes());
        self.jwt_payload_b64.populate(w, parts[1].as_bytes());
        self.jwt_signature_b64.populate(w, parts[2].as_bytes());
        self.rsa_modulus.populate(w, rsa_modulus);
        self.expected_issuer.populate(w, expected_issuer.as_bytes());

        // === Compute intermediate witnesses ===
        // The circuit needs decoded values for constraint checking
        // In a real implementation, these would be computed by the prover

        // Note: The circuit verifies these decodings are correct
        // We can't provide wrong values here - constraints will fail
    }
}
```

## Part 6: Common Pitfalls and Solutions

### Wire Aliasing Issues

**Problem**: Multiple circuits trying to write to the same wire.

```rust
// WRONG: Both circuits think they own output_wire
let output_wire = b.add_witness();
let circuit_a = CircuitA::new(b, output_wire);
let circuit_b = CircuitB::new(b, output_wire);  // Will fail!
```

**Solution**: Create separate wires and add equality constraint if needed.

```rust
// CORRECT: Each circuit has its own output
let output_a = b.add_witness();
let output_b = b.add_witness();
let circuit_a = CircuitA::new(b, output_a);
let circuit_b = CircuitB::new(b, output_b);

// If outputs must be equal, add constraint
b.assert_eq("outputs_must_match", output_a, output_b);
```

### Zero Padding Confusion

**Problem**: Forgetting that unused bytes must be zero in FixedByteVec.

```rust
// WRONG: Garbage data in unused portion
let mut data = vec![0xFFu8; MAX_LEN];  // Pre-filled with 0xFF
data[..actual_len].copy_from_slice(&input);
// data[actual_len..] still contains 0xFF!
```

**Solution**: Always zero unused bytes.

```rust
// CORRECT: Explicitly zero unused portion
let mut data = vec![0u8; MAX_LEN];  // Pre-filled with zeros
data[..actual_len].copy_from_slice(&input);
// data[actual_len..] is already zero

// Or use the utility function which handles this:
pack_bytes_into_wires_le(w, &wires, &input);  // Auto-zeros unused
```

## Part 7: Testing and Development Patterns

### The ExampleCircuit Pattern

The `crates/examples` directory provides a standardized framework for building testable circuits:

```rust
/// Separation of concerns:
/// - Params: Compile-time circuit configuration
/// - Instance: Runtime test data
/// - Build: Circuit construction logic
/// - Populate: Witness generation logic
pub trait ExampleCircuit: Sized {
    type Params: clap::Args;     // CLI arguments for configuration
    type Instance: clap::Args;   // CLI arguments for test data

    fn build(params: Self::Params, builder: &mut CircuitBuilder) -> Result<Self>;
    fn populate_witness(&self, instance: Self::Instance, filler: &mut WitnessFiller) -> Result<()>;
}
```

This pattern enables:
- Automatic CLI generation with subcommands
- Parameter sweeping for optimization
- Regression testing with snapshots
- Clear separation of circuit structure from test data

### Snapshot Testing

Track circuit complexity over time:

```rust
#[test]
fn test_circuit_complexity_unchanged() {
    let mut builder = CircuitBuilder::new();
    let circuit = MyCircuit::new(&mut builder);
    let built = builder.build();

    // Compares against saved snapshot
    // Fails if constraint count changes unexpectedly
    snapshot::check_snapshot("my_circuit", &built).unwrap();
}
```

Use the CLI to manage snapshots:
```bash
# Check current circuit matches snapshot
cargo run --example my_circuit check-snapshot

# Update snapshot after intentional changes
cargo run --example my_circuit bless-snapshot

# View circuit statistics
cargo run --example my_circuit stat
```

### Development Workflow

1. **Start with clear interfaces**: Define wire inputs/outputs before implementation
2. **Build incrementally**: Test each subcircuit in isolation first
3. **Use namespacing**: Helps identify which subcircuit has issues
4. **Verify witness flow**: Draw dependency graph for complex circuits
5. **Profile constraints**: Use `stat` command to identify expensive operations

## Part 8: Performance Considerations

### When to Share vs Duplicate Circuits

**Share circuits** when you have multiple inputs that need the same operation and can serialize processing:

```rust
// Shared hasher with multiplexer - saves constraints
pub struct SharedHasher {
    messages: Vec<FixedByteVec>,
    selector: Wire,
    hasher: Sha256,  // Single instance
}
```

**Duplicate circuits** when you need true parallel processing or different configurations:

```rust
// Separate hashers for independent data streams
pub struct ParallelHashers {
    stream_a_hasher: Sha256,  // Independent processing
    stream_b_hasher: Sha256,  // Can have different parameters
}
```

### Constraint Cost Analysis

Use the Binius64 cost model to optimize:
- AND constraint: 1x cost
- MUL constraint: ~200x cost
- Witness commitment: ~0.2x cost

Focus optimization efforts on reducing MUL constraints first, then AND constraints, and worry about witness count last.

## Conclusion

Successful circuit composition requires:

1. **Understanding witness dependencies**: Know your data flow graph
2. **Managing wire lifetime**: Each wire written once, read many times
3. **Choosing appropriate patterns**: Pipeline, sharing, or duplication
4. **Testing systematically**: Unit → Integration → System tests
5. **Profiling regularly**: Track constraint counts and identify bottlenecks

## Further Reading

- `tutorial_control_flow.md`: Control flow patterns in circuits
- `tutorial_theory.md`: Theoretical foundations of Binius64
- `circuit_design.md`: Low-level circuit design principles
- `rust_circuits.md`: Rust implementation conventions

## Example Code

Complete working examples can be found in:
- `crates/frontend/src/circuits/zklogin.rs`: Full JWT verification
- `crates/frontend/src/circuits/rs256.rs`: RSA signature verification
- `crates/examples/`: CLI framework and testing patterns

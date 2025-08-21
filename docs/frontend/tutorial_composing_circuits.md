# Composing Circuits: Building Applications from Components

This tutorial covers how to compose multiple circuits into complete applications in Binius64, demonstrating patterns for circuit interaction, data flow, and witness management.

## Part 1: Introduction to Circuit Composition

### Why Circuit Composition Matters

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

Understanding witness management is crucial because it's where most circuit composition errors occur. The witness lifecycle has three phases:

1. **Declaration Phase** (Circuit Building):
   ```rust
   let input = builder.add_witness();      // Declare a witness wire
   let output = builder.add_witness();     // Declare another
   ```

2. **Population Phase** (Witness Filling):
   ```rust
   w[input] = Word(42);                    // Assign actual value
   // output will be computed by circuit evaluation
   ```

3. **Evaluation Phase** (Circuit Execution):
   ```rust
   circuit.populate_wire_witness(&mut w)?; // Compute all intermediate values
   ```

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

### The Wire Packing Challenge

Binius64 uses 64-bit wires, but real-world data comes in various formats:
- **User input**: UTF-8 strings
- **Network data**: Big-endian byte streams
- **Cryptographic values**: Multi-precision integers
- **File formats**: Base64, JSON, Protocol Buffers

Wire packing is the process of converting these formats into 64-bit wire values that circuits can process.

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

This inconsistency creates composition problems:

```rust
// Problem 1: Unclear data flow
let sha256 = Sha256::new(&builder, ...);
let rs256 = Rs256Verify::new(&builder, message, ...);
// Which circuit "owns" the message witness population?
// Do I call sha256.populate_message() or rs256.populate_message()?

// Problem 2: Hidden dependencies
let base64 = Base64UrlSafe::new(&builder, decoded, encoded, len);
// Base64 doesn't populate anything - you must know to populate
// decoded, encoded, and len yourself in the right order

// Problem 3: Duplicate population logic
impl JwtVerifier {
    fn populate_witness(&self, w: &mut WitnessFiller, jwt: &str) {
        // Must manually coordinate population across subcircuits
        self.header_b64.populate_bytes_le(w, header);
        // But base64 decoder has no populate method!
        // Must manually populate its wires...
        w[self.header_decoder.len_decoded] = Word(header.len() as u64);
        pack_bytes_into_wires_le(w, &self.header_decoder.decoded, header);
    }
}
```

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
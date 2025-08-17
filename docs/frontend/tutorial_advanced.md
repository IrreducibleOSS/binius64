# Binius-64 Circuit Writing Tutorial: Advanced Level

This tutorial covers production-ready cryptographic circuits including SHA-256, RSA verification, and complex protocols like ZKLogin.

## Advanced Circuit Architecture

When building production circuits, we need to consider:
- Constraint optimization (minimizing prover work)
- Modularity and reusability
- Proper abstraction layers
- Thorough testing strategies

## Example 1: SHA-256 Implementation

SHA-256 is a cornerstone of many cryptographic protocols. Let's compare regular Rust with the circuit version:

### Rust Version
```rust
use sha2::{Sha256, Digest};

// Regular Rust - using the sha2 crate
fn compute_sha256(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

// Manual implementation showing the structure
struct Sha256State {
    state: [u32; 8],
    buffer: Vec<u8>,
    total_len: u64,
}

impl Sha256State {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: Vec::new(),
            total_len: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.total_len += data.len() as u64;
        
        // Process complete 512-bit blocks
        while self.buffer.len() >= 64 {
            let block = &self.buffer[0..64];
            self.compress_block(block);
            self.buffer.drain(0..64);
        }
    }
    
    fn finalize(mut self) -> [u8; 32] {
        // Add padding and process final block(s)
        self.add_padding();
        self.state_to_bytes()
    }
}
```

### Circuit Version - SHA-256 Overview

```rust
use binius_core::word::Word;
use crate::compiler::{CircuitBuilder, Wire};

pub struct Sha256 {
    pub max_len: usize,
    pub len: Wire,
    pub digest: [Wire; 4],      // 256 bits as 4x64-bit words
    pub message: Vec<Wire>,     // Input message
    compress: Vec<Compress>,    // Compression gadgets
}
```

The circuit implementation differs in these key ways:
1. **Fixed structure**: Must allocate for `max_len` upfront (Rust can grow dynamically)
2. **No branching**: Processes all blocks even if unused (Rust stops at actual length)
3. **Witness-based**: Length is a witness value verified by constraints
4. **Parallel packing**: Uses 64-bit words to pack two SHA-256 words

### Key Implementation Details

```rust
impl Sha256 {
    pub fn new(
        builder: &CircuitBuilder,
        max_len: usize,
        len: Wire,
        digest: [Wire; 4],
        message: Vec<Wire>,
    ) -> Self {
        // Step 1: Validate constraints
        assert!(max_len > 0);
        assert!(max_len.saturating_mul(8) < (1u64 << 32) as usize);
        
        // Step 2: Length validation
        let max_len_wire = builder.add_constant_64(max_len as u64);
        let too_large = builder.icmp_ult(max_len_wire, len);
        builder.assert_0("length_check", too_large);
        
        // Step 3: Setup compression chain
        let n_blocks = (max_len + 9).div_ceil(64);
        let mut compress = Vec::with_capacity(n_blocks);
        
        // Initialize with SHA-256 IV
        let mut state = [
            builder.add_constant_64(0x6a09e667bb67ae85),
            builder.add_constant_64(0x3c6ef372a54ff53a),
            builder.add_constant_64(0x510e527f9b05688c),
            builder.add_constant_64(0x1f83d9ab5be0cd19),
        ];
        
        // Chain compressions
        for block_idx in 0..n_blocks {
            let block = extract_block(builder, &message, block_idx);
            let compress_gadget = Compress::new(
                &builder.subcircuit(format!("compress[{}]", block_idx)),
                state,
                block,
            );
            state = compress_gadget.output_state;
            compress.push(compress_gadget);
        }
        
        // Verify final digest
        for i in 0..4 {
            builder.assert_eq(
                format!("digest[{}]", i),
                state[i],
                digest[i]
            );
        }
        
        Self { max_len, len, digest, message, compress }
    }
}
```

### SHA-256 Compression Function

Let's compare the compression function implementations:

#### Rust Version
```rust
// Regular Rust compression function
fn compress_block(&mut self, block: &[u8]) {
    // Convert bytes to 32-bit words (big-endian)
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i*4], block[i*4+1], block[i*4+2], block[i*4+3]
        ]);
    }
    
    // Message schedule expansion
    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    
    // Working variables
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
    
    // 64 rounds
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    
    // Update state
    self.state[0] = self.state[0].wrapping_add(a);
    self.state[1] = self.state[1].wrapping_add(b);
    // ... etc
}
```

#### Circuit Version

The circuit version must handle everything without branching:

```rust
pub struct Compress {
    pub input_state: [Wire; 8],
    pub output_state: [Wire; 8],
    message_schedule: [Wire; 64],
}

impl Compress {
    fn new(
        b: &CircuitBuilder,
        state: [Wire; 8],
        block: [Wire; 16],
    ) -> Self {
        // Message schedule expansion
        let mut w = [b.add_constant(Word::ZERO); 64];
        
        // First 16 words come from input
        for i in 0..16 {
            w[i] = block[i];
        }
        
        // Expand to 64 words
        for i in 16..64 {
            let s0 = sigma0(b, w[i-15]);
            let s1 = sigma1(b, w[i-2]);
            w[i] = b.iadd_32(
                b.iadd_32(w[i-16], s0),
                b.iadd_32(w[i-7], s1)
            );
        }
        
        // 64 rounds of compression
        let mut a = state[0];
        let mut b = state[1];
        // ... etc for c-h
        
        for round in 0..64 {
            let ch = choice(b, e, f, g);
            let maj = majority(b, a, b, c);
            let s0 = big_sigma0(b, a);
            let s1 = big_sigma1(b, e);
            
            let temp1 = b.iadd_32(
                h,
                b.iadd_32(s1, b.iadd_32(ch, b.iadd_32(K[round], w[round])))
            );
            let temp2 = b.iadd_32(s0, maj);
            
            h = g;
            g = f;
            f = e;
            e = b.iadd_32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = b.iadd_32(temp1, temp2);
        }
        
        // Add to initial state
        let output_state = [
            b.iadd_32(state[0], a),
            b.iadd_32(state[1], b),
            // ... etc
        ];
        
        Self { input_state: state, output_state, message_schedule: w }
    }
}
```

### Key Differences:
- **Rust**: Uses `wrapping_add` for modular arithmetic, native `rotate_right` operations
- **Circuit**: Must use circuit operations (`iadd_32`, `rotr_32`), each creating constraints
- **Circuit Insight**: Every operation in the circuit creates constraints that will be verified, while Rust just executes the operations directly

### Optimization: Parallel Word Packing

Binius-64 packs two 32-bit SHA-256 words into one 64-bit wire using XOR:

```rust
fn pack_sha256_words(b: &CircuitBuilder, lo: u32, hi: u32) -> Wire {
    let lo_wire = b.add_constant_64(lo as u64);
    let hi_wire = b.add_constant_64((hi as u64) << 32);
    b.bxor(lo_wire, hi_wire)
}

// This allows processing two SHA-256 operations in parallel!
```

## Example 2: RSA Signature Verification (RS256)

RSA verification in ZK is challenging due to bignum arithmetic. Let's compare approaches:

### Rust Version
```rust
use rsa::{RsaPublicKey, PaddingScheme, PublicKey};
use sha2::{Sha256, Digest};

// Regular Rust - using rsa crate
fn verify_rsa_signature(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    // Hash the message
    let digest = Sha256::digest(message);
    
    // Verify with PKCS#1 v1.5 padding
    let padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(rsa::Hash::SHA2_256),
    };
    
    public_key.verify(padding, &digest, signature)?;
    Ok(true)
}

// Manual implementation showing the math
fn verify_rsa_manual(
    n: &BigUint,  // modulus
    e: &BigUint,  // public exponent (usually 65537)
    message: &[u8],
    signature: &[u8],
) -> bool {
    // Convert signature to BigUint
    let sig = BigUint::from_bytes_be(signature);
    
    // Compute signature^e mod n
    let decrypted = sig.modpow(e, n);
    
    // Verify PKCS#1 v1.5 padding structure
    let decrypted_bytes = decrypted.to_bytes_be();
    if decrypted_bytes[0] != 0x00 || decrypted_bytes[1] != 0x01 {
        return false;
    }
    
    // Find 0x00 separator after padding
    let separator_pos = decrypted_bytes[2..].iter()
        .position(|&b| b == 0x00)
        .map(|p| p + 2);
    
    if separator_pos.is_none() {
        return false;
    }
    
    // Extract and verify digest
    let digest_start = separator_pos.unwrap() + 1;
    let extracted_digest = &decrypted_bytes[digest_start..];
    let expected_digest = Sha256::digest(message);
    
    extracted_digest == expected_digest.as_slice()
}
```

### Circuit Version

The circuit must handle bignum arithmetic without native big integer support:

```rust
pub struct Rs256Verify {
    /// RSA public key (up to 4096 bits)
    pub rsa_n: Vec<Wire>,
    
    /// Message to verify
    pub message: Vec<Wire>,
    pub len_message: Wire,
    
    /// Signature
    pub signature: Vec<Wire>,
    
    /// Internal gadgets
    sha256: Sha256,
    pkcs1_verify: Pkcs1Verify,
    modexp: ModularExponentiation,
}

impl Rs256Verify {
    pub fn new(
        b: &CircuitBuilder,
        max_message_len: usize,
        rsa_key_bits: usize,
    ) -> Self {
        // Step 1: Hash the message
        let sha256 = Sha256::new(
            &b.subcircuit("sha256"),
            max_message_len,
            len_message,
            digest_wires,
            message,
        );
        
        // Step 2: Verify PKCS#1 v1.5 padding
        let pkcs1 = Pkcs1Verify::new(
            &b.subcircuit("pkcs1"),
            &sha256.digest,
            rsa_key_bits,
        );
        
        // Step 3: Modular exponentiation (signature^e mod n)
        let modexp = ModularExponentiation::new(
            &b.subcircuit("modexp"),
            signature,
            e_wire,  // Usually 65537
            rsa_n,
            pkcs1.padded_hash,
        );
        
        Self { rsa_n, message, len_message, signature, sha256, pkcs1_verify, modexp }
    }
}
```

### Key Differences:
- **Rust**: Uses native `BigUint` type with built-in `modpow` operation
- **Circuit**: Must implement bignum arithmetic using 64-bit word arrays
- **Circuit Insight**: Modular exponentiation is extremely expensive in circuits (thousands of MUL constraints), so we use hints where the prover provides intermediate values that are then verified

### Bignum Arithmetic

Let's compare how bignum operations work:

#### Rust Version
```rust
use num_bigint::BigUint;

// Regular Rust with BigUint
fn bignum_multiply(a: &BigUint, b: &BigUint) -> BigUint {
    a * b  // Simple operator overloading
}

fn bignum_mod_reduce(value: &BigUint, modulus: &BigUint) -> BigUint {
    value % modulus  // Built-in modulo operation
}

// Manual implementation showing the algorithm
fn multiply_limbs(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = vec![0u64; a.len() + b.len()];
    
    for (i, &a_limb) in a.iter().enumerate() {
        let mut carry = 0u128;
        
        for (j, &b_limb) in b.iter().enumerate() {
            let product = a_limb as u128 * b_limb as u128;
            let sum = result[i + j] as u128 + product + carry;
            
            result[i + j] = sum as u64;
            carry = sum >> 64;
        }
        
        if carry > 0 {
            result[i + b.len()] = carry as u64;
        }
    }
    
    result
}
```

#### Circuit Version

Binius-64 provides efficient bignum operations using constraints:

```rust
pub struct BigUint {
    /// Little-endian limbs (64-bit words)
    pub limbs: Vec<Wire>,
}

impl BigUint {
    /// Multiplication: a * b = (hi, lo)
    pub fn mul(
        b: &CircuitBuilder,
        a: &[Wire],
        b_val: &[Wire],
    ) -> (Vec<Wire>, Vec<Wire>) {
        let n = a.len();
        let m = b_val.len();
        let result_len = n + m;
        
        let mut result = vec![b.add_internal(); result_len];
        
        // School-book multiplication with carry propagation
        for i in 0..n {
            let mut carry = b.add_constant(Word::ZERO);
            
            for j in 0..m {
                // 64x64 -> 128 bit multiplication (MUL constraint)
                let (lo, hi) = b.imul(a[i], b_val[j]);
                
                // Add to result with carry (AND constraints)
                let (sum1, carry1) = b.iadd_cin_cout(result[i+j], lo, carry);
                let (sum2, carry2) = b.iadd_cin_cout(
                    result[i+j+1], 
                    hi, 
                    carry1
                );
                
                result[i+j] = sum1;
                result[i+j+1] = sum2;
                carry = carry2;
            }
        }
        
        // Split into high and low parts
        (result[0..n].to_vec(), result[n..].to_vec())
    }
    
    /// Modular reduction using hints
    pub fn mod_reduce(
        b: &CircuitBuilder,
        value: &[Wire],
        modulus: &[Wire],
    ) -> Vec<Wire> {
        // Prover provides quotient and remainder as hints
        let (q, r) = b.biguint_divide_hint(value, modulus);
        
        // Verify: value = q * modulus + r
        let (q_m_lo, q_m_hi) = Self::mul(b, &q, modulus);
        let reconstructed = Self::add_with_carry(b, &q_m_lo, &r);
        
        // Assert reconstruction matches original
        for i in 0..value.len() {
            b.assert_eq(
                format!("mod_check[{}]", i),
                reconstructed[i],
                value[i]
            );
        }
        
        // Verify r < modulus
        let cmp = Self::compare(b, &r, modulus);
        b.assert_0("remainder_bound", cmp);
        
        r
    }
}
```

### Key Differences:
- **Rust**: Native 128-bit intermediate values for overflow handling
- **Circuit**: Must track carries explicitly using circuit operations
- **Circuit Insight**: Division is too expensive to compute in-circuit (would require thousands of constraints), so we use a hint-and-verify pattern where the prover provides the result and we only verify it's correct

## Example 3: ZKLogin - A Complete Protocol

ZKLogin demonstrates how to compose multiple advanced gadgets into a complete protocol:

### Rust Version
```rust
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,    // Subject (user ID)
    aud: String,    // Audience
    iss: String,    // Issuer
    nonce: String,  // Ephemeral nonce
    exp: usize,     // Expiration time
}

// Regular Rust implementation
fn verify_zklogin(
    jwt_token: &str,
    rsa_public_key: &[u8],
    expected_zkaddr: &[u8; 32],
    salt: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    // Step 1: Decode and verify JWT
    let header = decode_header(jwt_token)?;
    let decoding_key = DecodingKey::from_rsa_pem(rsa_public_key)?;
    
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["expected_audience"]);
    
    let token_data = decode::<Claims>(jwt_token, &decoding_key, &validation)?;
    let claims = token_data.claims;
    
    // Step 2: Compute zkaddr = SHA256(sub || aud || iss || salt)
    let mut hasher = Sha256::new();
    hasher.update(claims.sub.as_bytes());
    hasher.update(claims.aud.as_bytes());
    hasher.update(claims.iss.as_bytes());
    hasher.update(salt);
    let computed_zkaddr = hasher.finalize();
    
    // Step 3: Verify zkaddr matches
    if computed_zkaddr.as_slice() != expected_zkaddr {
        return Ok(false);
    }
    
    // Step 4: Verify nonce (in real implementation, check ephemeral signature)
    // This would involve verifying a signature over the nonce
    
    Ok(true)
}

// Manual JWT parsing for comparison
fn parse_jwt_manual(jwt: &str) -> Result<(String, String, Vec<u8>), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".into());
    }
    
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];
    
    // Decode from base64url
    let header = base64_url::decode(header_b64)?;
    let payload = base64_url::decode(payload_b64)?;
    let signature = base64_url::decode(signature_b64)?;
    
    Ok((
        String::from_utf8(header)?,
        String::from_utf8(payload)?,
        signature,
    ))
}
```

### Circuit Version

The circuit must handle all parsing and verification without external libraries:

```rust
pub struct ZkLogin {
    // Claims extracted from JWT
    pub sub: FixedByteVec,
    pub aud: FixedByteVec,
    pub iss: FixedByteVec,
    
    // zkaddr = SHA256(sub || aud || iss || salt)
    pub zkaddr: [Wire; 4],
    
    // JWT components
    pub jwt_header: JwtClaims,
    pub jwt_payload: JwtClaims,
    pub jwt_signature_verify: Rs256Verify,
    
    // Nonce verification
    pub nonce_sha256: Sha256,
}

impl ZkLogin {
    pub fn new(b: &CircuitBuilder, config: Config) -> Self {
        // Step 1: Decode base64 JWT parts
        let header_decoder = Base64UrlSafe::new(
            &b.subcircuit("decode_header"),
            config.max_len_json_jwt_header,
            jwt_header_bytes,
            base64_jwt_header,
            len_jwt_header,
        );
        
        // Step 2: Parse JWT claims
        let jwt_claims = JwtClaims::new(
            &b.subcircuit("parse_claims"),
            &jwt_payload_bytes,
            vec![
                Attribute::new("sub", sub.data.clone()),
                Attribute::new("aud", aud.data.clone()),
                Attribute::new("iss", iss.data.clone()),
                Attribute::new("nonce", nonce.data.clone()),
            ],
        );
        
        // Step 3: Verify JWT signature
        let jwt_verify = Rs256Verify::new(
            &b.subcircuit("verify_jwt"),
            signed_jwt_len,
            &signed_jwt,
            &jwt_signature,
            &rsa_n,
        );
        
        // Step 4: Compute zkaddr
        let zkaddr_input = Concat::new(
            &b.subcircuit("zkaddr_concat"),
            vec![
                Term { data: sub.data.clone(), len: sub.len, max_len: config.max_len_jwt_sub },
                Term { data: aud.data.clone(), len: aud.len, max_len: config.max_len_jwt_aud },
                Term { data: iss.data.clone(), len: iss.len, max_len: config.max_len_jwt_iss },
                Term { data: salt.data.clone(), len: salt.len, max_len: config.max_len_salt },
            ],
        );
        
        let zkaddr_sha = Sha256::new(
            &b.subcircuit("zkaddr_sha256"),
            zkaddr_input.max_n_joined,
            zkaddr_input.len_joined,
            zkaddr,
            zkaddr_input.joined,
        );
        
        // Step 5: Verify ephemeral signature
        let eph_verify = verify_ephemeral_signature(b, &config);
        
        Self { sub, aud, iss, zkaddr, jwt_header, jwt_payload, jwt_signature_verify, ... }
    }
}
```

### Key Differences:
- **Rust**: Can use libraries like `jsonwebtoken` for JWT parsing and validation
- **Circuit**: Must implement JWT parsing, base64 decoding, and JSON extraction from scratch
- **Circuit Insight**: The circuit processes the entire maximum-length JWT even if the actual JWT is shorter, using masking to handle variable-length data. This is why ZKLogin circuits can be very large (hundreds of thousands of constraints)

## Performance Optimization Strategies

### 1. Constraint Count Analysis

Always measure your constraint usage:

```rust
let circuit = builder.build();
println!("AND constraints: {}", circuit.num_and_constraints());
println!("MUL constraints: {}", circuit.num_mul_constraints());
println!("Total witness size: {}", circuit.num_witness_wires());

// Approximate prover cost
let cost = circuit.num_and_constraints() + 
           8 * circuit.num_mul_constraints() + 
           circuit.num_witness_wires() / 5;
```

### 2. Hint-Based Optimization

For expensive operations, use hints that the prover provides:

#### Rust Version
```rust
// Regular Rust - direct computation
fn divide_biguint(dividend: &BigUint, divisor: &BigUint) -> (BigUint, BigUint) {
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    (quotient, remainder)
}
```

#### Circuit Version
```rust
// Circuit - hint and verify pattern
fn divide_with_hint(
    builder: &CircuitBuilder,
    dividend: &[Wire],
    divisor: &[Wire],
) -> (Vec<Wire>, Vec<Wire>) {
    // Prover computes division outside circuit (like Rust version)
    let (quotient, remainder) = builder.biguint_divide_hint(dividend, divisor);
    
    // Circuit only verifies: dividend = quotient * divisor + remainder
    verify_division(builder, dividend, divisor, &quotient, &remainder);
    
    (quotient, remainder)
}

fn verify_division(
    builder: &CircuitBuilder,
    dividend: &[Wire],
    divisor: &[Wire],
    quotient: &[Wire],
    remainder: &[Wire],
) {
    // Verify: dividend = quotient * divisor + remainder
    let product = BigUint::mul(builder, quotient, divisor);
    let reconstructed = BigUint::add(builder, &product, remainder);
    
    for i in 0..dividend.len() {
        builder.assert_eq(format!("div_check[{}]", i), reconstructed[i], dividend[i]);
    }
    
    // Verify: remainder < divisor
    let overflow = builder.icmp_ult(divisor[0], remainder[0]); // Simplified
    builder.assert_0("remainder_bound", overflow);
}
```

**Key Insight**: Computing division in-circuit would require thousands of constraints. By having the prover compute it outside and only verifying the result, we reduce the cost to just a multiplication and a few comparisons.

### 3. Batch Operations

Process multiple items together when possible:

```rust
// Bad: Individual SHA-256 for each item
for msg in messages {
    let hash = Sha256::new(builder, msg);
}

// Better: Merkle tree of hashes
let tree = MerkleTree::new(builder, messages);
```

### 4. Precomputation

Move expensive computations outside the circuit when possible:

```rust
// Precompute lookup tables
const SBOX_TABLE: [u64; 256] = precompute_sbox();

// Use conditional selection in-circuit
let sbox_out = lookup_8bit(builder, input, &SBOX_TABLE);
```

## Testing Production Circuits

### 1. Differential Testing

Compare your circuit against reference implementations:

```rust
#[test]
fn test_sha256_against_reference() {
    let circuit = build_sha256_circuit();
    
    for _ in 0..10000 {
        let msg = random_message();
        let expected = sha2::Sha256::digest(&msg);
        
        let mut w = circuit.new_witness_filler();
        populate_message(&mut w, &msg);
        populate_digest(&mut w, &expected);
        
        circuit.populate_wire_witness(&mut w).unwrap();
    }
}
```

### 2. Edge Case Testing

```rust
#[test]
fn test_sha256_edge_cases() {
    // Empty message
    test_sha256(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    
    // Single block boundary (55 bytes)
    test_sha256(&[0x61; 55], "expected_hash_here");
    
    // Double block boundary (64 bytes)
    test_sha256(&[0x61; 64], "expected_hash_here");
    
    // Maximum length
    test_sha256(&[0xFF; MAX_LEN], "expected_hash_here");
}
```

### 3. Constraint Verification

```rust
use binius_frontend::constraint_verifier::verify_constraints;

#[test]
fn verify_circuit_constraints() {
    let circuit = build_circuit();
    let cs = circuit.constraint_system();
    
    let mut w = circuit.new_witness_filler();
    populate_witness(&mut w);
    circuit.populate_wire_witness(&mut w).unwrap();
    
    verify_constraints(cs, &w.value_vec).unwrap();
}
```

## Common Pitfalls and Solutions

### 1. Endianness Issues

```rust
// SHA-256 uses big-endian, but Binius is little-endian
fn convert_endianness(b: &CircuitBuilder, word: Wire) -> Wire {
    // Swap bytes within 32-bit words
    let bytes = [
        extract_byte(b, word, 0),
        extract_byte(b, word, 1),
        extract_byte(b, word, 2),
        extract_byte(b, word, 3),
    ];
    
    pack_bytes_be(b, &bytes)
}
```

### 2. Overflow Handling

```rust
// Always check for overflow in arithmetic
let (sum, carry) = builder.iadd_cin_cout(a, b, cin);
builder.assert_0("no_overflow", carry);
```

### 3. Variable Length Data

```rust
// Properly mask unused data
for i in 0..max_words {
    let is_valid = builder.icmp_ult(
        builder.add_constant_64(i * 8),
        actual_length
    );
    
    let masked_word = builder.band(word[i], is_valid);
    // Use masked_word in computations
}
```

## Building Your Own Advanced Circuit

When designing complex circuits:

1. **Start with the specification**: Implement exactly what the standard says
2. **Build incrementally**: Test each component separately
3. **Optimize later**: Get it working first, then optimize
4. **Document constraints**: Explain why each constraint exists
5. **Provide test vectors**: Include known input/output pairs

## Conclusion

You now have the knowledge to build production-ready ZK circuits in Binius-64! Remember:
- Always verify your constraints actually enforce what you intend
- Test exhaustively with known vectors and random inputs
- Profile constraint counts and optimize the expensive parts
- Use the gadget pattern for modularity and reuse

Happy circuit building!
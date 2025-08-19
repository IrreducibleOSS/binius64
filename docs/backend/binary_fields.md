# Binary Fields in Binius64

## Overview

The binary field implementation in Binius64 focuses on three key field types:
- **BinaryField1b (B1)**: The base binary field GF(2)
- **BinaryField128bGhash**: A 128-bit field optimized for GHASH cryptographic operations
- **AESTowerField128b**: A 128-bit field compatible with AES operations

## Fields Used in Binius64

Binius64 primarily uses three field types:

### BinaryField1b (B1)
- The base binary field GF(2) = {0, 1}
- Used as the foundation for multilinear polynomials
- Addition and multiplication are simple bit operations

### BinaryField128bGhash
- 128-bit field optimized for GHASH (Galois Hash)
- Used in authenticated encryption (GCM mode)
- Irreducible polynomial optimized for carryless multiplication

### AESTowerField128b
- 128-bit field compatible with AES operations
- Enables efficient AES-based cryptographic primitives
- Different representation than GHASH but same field size

## Field Arithmetic in Binius64

### Addition (Simple XOR)

For all binary fields, addition is implemented as XOR:

```rust

impl Add for BinaryField128bGhash {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)  // Just XOR the u128 values
    }
}

```

**Why Addition is Simple XOR**:
- In GF(2): 1 + 1 = 0 (characteristic 2)
- This property extends to all extensions
- No carries, no field reduction needed
- Works directly on the bit representation

### Multiplication

For the 128-bit fields used in Binius64:

```rust
impl Mul for BinaryField128bGhash {
    fn mul(self, other: Self) -> Self {
        // Direct polynomial multiplication in GF(2^128)
        // Uses carryless multiplication instructions when available
        ghash_multiply(self.0, other.0)
    }
}

impl Mul for AESTowerField128b {
    fn mul(self, other: Self) -> Self {
        // AES-specific multiplication
        // Different polynomial basis than GHASH
        aes_multiply(self.0, other.0)
    }
}
```

These implementations may use:
- **PCLMULQDQ** instruction on x86_64 for carryless multiplication
- **PMULL** instruction on ARM for polynomial multiplication
- Fallback to software implementation when hardware support unavailable

## Isomorphism and Different Field Representations

### Different Representations of the Same Field

The same mathematical field GF(2^128) can have different representations: These different representations of binary fields are **isomorphic** to each other (same mathematical structure) but use different computational representations and algorithms.


```rust
BinaryField128bGhash   // GHASH polynomial representation
BinaryField128bPolyval // POLYVAL polynomial representation

// Different irreducible polynomials:
GHASH:    x^128 + x^7 + x^2 + x + 1
POLYVAL:  x^128 + x^127 + x^126 + x^121 + 1
```

**Computational Impact**:
- Different multiplication algorithms
- Different performance characteristics
- **Cannot mix operations** between representations without conversion

## Underliers (Native Types)

Underliers are the raw storage types that represent field elements at the machine level.

### 1. Performance: Direct Hardware Operations
```rust
// What we want mathematically (field addition in GF(2^n)):
field_a + field_b

// What the CPU actually does (XOR on bits):
underlier_a ^ underlier_b

// The underlier gives us direct access to hardware instructions
```

### 2. SIMD and Platform-Specific Optimizations
```rust
// Different platforms have different optimal representations
#[cfg(target_arch = "x86_64")]
type Underlier = __m256i;  // AVX2 256-bit vector

#[cfg(target_arch = "aarch64")]
type Underlier = uint8x16_t;  // NEON 128-bit vector
```

### 3. Binary Field Special Property
In binary fields (GF(2^n)), field operations map directly to bitwise operations:
- **Addition** = XOR
- **Multiplication** = Polynomial multiplication mod irreducible polynomial
- **Squaring** = Bit spreading (special operation)

Having underlier access lets us use these efficient bitwise implementations.

### 4. Type Safety Boundaries

Underliers let us separate concerns. This separation allows:
- Safe field arithmetic by default
- Opt-in to low-level optimizations when needed
- Platform-specific implementations without exposing details

```rust
// High level (safe, mathematical):
trait Field {
    fn mul(self, other: Self) -> Self;  // Field multiplication
}

// Low level (unsafe, hardware):
trait WithUnderlier {
    type Underlier;
    fn to_underlier(self) -> Self::Underlier;  // Escape hatch
}
```

## Appendix

### Comparison with Prime Field Arithmetic

**Prime Fields (e.g., BN254, BLS12-381)**:
- Field elements are integers modulo a large prime p
- Addition: `(a + b) mod p` - requires carry propagation and modular reduction
- Multiplication: `(a * b) mod p` - requires full integer multiplication plus expensive modular reduction
- Storage: Elements near the prime size (e.g., 256 bits for BN254)
- Hardware mapping: Poor - CPUs aren't optimized for large prime arithmetic

**Binary Fields (Binius64)**:
- Field elements are polynomials over GF(2) modulo an irreducible polynomial
- Addition: Simple XOR - no carries, no reduction needed
- Multiplication: Polynomial multiplication with XOR combinations - no integer carries
- Storage: Exactly powers of 2 (8, 16, 32, 64, 128 bits)
- Hardware mapping: Excellent - XOR is a native CPU instruction, some CPUs have carryless multiply

For the Binius tower construction (which is not used in Binius64), see section 2.3 of [Succinct Arguments over Towers of Binary Fields](https://eprint.iacr.org/2023/1784).

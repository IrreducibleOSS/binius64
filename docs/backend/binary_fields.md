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
BinaryField128b        // Tower field representation
BinaryField128bGhash   // GHASH polynomial representation
BinaryField128bPolyval // POLYVAL polynomial representation

// Different irreducible polynomials:
Tower:    x^128 + x^7 + x^2 + x + 1
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

### Binary Tower Field Construction

The original Binius framework (available at https://github.com/IrreducibleOSS/binius) uses a recursive tower field construction to build binary extension fields of increasing size. While Binius64 primarily uses B1, GHASH, and AES fields, understanding the tower construction provides valuable mathematical context.

**Binius64's Fields**:

Binius64 focuses on the specific fields needed for its protocol:
- B1 for multilinear polynomials (the core witness representation)
- 128-bit fields for challenges and cryptographic operations
- GHASH and AES fields leverage existing hardware acceleration

**Tower Construction**:

### The Type Mapping

```rust
// Field Type          →  Underlier Type
BinaryField1b         →  U1 (SmallU<1>, 1 bit in u8)
BinaryField2b         →  U2 (SmallU<2>, 2 bits in u8)
BinaryField4b         →  U4 (SmallU<4>, 4 bits in u8)
BinaryField8b         →  u8
BinaryField16b        →  u16
BinaryField32b        →  u32
BinaryField64b        →  u64
BinaryField128b       →  u128

// For packed/SIMD types
PackedBinaryField8x16b → __m128i (x86) or uint8x16_t (ARM) or [u16; 8] (portable)
PackedBinaryField4x32b → __m128i (x86) or uint8x16_t (ARM) or u128 (portable)
// etc.
```

Binary tower fields are built recursively through degree-2 extensions:
- Start with GF(2) = {0, 1}
- Each extension doubles the field size
- Build sequence: GF(2) → GF(4) → GF(8) → ... → GF(2^128)

```
BinaryField2b  = GF(2²)  = GF(2)[X]/(X² + X + 1)
BinaryField4b  = GF(2⁴)  = BinaryField2b[Y]/(Y² + Y + α)
BinaryField8b  = GF(2⁸)  = BinaryField4b[Z]/(Z² + Z + αY)
...continuing recursively...
```

**Recursive Multiplication Algorithm**:

The tower structure enables elegant recursive multiplication using Karatsuba's algorithm:

```rust
// Multiplication in GF(2^(2n)) built from GF(2^n)
// Elements: a = a₀ + a₁·X, b = b₀ + b₁·X
fn mul_tower(a₀, a₁, b₀, b₁) -> (c₀, c₁) {
    let a₀b₀ = mul_base(a₀, b₀);
    let a₁b₁ = mul_base(a₁, b₁);
    let a₀a₁ = add(a₀, a₁);
    let b₀b₁ = add(b₀, b₁);
    let middle = mul_base(a₀a₁, b₀b₁);

    // Karatsuba combination with tower-specific reduction
    c₀ = add(a₀b₀, mul_base(a₁b₁, β));  // β is field-specific
    c₁ = add(middle, xor(a₀b₀, a₁b₁));
}
```

**General Tower Construction Advantages**:

*Monolithic field construction*:
- Single multiplication algorithm for the entire field
- Often requires specialized assembly or intrinsics
- Hard to optimize across different field sizes

*Tower construction (Binius64)*:
- Recursive decomposition enables size-specific optimizations
- Small fields (2-4 bits): Lookup tables
- Medium fields (8-16 bits): SIMD shuffle instructions
- Large fields (64-128 bits): Karatsuba with hardware carryless multiply
- Natural code reuse through recursion

**Complexity Comparison**:

*Prime field multiplication (256-bit)*:
- ~16 64-bit multiplications for product
- Complex reduction (Barrett, Montgomery, etc.)
- Total: ~20-30 multiplication-equivalent operations


*Binary tower field multiplication (128-bit)*:
- Karatsuba reduces to 3 multiplications at each level
- Multiple levels of recursion for efficient implementation
- Optimized with bit-level operations at the lowest level

*GHASH/POLYVAL implementations*:
- With SIMD/carryless multiply: ~10 multiplication-equivalent operations
- XOR is much cheaper than integer addition


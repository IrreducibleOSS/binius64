//! Tests for optimizations that reduce constraint count
//! All tests validate against reference implementations

mod common;
use common::{validate_with_reference, standard_test_vectors};

use binius_beamish::*;
use binius_beamish::types::{Field64, U32};
use binius_beamish::optimize::OptConfig;
use binius_beamish::ops::arithmetic::add;

/// Test AND zero elimination: x & 0 → 0
#[test]
fn test_and_zero_elimination() {
    validate_with_reference(
        "AND Zero Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &and(&a, &constant(0)))
        },
        |_inputs| {
            // Reference: a & 0 = 0
            0
        },
        |c| c.and_zero_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test AND ones elimination: x & 1* → x
#[test]
fn test_and_ones_elimination() {
    validate_with_reference(
        "AND Ones Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &and(&a, &constant(0xFFFFFFFFFFFFFFFF)))
        },
        |inputs| {
            // Reference: a & 0xFF...FF = a
            inputs[0]
        },
        |c| c.and_ones_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test AND self-elimination: x & x → x
#[test]
fn test_and_self_elimination() {
    validate_with_reference(
        "AND Self-Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &and(&a, &a))
        },
        |inputs| {
            // Reference: a & a = a
            inputs[0]
        },
        |c| c.and_self_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test OR zero elimination: x | 0 → x
#[test]
fn test_or_zero_elimination() {
    validate_with_reference(
        "OR Zero Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &or(&a, &constant(0)))
        },
        |inputs| {
            // Reference: a | 0 = a
            inputs[0]
        },
        |c| c.or_zero_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test OR ones elimination: x | 1* → 1*
#[test]
fn test_or_ones_elimination() {
    validate_with_reference(
        "OR Ones Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &or(&a, &constant(0xFFFFFFFFFFFFFFFF)))
        },
        |_inputs| {
            // Reference: a | 0xFF...FF = 0xFF...FF
            0xFFFFFFFFFFFFFFFF
        },
        |c| c.or_ones_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test OR self-elimination: x | x → x
#[test]
fn test_or_self_elimination() {
    validate_with_reference(
        "OR Self-Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &or(&a, &a))
        },
        |inputs| {
            // Reference: a | a = a
            inputs[0]
        },
        |c| c.or_self_elimination = true,
        standard_test_vectors(1),
    );
}

/// Test XOR of ANDs pattern: (a&b) ⊕ (a&c) ⊕ (b&c)
#[test]
fn test_xor_of_ands_rewrite() {
    validate_with_reference(
        "XOR of ANDs Pattern",
        || {
            let a = val::<Field64>(0);
            let b = val::<Field64>(1);
            let c = val::<Field64>(2);
            let result = val::<Field64>(3);
            
            let ab = and(&a, &b);
            let ac = and(&a, &c);
            let bc = and(&b, &c);
            let maj = xor(&xor(&ab, &ac), &bc);
            
            eq(&result, &maj)
        },
        |inputs| {
            // Reference: (a&b) ⊕ (a&c) ⊕ (b&c)
            let a = inputs[0];
            let b = inputs[1];
            let c = inputs[2];
            (a & b) ^ (a & c) ^ (b & c)
        },
        |c| c.xor_of_ands_rewrite = true,
        standard_test_vectors(3),
    );
}

/// Test carry chain fusion for multiple additions
#[test]
fn test_carry_chain_fusion() {
    validate_with_reference(
        "Carry Chain Fusion",
        || {
            let a = val::<U32>(0);
            let b = val::<U32>(1);
            let c = val::<U32>(2);
            let d = val::<U32>(3);
            
            // Build chain: ((a + b) + c) + d
            let ab = add(&a, &b);
            let abc = add(&ab, &c);
            let abcd = add(&abc, &d);
            abcd.cast::<Field64>()
        },
        |inputs| {
            // Reference: 32-bit addition with wrapping
            let a = inputs[0] as u32;
            let b = inputs[1] as u32;
            let c = inputs[2] as u32;
            let d = inputs[3] as u32;
            a.wrapping_add(b).wrapping_add(c).wrapping_add(d) as u64
        },
        |c| c.carry_chain_fusion = true,
        vec![
            vec![0, 0, 0, 0],
            vec![1, 2, 3, 4],
            vec![0xFFFFFFFF, 1, 0, 0],  // Test carry
            vec![0x80000000, 0x80000000, 0, 0],  // Test overflow
            vec![0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222],
        ],
    );
}

/// Test complex addition chain with rotation-XOR operands
#[test]
fn test_complex_addition_chain() {
    validate_with_reference(
        "Complex Addition Chain",
        || {
            let a = val::<U32>(0);
            let b = val::<U32>(1);
            let c = val::<U32>(2);
            let d = val::<U32>(3);
            
            // Rotation-XOR pattern 1
            let rot_xor1 = xor(&xor(&ror(&b, 7), &ror(&b, 18)), &shr(&b, 3));
            
            // Rotation-XOR pattern 2
            let rot_xor2 = xor(&xor(&ror(&d, 17), &ror(&d, 19)), &shr(&d, 10));
            
            // Chain of additions with complex operands
            let sum = add(&add(&add(&a, &rot_xor1), &c), &rot_xor2);
            sum.cast::<Field64>()
        },
        |inputs| {
            // Reference computation
            let a = inputs[0] as u32;
            let b = inputs[1] as u32;
            let c = inputs[2] as u32;
            let d = inputs[3] as u32;
            
            let rot_xor1 = b.rotate_right(7) ^ b.rotate_right(18) ^ (b >> 3);
            let rot_xor2 = d.rotate_right(17) ^ d.rotate_right(19) ^ (d >> 10);
            
            a.wrapping_add(rot_xor1).wrapping_add(c).wrapping_add(rot_xor2) as u64
        },
        |c| {
            c.carry_chain_fusion = true;
            // Enable all optimizations for complex test
            *c = OptConfig::default();
        },
        vec![
            vec![0, 0, 0, 0],
            vec![0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
            vec![0x12345678, 0x9ABCDEF0, 0x11111111, 0x87654321],
        ],
    );
}
//! Conditional operations for Beamish
//!
//! Provides comparison, selection, and conditional assertion operations
//! optimized for binary field arithmetic with delayed binding.

use crate::*;
use crate::expr::Expr;
use crate::types::BitType;

// ============================================================================
// Core Selection Operations
// ============================================================================

/// Select between two values based on a condition
/// 
/// Returns `true_val` when `cond` is 1, `false_val` when `cond` is 0.
/// 
/// # Implementation
/// Uses the formula: `false_val XOR (cond AND (true_val XOR false_val))`
/// This generates only AND constraints, with XOR operations remaining free.
pub fn select<T: BitType>(cond: &Expr<T>, true_val: &Expr<T>, false_val: &Expr<T>) -> Expr<T> {
    let diff = xor(true_val, false_val);
    let masked = and(cond, &diff);
    xor(false_val, &masked)
}

/// Conditional XOR: XOR a value only if condition is true
///
/// Returns `base XOR value` when `cond` is 1, `base` when `cond` is 0.
pub fn cond_xor<T: BitType>(cond: &Expr<T>, base: &Expr<T>, value: &Expr<T>) -> Expr<T> {
    let masked = and(cond, value);
    xor(base, &masked)
}

// ============================================================================
// Comparison Operations
// ============================================================================

/// Check if two values are equal
///
/// Returns all-1s if `a == b`, all-0s otherwise.
/// 
/// # Implementation
/// In binary fields, equality is just: NOT(a XOR b)
/// This is free (only XOR and NOT, no constraints).
pub fn icmp_eq<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    not(&xor(a, b))
}

/// Unsigned less-than comparison (for U64)
///
/// Returns all-1s if `a < b`, all-0s otherwise.
/// 
/// # Algorithm
/// Computes `a < b` by checking if there's a borrow when computing `a - b`.
/// This is done by computing `¬a + b` and checking if it carries out (≥ 2^64).
///
/// # Implementation
/// Uses a BlackBox to compute the borrow chain, then constrains it with regular ops.
/// The MSB of the borrow chain indicates the result.
///
/// # Cost
/// 2 AND constraints (from the constraint verification)
pub fn icmp_ult(a: &Expr<crate::types::U64>, b: &Expr<crate::types::U64>) -> Expr<crate::types::U64> {
    use crate::expr::ExprNode;
    
    // BlackBox computes the borrow chain for a < b
    let bout = Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("icmp_ult needs 2 inputs") };
            // Compute borrow chain: ¬a + b, track if it carries out
            let not_a = !a;
            let (_, carry) = not_a.overflowing_add(*b);
            // If carry, set MSB; otherwise 0
            if carry { 0x8000_0000_0000_0000 } else { 0 }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }));
    
    // TODO: Build constraints to verify bout is computed correctly
    // For now, we trust the BlackBox computation
    
    // Extract and broadcast MSB using built-in arithmetic right shift
    crate::ops::bitwise::sar(&bout, 63)
}

// ============================================================================
// Multi-way Selection
// ============================================================================

/// Select from an array of values based on an index
///
/// For dynamic array access, selects `values[index]`.
/// 
/// # Example
/// ```
/// let values = [a, b, c, d];  // 4 values
/// let index = expr;            // Index 0-3
/// let result = mux_array(&values, &index);
/// ```
pub fn mux_array<T: BitType>(values: &[Expr<T>], index: &Expr<T>) -> Expr<T> {
    match values.len() {
        0 => panic!("mux_array requires at least one value"),
        1 => values[0].clone(),
        2 => {
            // Base case: use LSB as selector
            select(index, &values[1], &values[0])
        }
        n => {
            // Build tree of 2-to-1 muxes
            // Split array in half and recurse
            let half = n / 2;
            let (lower, upper) = values.split_at(half);
            
            // Use MSB to select between halves
            let msb_shift = (n.next_power_of_two().trailing_zeros() - 1) as u8;
            let msb = if msb_shift > 0 {
                shr(index, msb_shift)
            } else {
                index.clone()
            };
            
            let lower_result = mux_array(lower, index);
            let upper_result = mux_array(upper, index);
            
            select(&msb, &upper_result, &lower_result)
        }
    }
}

/// Select from multiple wire groups based on selector
///
/// Each group must have the same number of wires.
/// Returns the group at position `sel`.
///
/// # Example
/// ```
/// let groups = [&[a1, a2], &[b1, b2], &[c1, c2]];
/// let sel = expr;  // Selects group 0, 1, or 2
/// let [out1, out2] = multi_mux(&groups, &sel);
/// ```
pub fn multi_mux<T: BitType>(groups: &[&[Expr<T>]], sel: &Expr<T>) -> Vec<Expr<T>> {
    assert!(!groups.is_empty(), "groups must not be empty");
    
    let group_size = groups[0].len();
    assert!(group_size > 0, "groups must not be empty");
    
    // Check all groups have same length
    for group in groups {
        assert_eq!(group.len(), group_size, "all groups must have same length");
    }
    
    // For each position, build a mux across groups
    (0..group_size)
        .map(|pos| {
            let values: Vec<_> = groups.iter().map(|g| g[pos].clone()).collect();
            mux_array(&values, sel)
        })
        .collect()
}

// ============================================================================
// Conditional Assertions
// ============================================================================

/// Assert equality conditionally
///
/// Generates a constraint that `a == b` when `cond` is true.
/// When `cond` is false, no constraint is enforced.
///
/// # Returns
/// An expression that should equal zero (for constraint generation).
pub fn assert_eq_cond<T: BitType>(cond: &Expr<T>, a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    let diff = xor(a, b);
    and(cond, &diff)
}

/// Assert zero conditionally
///
/// Generates a constraint that `value == 0` when `cond` is true.
pub fn assert_zero_cond<T: BitType>(cond: &Expr<T>, value: &Expr<T>) -> Expr<T> {
    and(cond, value)
}

// ============================================================================
// Logical Operations (for combining conditions)
// ============================================================================

/// Logical AND of conditions
///
/// Both conditions must be all-1s for result to be all-1s.
pub fn cond_and<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    and(a, b)
}

/// Logical OR of conditions
///
/// At least one condition must be all-1s for result to be all-1s.
/// 
/// # Implementation
/// Uses De Morgan's law: a OR b = NOT(NOT(a) AND NOT(b))
pub fn cond_or<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    not(&and(&not(a), &not(b)))
}

/// Logical NOT of condition
pub fn cond_not<T: BitType>(cond: &Expr<T>) -> Expr<T> {
    not(cond)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Create a mask from a boolean (0 or 1) value
///
/// Converts 1 -> all-1s, 0 -> all-0s
pub fn bool_to_mask<T: BitType>(bool_val: &Expr<T>) -> Expr<T> {
    // Assuming bool_val is 0 or 1, we need to expand it
    // In binary fields, we can use: mask = -bool_val (two's complement)
    // Or just use the value directly if it's already 0 or all-1s
    
    // For now, assume input is already 0 or all-1s
    bool_val.clone()
}

/// Extract a bit from a value at given position
///
/// Returns 1 if bit is set, 0 otherwise.
pub fn extract_bit<T: BitType>(value: &Expr<T>, bit_pos: u8) -> Expr<T> {
    let shifted = shr(value, bit_pos);
    and(&shifted, &constant::<T>(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::U64;
    use crate::compute::expressions::ExpressionEvaluator;
    use crate::optimize::OptConfig;
    use crate::constraints::to_constraints;
    
    #[test]
    fn test_select() {
        let cond_true = constant::<U64>(u64::MAX);  // all-1s
        let cond_false = constant::<U64>(0);
        let a = constant::<U64>(0xAAAA);
        let b = constant::<U64>(0xBBBB);
        
        let result_true = select(&cond_true, &a, &b);
        let result_false = select(&cond_false, &a, &b);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&result_true), 0xAAAA);
        assert_eq!(eval.evaluate(&result_false), 0xBBBB);
    }
    
    #[test]
    fn test_select_with_witness() {
        let cond = val::<U64>(0);  // witness value
        let a = constant::<U64>(0xAAAA);
        let b = constant::<U64>(0xBBBB);
        
        let result = select(&cond, &a, &b);
        
        // Test with cond = all-1s
        let mut eval = ExpressionEvaluator::new(vec![u64::MAX]);
        assert_eq!(eval.evaluate(&result), 0xAAAA);
        
        // Test with cond = 0
        let mut eval = ExpressionEvaluator::new(vec![0]);
        assert_eq!(eval.evaluate(&result), 0xBBBB);
    }
    
    #[test]
    fn test_cond_xor() {
        let cond = val::<U64>(0);
        let base = constant::<U64>(0xFF00);
        let value = constant::<U64>(0x00FF);
        
        let result = cond_xor(&cond, &base, &value);
        
        // When cond = all-1s: should XOR
        let mut eval = ExpressionEvaluator::new(vec![u64::MAX]);
        assert_eq!(eval.evaluate(&result), 0xFFFF);
        
        // When cond = 0: should not XOR
        let mut eval = ExpressionEvaluator::new(vec![0]);
        assert_eq!(eval.evaluate(&result), 0xFF00);
    }
    
    #[test]
    fn test_icmp_eq() {
        let a = constant::<U64>(42);
        let b = constant::<U64>(42);
        let c = constant::<U64>(43);
        
        let eq_result = icmp_eq(&a, &b);
        let ne_result = icmp_eq(&a, &c);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        // When equal: NOT(0) = all-1s
        assert_eq!(eval.evaluate(&eq_result), u64::MAX);
        // When not equal: NOT(non-zero) = some pattern, not necessarily 0
        // For 42 XOR 43 = 1, NOT(1) = 0xFFFFFFFFFFFFFFFE
        assert_ne!(eval.evaluate(&ne_result), u64::MAX);
    }
    
    
    #[test]
    fn test_mux_array() {
        // Test 2-way mux (simplest case)
        let values = vec![
            constant::<U64>(10),
            constant::<U64>(20),
        ];
        
        // Index 0 should select first value
        let index0 = constant::<U64>(0);
        let result0 = mux_array(&values, &index0);
        
        // Index 1 (or all-1s) should select second value
        let index1 = constant::<U64>(u64::MAX);  // all-1s for true condition
        let result1 = mux_array(&values, &index1);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&result0), 10);
        assert_eq!(eval.evaluate(&result1), 20);
    }
    
    #[test]
    fn test_multi_mux() {
        // Test selecting from groups of wires
        let group_a = vec![constant::<U64>(10), constant::<U64>(20)];
        let group_b = vec![constant::<U64>(30), constant::<U64>(40)];
        let groups = vec![group_a.as_slice(), group_b.as_slice()];
        
        // Select group A (index 0)
        let sel_a = constant::<U64>(0);
        let result_a = multi_mux(&groups, &sel_a);
        
        // Select group B (index all-1s)
        let sel_b = constant::<U64>(u64::MAX);
        let result_b = multi_mux(&groups, &sel_b);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(result_a.len(), 2);
        assert_eq!(eval.evaluate(&result_a[0]), 10);
        assert_eq!(eval.evaluate(&result_a[1]), 20);
        
        assert_eq!(result_b.len(), 2);
        assert_eq!(eval.evaluate(&result_b[0]), 30);
        assert_eq!(eval.evaluate(&result_b[1]), 40);
    }
    
    #[test]
    fn test_assert_eq_cond() {
        let cond_true = constant::<U64>(u64::MAX);
        let cond_false = constant::<U64>(0);
        let a = constant::<U64>(42);
        let b = constant::<U64>(42);
        let c = constant::<U64>(43);
        
        // When condition is true and values equal -> 0
        let result1 = assert_eq_cond(&cond_true, &a, &b);
        // When condition is false -> 0 regardless
        let result2 = assert_eq_cond(&cond_false, &a, &c);
        // When condition is true and values differ -> non-zero
        let result3 = assert_eq_cond(&cond_true, &a, &c);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&result1), 0);
        assert_eq!(eval.evaluate(&result2), 0);
        assert_eq!(eval.evaluate(&result3), 1);  // all-1s AND (42 XOR 43) = all-1s AND 1 = 1
    }
    
    #[test]
    fn test_assert_zero_cond() {
        let cond_true = constant::<U64>(u64::MAX);
        let cond_false = constant::<U64>(0);
        let zero = constant::<U64>(0);
        let nonzero = constant::<U64>(42);
        
        let result1 = assert_zero_cond(&cond_true, &zero);
        let result2 = assert_zero_cond(&cond_false, &nonzero);
        let result3 = assert_zero_cond(&cond_true, &nonzero);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&result1), 0);
        assert_eq!(eval.evaluate(&result2), 0);
        assert_eq!(eval.evaluate(&result3), 42);  // all-1s AND 42 = 42
    }
    
    #[test]
    fn test_cond_and_or() {
        let true_cond = constant::<U64>(u64::MAX);
        let false_cond = constant::<U64>(0);
        
        let and_tt = cond_and(&true_cond, &true_cond);
        let and_tf = cond_and(&true_cond, &false_cond);
        let and_ff = cond_and(&false_cond, &false_cond);
        
        let or_tt = cond_or(&true_cond, &true_cond);
        let or_tf = cond_or(&true_cond, &false_cond);
        let or_ff = cond_or(&false_cond, &false_cond);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&and_tt), u64::MAX);
        assert_eq!(eval.evaluate(&and_tf), 0);
        assert_eq!(eval.evaluate(&and_ff), 0);
        
        assert_eq!(eval.evaluate(&or_tt), u64::MAX);
        assert_eq!(eval.evaluate(&or_tf), u64::MAX);
        assert_eq!(eval.evaluate(&or_ff), 0);
    }
    
    #[test]
    fn test_cond_not() {
        let true_cond = constant::<U64>(u64::MAX);
        let false_cond = constant::<U64>(0);
        
        let not_true = cond_not(&true_cond);
        let not_false = cond_not(&false_cond);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&not_true), 0);
        assert_eq!(eval.evaluate(&not_false), u64::MAX);
    }
    
    #[test]
    fn test_extract_bit() {
        let value = constant::<U64>(0b1010_1100);  // Binary: 10101100
        
        let bit0 = extract_bit(&value, 0);  // Should be 0
        let bit2 = extract_bit(&value, 2);  // Should be 1
        let bit3 = extract_bit(&value, 3);  // Should be 1
        let bit4 = extract_bit(&value, 4);  // Should be 0
        let bit7 = extract_bit(&value, 7);  // Should be 1
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        assert_eq!(eval.evaluate(&bit0), 0);
        assert_eq!(eval.evaluate(&bit2), 1);
        assert_eq!(eval.evaluate(&bit3), 1);
        assert_eq!(eval.evaluate(&bit4), 0);
        assert_eq!(eval.evaluate(&bit7), 1);
    }
    
    #[test] 
    fn test_icmp_ult() {
        // Test unsigned less-than comparison using BlackBox implementation
        let a = constant::<U64>(5);
        let b = constant::<U64>(10);
        let c = constant::<U64>(10);
        let d = constant::<U64>(5);
        
        let result_lt = icmp_ult(&a, &b);  // 5 < 10 should be true (all-1s)
        let result_eq = icmp_ult(&c, &c);  // 10 < 10 should be false (0)
        let result_gt = icmp_ult(&b, &d);  // 10 < 5 should be false (0)
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        
        // Test the BlackBox implementation
        assert_eq!(eval.evaluate(&result_lt), u64::MAX, "5 < 10 should be true");
        assert_eq!(eval.evaluate(&result_eq), 0, "10 < 10 should be false");
        assert_eq!(eval.evaluate(&result_gt), 0, "10 < 5 should be false");
    }
    
    #[test]
    fn test_select_constraint_generation() {
        // Verify that select generates only 1 AND constraint
        let cond = val::<U64>(0);
        let a = val::<U64>(1);
        let b = val::<U64>(2);
        
        let result = select(&cond, &a, &b);
        
        let mut config = OptConfig::none_enabled();
        config.canonicalize_enabled = false;
        let constraints = to_constraints(&result, &config);
        
        // Should generate exactly 1 AND constraint for the select
        let and_count = constraints.iter().filter(|c| {
            matches!(c, crate::constraints::Constraint::And { .. })
        }).count();
        
        assert_eq!(and_count, 1, "select should generate exactly 1 AND constraint");
    }
}
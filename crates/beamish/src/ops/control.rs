//! Control flow operations using efficient masking patterns

use crate::expr::Expr;
use crate::types::{U32, BitType};
use crate::ops::{conditional::select, arithmetic::{add, icmp_ult32}, bitwise::{and, not, xor, sar32}};
use crate::{constant, zero, ones};


/// General masked reduction over an array range.
///
/// Applies a reduction operation to elements in array[start..end).
/// Uses efficient masking - O(array.len()) constraints, independent of range size.
///
/// This matches the frontend masking approach and is much more efficient
/// than predicated fold patterns for range-based operations.
///
/// # Examples
/// ```ignore
/// // Sum elements in range [2..7)  
/// let sum = masked_reduce(&array, &start, &end, zero::<U32>(), add);
///
/// // XOR elements in range
/// let xor_result = masked_reduce(&array, &start, &end, zero::<U32>(), xor);
/// ```
pub fn masked_reduce<T: BitType, F>(
    array: &[Expr<T>],
    start: &Expr<U32>,
    end: &Expr<U32>,
    init: Expr<T>,
    op: F,
) -> Expr<T>
where
    F: Fn(&Expr<T>, &Expr<T>) -> Expr<T>,
{
    let mut result = init;
    
    for (i, element) in array.iter().enumerate() {
        let i_const = constant::<U32>(i as u64);
        
        // Check if index i is in range [start, end)
        // in_range = (i >= start) & (i < end)
        let lt_start = icmp_ult32(&i_const, start);    // i < start  
        let ge_start = not(&lt_start);                   // i >= start (NOT(i < start))
        let lt_end = icmp_ult32(&i_const, end);        // i < end
        let in_range = and(&ge_start, &lt_end);        // both conditions
        
        // Create bitmask: all-1s if in_range, all-0s otherwise
        // Cast U32 mask to type T 
        let mask_u32 = sar32(&in_range, 31);         // Sign extend to all bits
        let mask: Expr<T> = Expr::wrap(mask_u32.inner);
        
        // Apply mask: include element if in range, zero otherwise
        let masked_element = and(element, &mask);
        
        // Apply reduction operation
        result = op(&result, &masked_element);
    }
    
    result
}

/// Sum elements in array[start..end) (U32 only)
pub fn masked_sum(
    array: &[Expr<U32>],
    start: &Expr<U32>,
    end: &Expr<U32>,
) -> Expr<U32> {
    masked_reduce(array, start, end, zero::<U32>(), |a, b| add(a, b))
}

/// XOR elements in array[start..end)  
pub fn masked_xor<T: BitType>(
    array: &[Expr<T>],
    start: &Expr<U32>,
    end: &Expr<U32>,
) -> Expr<T> {
    masked_reduce(array, start, end, zero::<T>(), |a, b| xor(a, b))
}

/// AND elements in array[start..end)
pub fn masked_and<T: BitType>(
    array: &[Expr<T>],
    start: &Expr<U32>, 
    end: &Expr<U32>,
) -> Expr<T> {
    masked_reduce(array, start, end, ones::<T>(), |a, b| and(a, b))
}

/// Dynamic array indexing - selects array[index] where index is dynamic.
///
/// Uses a binary tree of 2-to-1 muxes to select from the array based on
/// bits of the index. This generates 2(N-1) AND constraints for N array elements.
///
/// # Implementation  
/// Builds a tree bottom-up, using each bit of the index to select between
/// pairs at each level. Extracts bits and broadcasts them using arithmetic shift.
pub fn array_index<T: BitType>(array: &[Expr<T>], index: &Expr<U32>) -> Expr<T> {
    use crate::ops::bitwise::{and, shr32, shl, sar32};
    
    if array.is_empty() {
        panic!("array_index requires non-empty array");
    }
    
    if array.len() == 1 {
        return array[0].clone();
    }
    
    // Build mux tree level by level
    let mut current_level = array.to_vec();
    let mut bit_pos = 0u8;
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        // Extract bit k (using 32-bit shift since index is U32)
        let shifted = if bit_pos > 0 {
            shr32(index, bit_pos)
        } else {
            index.clone()
        };
        
        let bit = and(&shifted, &constant::<U32>(1));
        
        // Broadcast bit to all positions using 32-bit arithmetic shift
        let bit_msb = shl(&bit, 31);  // Move to MSB for U32
        let mask_u32 = sar32(&bit_msb, 31);  // Broadcasts MSB to all bits
        
        // Type conversion from U32 to T
        let mask_t: Expr<T> = Expr::wrap(mask_u32.inner);
        
        // Build next level of tree
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                // When mask is all-1s (bit=1), select chunk[1]
                // When mask is all-0s (bit=0), select chunk[0]
                next_level.push(select(&mask_t, &chunk[1], &chunk[0]));
            } else {
                // Odd element - carry forward
                next_level.push(chunk[0].clone());
            }
        }
        
        current_level = next_level;
        bit_pos += 1;
    }
    
    current_level[0].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant;
    use crate::compute::expressions::ExpressionEvaluator;
    use crate::constraints::to_constraints;
    
    #[test]
    fn test_fixed_vs_masked_array_sum() {
        println!("\n=== Fixed vs Masked Array Sum Comparison ===");
        
        let array: Vec<Expr<U32>> = (0..10).map(|i| constant::<U32>(i as u64)).collect();
        
        // Fixed version (baseline)
        let fixed_sum = array.iter().fold(constant::<U32>(0), |acc, val| add(&acc, val));
        
        // Masked version (should be similar cost)
        let masked_sum = masked_sum(&array, &constant::<U32>(0), &constant::<U32>(10));
        
        let mut evaluator = ExpressionEvaluator::new(vec![]);
        let fixed_result = evaluator.evaluate(&fixed_sum) as u32;
        let masked_result = evaluator.evaluate(&masked_sum) as u32;
        
        let fixed_constraints = to_constraints(&fixed_sum);
        let masked_constraints = to_constraints(&masked_sum);
        
        println!("Fixed result: {}, constraints: {}", fixed_result, fixed_constraints.len());
        println!("Masked result: {}, constraints: {}", masked_result, masked_constraints.len());
        
        if fixed_constraints.len() > 0 {
            let overhead = masked_constraints.len() as f64 / fixed_constraints.len() as f64;
            println!("Masked overhead: {:.2}x", overhead);
        }
        
        assert_eq!(fixed_result, masked_result, "Results should be identical");
        assert_eq!(fixed_result, 45, "Sum should be 45");
    }
    
    #[test]
    fn test_masked_partial_sums() {
        println!("\n=== Masked Partial Sums ===");
        
        let array: Vec<Expr<U32>> = (0..10).map(|i| constant::<U32>(i as u64)).collect();
        
        let test_cases = [
            (0, 5, 10),    // First half: 0+1+2+3+4 = 10
            (2, 7, 20),    // Middle: 2+3+4+5+6 = 20  
            (5, 10, 35),   // Last half: 5+6+7+8+9 = 35
            (3, 4, 3),     // Single element: just 3
            (7, 7, 0),     // Empty range: 0
        ];
        
        for &(start, end, expected) in &test_cases {
            let sum = masked_sum(&array, &constant::<U32>(start), &constant::<U32>(end));
            
            let mut evaluator = ExpressionEvaluator::new(vec![]);
            let result = evaluator.evaluate(&sum) as u32;
            
            let constraints = to_constraints(&sum);
            
            println!("Range [{}..{}) = {}: {} constraints", start, end, result, constraints.len());
            assert_eq!(result, expected, "Range [{}..{}) should sum to {}", start, end, expected);
        }
    }
    
    #[test]
    fn test_masked_xor() {
        println!("\n=== Masked XOR Operations ===");
        
        let array: Vec<Expr<U32>> = vec![
            constant::<U32>(0b1010),  // 10
            constant::<U32>(0b1100),  // 12  
            constant::<U32>(0b0110),  // 6
            constant::<U32>(0b0001),  // 1
        ];
        
        // XOR all elements: 10 ^ 12 ^ 6 ^ 1 = 9
        let full_xor = masked_xor(&array, &constant::<U32>(0), &constant::<U32>(4));
        
        // XOR middle elements: 12 ^ 6 = 10
        let partial_xor = masked_xor(&array, &constant::<U32>(1), &constant::<U32>(3));
        
        let mut evaluator = ExpressionEvaluator::new(vec![]);
        let full_result = evaluator.evaluate(&full_xor) as u32;
        let partial_result = evaluator.evaluate(&partial_xor) as u32;
        
        println!("Full XOR [0..4): {}", full_result);
        println!("Partial XOR [1..3): {}", partial_result);
        
        assert_eq!(full_result, 9, "10^12^6^1 should equal 9");
        assert_eq!(partial_result, 10, "12^6 should equal 10");
    }
    
    #[test]
    fn test_array_index() {
        println!("\n=== Array Index Tests ===");
        
        let array: Vec<Expr<U32>> = (0..10).map(|i| constant::<U32>(i as u64)).collect();
        
        // Test multiple indices
        for test_idx in [0, 1, 3, 5, 9] {
            let index_expr = constant::<U32>(test_idx);
            let value = array_index(&array, &index_expr);
            
            let mut evaluator = ExpressionEvaluator::new(vec![]);
            let result = evaluator.evaluate(&value) as u32;
            
            println!("Index {} => Result {}", test_idx, result);
            assert_eq!(result, test_idx as u32, "Failed for index {}", test_idx);
        }
    }
    
    #[test]
    fn test_masking_vs_frontend_efficiency() {
        println!("\n=== Masking Efficiency Comparison ===");
        
        let array: Vec<Expr<U32>> = (0..10).map(|i| constant::<U32>(i as u64)).collect();
        
        // Test different range sizes - all should have similar constraint counts
        let ranges = [
            (0, 10, "Full"),
            (2, 7, "Middle"),
            (3, 4, "Single"),
        ];
        
        for &(start, end, desc) in &ranges {
            let sum = masked_sum(&array, &constant::<U32>(start), &constant::<U32>(end));
            let constraints = to_constraints(&sum);
            
            let mut evaluator = ExpressionEvaluator::new(vec![]);
            let result = evaluator.evaluate(&sum) as u32;
            
            println!("{} range [{}..{}): {} constraints, result: {}", 
                     desc, start, end, constraints.len(), result);
        }
        
        println!("All ranges should have similar constraint counts (masking is range-independent)");
    }
}
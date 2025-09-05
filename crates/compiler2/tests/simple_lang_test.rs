//! Tests for the simplified lang module using existing recipe system

use binius_compiler2::lang::*;
use binius_compiler2::*;

#[test]
fn test_typed_xor_with_existing_recipes() {
    // Use existing PredicateCompiler with its built-in recipe system
    let mut compiler = PredicateCompiler::new();
    
    let a = U32Value::new(compiler.allocator().new_private());
    let b = U32Value::new(compiler.allocator().new_private());
    let result = compiler.allocator().new_auxiliary();
    
    // Use typed value to create expression, existing recipes handle the rest
    compiler.builder().add_equals(result, a.xor(&b));
    
    let (constraints, filler) = compiler.compile().unwrap();
    
    println!("Constraints: {}", constraints.total_constraints());
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 10);
    partial.set_private(1, 7);
    
    let complete = filler.fill(partial).unwrap();
    assert_eq!(complete.get(result), Some(10 ^ 7)); // 13
}

#[test]
fn test_typed_chain_with_existing_recipes() {
    let mut compiler = PredicateCompiler::new();
    
    let a = U32Value::new(compiler.allocator().new_private());
    let b = U32Value::new(compiler.allocator().new_private());
    let c = U32Value::new(compiler.allocator().new_private());
    
    let temp = compiler.allocator().new_auxiliary();
    let result = compiler.allocator().new_auxiliary();
    let temp_val = U32Value::new(temp);
    
    // Chain operations using typed values + existing recipes
    compiler.builder().add_equals(temp, a.xor(&b));
    compiler.builder().add_equals(result, temp_val.xor(&c));
    
    let (constraints, filler) = compiler.compile().unwrap();
    
    println!("Chain constraints: {}", constraints.total_constraints());
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 1);
    partial.set_private(1, 2);
    partial.set_private(2, 4);
    
    let complete = filler.fill(partial).unwrap();
    assert_eq!(complete.get(result), Some(1 ^ 2 ^ 4)); // 7
}

#[test]
fn test_typed_mixed_ops_with_existing_recipes() {
    let mut compiler = PredicateCompiler::new();
    
    let a = U32Value::new(compiler.allocator().new_private());
    let b = U32Value::new(compiler.allocator().new_private());
    let c = U32Value::new(compiler.allocator().new_private());
    
    let xor_temp = compiler.allocator().new_auxiliary();
    let result = compiler.allocator().new_auxiliary();
    let xor_val = U32Value::new(xor_temp);
    
    // Mix XOR and AND operations using existing recipes
    compiler.builder().add_equals(xor_temp, a.xor(&b));
    compiler.builder().add_equals(result, xor_val.and(&c));
    
    let (constraints, filler) = compiler.compile().unwrap();
    
    println!("Mixed ops constraints: {}", constraints.total_constraints());
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 0b1100);
    partial.set_private(1, 0b1010);
    partial.set_private(2, 0b1111);
    
    let complete = filler.fill(partial).unwrap();
    // (0b1100 XOR 0b1010) AND 0b1111 = 0b0110 AND 0b1111 = 0b0110 = 6
    assert_eq!(complete.get(result), Some(6));
}

#[test]
fn test_typed_shifts_with_existing_recipes() {
    let mut compiler = PredicateCompiler::new();
    
    let a = U32Value::new(compiler.allocator().new_private());
    let left_result = compiler.allocator().new_auxiliary();
    let right_result = compiler.allocator().new_auxiliary();
    
    // Use typed shift operations with existing recipes
    compiler.builder().add_equals(left_result, a.shl(2));
    compiler.builder().add_equals(right_result, a.shr(1));
    
    let (_, filler) = compiler.compile().unwrap();
    
    let mut partial = PartialWitness::new();
    partial.set_private(0, 8);
    
    let complete = filler.fill(partial).unwrap();
    assert_eq!(complete.get(left_result), Some(8 << 2)); // 32
    assert_eq!(complete.get(right_result), Some(8 >> 1)); // 4
}

#[test]
fn test_packing_with_simplified_lang() {
    fn test_with_packing(enable: bool) -> usize {
        let options = binius_compiler2::compiler::CompilerOptions { enable_packing: enable };
        let mut compiler = PredicateCompiler::with_options(options);
        
        let a = U32Value::new(compiler.allocator().new_private());
        let b = U32Value::new(compiler.allocator().new_private());
        let c = U32Value::new(compiler.allocator().new_private());
        
        let temp = compiler.allocator().new_auxiliary();
        let result = compiler.allocator().new_auxiliary();
        let temp_val = U32Value::new(temp);
        
        // Build operations using existing recipe system
        compiler.builder().add_equals(temp, a.xor(&b));
        compiler.builder().add_equals(result, temp_val.and(&c));
        
        let (constraints, _) = compiler.compile().unwrap();
        constraints.total_constraints()
    }
    
    let unpacked = test_with_packing(false);
    let packed = test_with_packing(true);
    
    println!("Simplified lang - Unpacked: {}, Packed: {}", unpacked, packed);
    
    assert_eq!(unpacked, 2); // XOR + AND
    assert_eq!(packed, 1);   // XOR packed into AND
}
//! Typed witness computation layer with 1-1 operation mapping
//!
//! This layer provides type-safe witness computation where each method
//! corresponds exactly to one Operation variant, ensuring perfect 
//! traceability and compile-time type safety.

use std::collections::HashMap;
use binius_core::Word;
use super::{
    FieldValue, UIntValue, BitsValue, FieldId, UIntId, BitsId,
    Operation, FieldOp, UIntOp, BitsOp, ConvertOp, WitnessOp, AssertOp,
    WitnessId, TrackedWord  // Legacy support
};

/// Typed witness execution context with perfect method-to-operation mapping
#[derive(Default)]
pub struct WitnessContext {
    /// Next available IDs for each type
    next_field_id: u32,
    next_uint_id: u32,
    next_bits_id: u32,
    next_legacy_id: u32,
    
    /// Values stored by their IDs
    field_values: HashMap<FieldId, Word>,
    uint_values: HashMap<UIntId, Word>,
    bits_values: HashMap<BitsId, Word>,
    legacy_values: HashMap<WitnessId, Word>,
    
    /// Operation trace for constraint compilation (1-1 with method calls)
    operations: Vec<Operation>,
}


impl WitnessContext {
    pub fn new() -> Self {
        Self::default()
    }
    
    // ========== WITNESS CREATION ==========
    
    /// Create a field element witness - for polynomial operations
    pub fn witness_field(&mut self, value: Word) -> FieldValue {
        let id = FieldId(self.next_field_id);
        self.next_field_id += 1;
        self.field_values.insert(id, value);
        
        // 1-1 mapping: method call -> operation
        self.operations.push(Operation::Witness(WitnessOp::Field(id, value)));
        
        FieldValue { value, id }
    }
    
    /// Create an unsigned integer witness - for arithmetic with carry
    pub fn witness_uint(&mut self, value: Word) -> UIntValue {
        let id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        self.uint_values.insert(id, value);
        
        self.operations.push(Operation::Witness(WitnessOp::UInt(id, value)));
        
        UIntValue { value, id }
    }
    
    /// Create a bit pattern witness - for masking and logical operations
    pub fn witness_bits(&mut self, value: Word) -> BitsValue {
        let id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(id, value);
        
        self.operations.push(Operation::Witness(WitnessOp::Bits(id, value)));
        
        BitsValue { value, id }
    }
    
    /// Shorter aliases for witness creation
    pub fn field(&mut self, value: Word) -> FieldValue {
        self.witness_field(value)
    }
    
    pub fn uint(&mut self, value: Word) -> UIntValue {
        self.witness_uint(value)
    }
    
    pub fn bits(&mut self, value: Word) -> BitsValue {
        self.witness_bits(value)
    }
    
    /// Convenience constants
    pub fn zero_field(&mut self) -> FieldValue {
        self.witness_field(Word::ZERO)
    }
    
    pub fn zero_uint(&mut self) -> UIntValue {
        self.witness_uint(Word::ZERO)
    }
    
    pub fn zero_bits(&mut self) -> BitsValue {
        self.witness_bits(Word::ZERO)
    }
    
    // ========== FIELD OPERATIONS (GF(2^64)) ==========
    
    /// Field addition (XOR operation in GF(2^64))
    pub fn add(&mut self, a: FieldValue, b: FieldValue) -> FieldValue {
        let result_value = Word(a.value.0 ^ b.value.0);  // XOR = field addition
        let result_id = FieldId(self.next_field_id);
        self.next_field_id += 1;
        self.field_values.insert(result_id, result_value);
        
        // 1-1 mapping: this method -> FieldOp::Add
        self.operations.push(Operation::Field(FieldOp::Add(a.id, b.id, result_id)));
        
        FieldValue { value: result_value, id: result_id }
    }
    
    /// Alias for field addition (familiar name)
    pub fn xor(&mut self, a: FieldValue, b: FieldValue) -> FieldValue {
        self.add(a, b)
    }
    
    /// Field multiplication (carryless multiplication in GF(2^64))
    pub fn mul(&mut self, a: FieldValue, b: FieldValue) -> FieldValue {
        // For now, simple implementation - real CLMUL would be more complex
        let result_value = self.compute_field_mul(a.value, b.value);
        let result_id = FieldId(self.next_field_id);
        self.next_field_id += 1;
        self.field_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Field(FieldOp::Mul(a.id, b.id, result_id)));
        
        FieldValue { value: result_value, id: result_id }
    }
    
    // ========== UNSIGNED INTEGER OPERATIONS ==========
    
    /// Unsigned integer addition with carry (mod 2^64 arithmetic)
    pub fn add_with_carry(&mut self, a: UIntValue, b: UIntValue, carry_in: UIntValue) 
        -> (UIntValue, UIntValue) {
        let carry_bit = carry_in.value.0 >> 63;  // Extract carry bit
        let (sum_val, carry_out_val) = {
            let a_val = a.value.0;
            let b_val = b.value.0;
            let sum128 = (a_val as u128) + (b_val as u128) + (carry_bit as u128);
            let sum = (sum128 & 0xFFFFFFFFFFFFFFFF) as u64;
            let carry_out = if sum128 > 0xFFFFFFFFFFFFFFFF { 
                0xFFFFFFFFFFFFFFFF  // All 1s for carry
            } else { 
                0 
            };
            (Word(sum), Word(carry_out))
        };
        
        let sum_id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        let carry_out_id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        
        self.uint_values.insert(sum_id, sum_val);
        self.uint_values.insert(carry_out_id, carry_out_val);
        
        // 1-1 mapping: this method -> UIntOp::Add  
        self.operations.push(Operation::UInt(UIntOp::Add(
            a.id, b.id, carry_in.id, sum_id, carry_out_id
        )));
        
        (UIntValue { value: sum_val, id: sum_id },
         UIntValue { value: carry_out_val, id: carry_out_id })
    }
    
    /// Alias for unsigned integer addition (familiar name)
    pub fn adc(&mut self, a: UIntValue, b: UIntValue, carry_in: UIntValue) 
        -> (UIntValue, UIntValue) {
        self.add_with_carry(a, b, carry_in)
    }
    
    /// Unsigned integer multiplication (64x64 -> 128 bit result)
    pub fn mul_with_overflow(&mut self, a: UIntValue, b: UIntValue) -> (UIntValue, UIntValue) {
        let result128 = (a.value.0 as u128) * (b.value.0 as u128);
        let lo_val = Word((result128 & 0xFFFFFFFFFFFFFFFF) as u64);
        let hi_val = Word((result128 >> 64) as u64);
        
        let lo_id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        let hi_id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        
        self.uint_values.insert(lo_id, lo_val);
        self.uint_values.insert(hi_id, hi_val);
        
        self.operations.push(Operation::UInt(UIntOp::Mul(a.id, b.id, lo_id, hi_id)));
        
        (UIntValue { value: lo_val, id: lo_id },
         UIntValue { value: hi_val, id: hi_id })
    }
    
    // ========== BIT PATTERN OPERATIONS ==========
    
    /// Bitwise AND
    pub fn and(&mut self, a: BitsValue, b: BitsValue) -> BitsValue {
        let result_value = Word(a.value.0 & b.value.0);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::And(a.id, b.id, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    /// Bitwise OR
    pub fn or(&mut self, a: BitsValue, b: BitsValue) -> BitsValue {
        let result_value = Word(a.value.0 | b.value.0);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::Or(a.id, b.id, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    /// Bitwise NOT
    pub fn not(&mut self, a: BitsValue) -> BitsValue {
        let result_value = Word(!a.value.0);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::Not(a.id, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    /// Logical left shift
    pub fn shl(&mut self, a: BitsValue, n: u32) -> BitsValue {
        let result_value = Word(a.value.0 << n);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::Shl(a.id, n, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    /// Logical right shift
    pub fn shr(&mut self, a: BitsValue, n: u32) -> BitsValue {
        let result_value = Word(a.value.0 >> n);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::Shr(a.id, n, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    /// Arithmetic right shift (sign-extending)
    pub fn sar(&mut self, a: BitsValue, n: u32) -> BitsValue {
        let result_value = Word(((a.value.0 as i64) >> n) as u64);
        let result_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(result_id, result_value);
        
        self.operations.push(Operation::Bits(BitsOp::Sar(a.id, n, result_id)));
        
        BitsValue { value: result_value, id: result_id }
    }
    
    // ========== TYPE CONVERSIONS ==========
    
    /// Reinterpret bits as field element (zero-cost conversion)
    pub fn as_field(&mut self, bits: BitsValue) -> FieldValue {
        let field_id = FieldId(self.next_field_id);
        self.next_field_id += 1;
        self.field_values.insert(field_id, bits.value);
        
        self.operations.push(Operation::Convert(ConvertOp::AsField(bits.id, field_id)));
        
        FieldValue { value: bits.value, id: field_id }
    }
    
    /// Reinterpret bits as unsigned integer (zero-cost conversion)
    pub fn as_uint(&mut self, bits: BitsValue) -> UIntValue {
        let uint_id = UIntId(self.next_uint_id);
        self.next_uint_id += 1;
        self.uint_values.insert(uint_id, bits.value);
        
        self.operations.push(Operation::Convert(ConvertOp::AsUInt(bits.id, uint_id)));
        
        UIntValue { value: bits.value, id: uint_id }
    }
    
    /// Reinterpret field as bits (zero-cost conversion)
    pub fn as_bits(&mut self, field: FieldValue) -> BitsValue {
        let bits_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(bits_id, field.value);
        
        self.operations.push(Operation::Convert(ConvertOp::AsBitsFromField(field.id, bits_id)));
        
        BitsValue { value: field.value, id: bits_id }
    }
    
    /// Reinterpret uint as bits (zero-cost conversion)  
    pub fn as_bits_from_uint(&mut self, uint: UIntValue) -> BitsValue {
        let bits_id = BitsId(self.next_bits_id);
        self.next_bits_id += 1;
        self.bits_values.insert(bits_id, uint.value);
        
        self.operations.push(Operation::Convert(ConvertOp::AsBitsFromUInt(uint.id, bits_id)));
        
        BitsValue { value: uint.value, id: bits_id }
    }
    
    // ========== ASSERTIONS ==========
    
    /// Assert two values are equal (works with any ID type via legacy WitnessId)
    pub fn assert_eq_field(&mut self, a: FieldValue, b: FieldValue, msg: &str) {
        assert_eq!(a.value, b.value, "{}", msg);
        // Convert to legacy IDs for assertion
        let a_legacy = WitnessId(a.id.0);
        let b_legacy = WitnessId(b.id.0);
        self.operations.push(Operation::Assert(AssertOp::Eq(a_legacy, b_legacy, msg.to_string())));
    }
    
    pub fn assert_eq_uint(&mut self, a: UIntValue, b: UIntValue, msg: &str) {
        assert_eq!(a.value, b.value, "{}", msg);
        let a_legacy = WitnessId(a.id.0);
        let b_legacy = WitnessId(b.id.0);
        self.operations.push(Operation::Assert(AssertOp::Eq(a_legacy, b_legacy, msg.to_string())));
    }
    
    pub fn assert_eq_bits(&mut self, a: BitsValue, b: BitsValue, msg: &str) {
        assert_eq!(a.value, b.value, "{}", msg);
        let a_legacy = WitnessId(a.id.0);
        let b_legacy = WitnessId(b.id.0);
        self.operations.push(Operation::Assert(AssertOp::Eq(a_legacy, b_legacy, msg.to_string())));
    }
    
    /// Assert value is zero
    pub fn assert_zero_field(&mut self, a: FieldValue, msg: &str) {
        assert_eq!(a.value, Word::ZERO, "{}", msg);
        let a_legacy = WitnessId(a.id.0);
        self.operations.push(Operation::Assert(AssertOp::Zero(a_legacy, msg.to_string())));
    }
    
    pub fn assert_zero_uint(&mut self, a: UIntValue, msg: &str) {
        assert_eq!(a.value, Word::ZERO, "{}", msg);
        let a_legacy = WitnessId(a.id.0);
        self.operations.push(Operation::Assert(AssertOp::Zero(a_legacy, msg.to_string())));
    }
    
    pub fn assert_zero_bits(&mut self, a: BitsValue, msg: &str) {
        assert_eq!(a.value, Word::ZERO, "{}", msg);
        let a_legacy = WitnessId(a.id.0);
        self.operations.push(Operation::Assert(AssertOp::Zero(a_legacy, msg.to_string())));
    }
    
    // ========== LEGACY SUPPORT ==========
    
    /// Legacy witness creation (for gradual migration)
    pub fn witness(&mut self, value: Word) -> TrackedWord {
        let id = WitnessId(self.next_legacy_id);
        self.next_legacy_id += 1;
        self.legacy_values.insert(id, value);
        TrackedWord { value, id }
    }
    
    // ========== ACCESS METHODS ==========
    
    /// Get the operation trace for constraint compilation
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
    
    /// Get all stored values (for debugging)
    pub fn field_values(&self) -> &HashMap<FieldId, Word> {
        &self.field_values
    }
    
    pub fn uint_values(&self) -> &HashMap<UIntId, Word> {
        &self.uint_values
    }
    
    pub fn bits_values(&self) -> &HashMap<BitsId, Word> {
        &self.bits_values
    }
    
    // ========== PRIVATE HELPERS ==========
    
    /// Compute field multiplication (simplified - real implementation would use CLMUL)
    fn compute_field_mul(&self, a: Word, b: Word) -> Word {
        // Simplified field multiplication for now
        // Real implementation would use carryless multiplication
        Word(a.0 ^ b.0)  // Placeholder
    }
}

// ========== LEGACY OPERATION ENUM (for migration) ==========

/// Legacy operation enum - deprecated, use typed Operation instead
#[derive(Clone, Debug)]
pub enum LegacyOperation {
    Witness(WitnessId),
    Constant(WitnessId, Word),
    Band(WitnessId, WitnessId, WitnessId),
    Bxor(WitnessId, WitnessId, WitnessId),
    Sar(WitnessId, u32, WitnessId),
    Shr(WitnessId, u32, WitnessId),
    Shl(WitnessId, u32, WitnessId),
    AddWithCarry(WitnessId, WitnessId, WitnessId, WitnessId, WitnessId),
    AssertEq(WitnessId, WitnessId, String),
    AssertZero(WitnessId, String),
}


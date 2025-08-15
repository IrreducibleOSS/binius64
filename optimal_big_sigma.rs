use binius_core::word::Word;
use crate::compiler::{CircuitBuilder, Wire};
use crate::compiler::constraint_builder::{ConstraintBuilder, ShiftedWire, Shift};

/// Current implementation of big_sigma_0 (3 AND constraints)
fn big_sigma_0_current(b: &CircuitBuilder, a: Wire) -> Wire {
    let r1 = b.rotr_32(a, 2);   // 1 AND constraint
    let r2 = b.rotr_32(a, 13);  // 1 AND constraint  
    let r3 = b.rotr_32(a, 22);  // 1 AND constraint
    let x1 = b.bxor(r1, r2);    // No constraint
    b.bxor(x1, r3)               // No constraint
    // Total: 3 AND constraints
}

/// Theoretically optimal big_sigma_0 (1 AND constraint)
/// Σ0(a) = ROTR(a, 2) XOR ROTR(a, 13) XOR ROTR(a, 22)
///       = ((a >> 2) ^ (a << 30) ^ (a >> 13) ^ (a << 19) ^ (a >> 22) ^ (a << 10)) & MASK_32
fn big_sigma_0_optimal(
    builder: &CircuitBuilder, 
    constraint_builder: &mut ConstraintBuilder,
    a: Wire
) -> Wire {
    // Create output wire
    let result = builder.add_internal();
    let mask32 = builder.add_constant(Word::MASK_32);
    
    // Build the XOR chain for operand A
    // ROTR(a, 2) = (a >> 2) ^ (a << 30)
    // ROTR(a, 13) = (a >> 13) ^ (a << 19)  
    // ROTR(a, 22) = (a >> 22) ^ (a << 10)
    let operand_a = vec![
        ShiftedWire { wire: a, shift: Shift::Srl(2) },   // a >> 2
        ShiftedWire { wire: a, shift: Shift::Sll(30) },  // a << 30
        ShiftedWire { wire: a, shift: Shift::Srl(13) },  // a >> 13
        ShiftedWire { wire: a, shift: Shift::Sll(19) },  // a << 19
        ShiftedWire { wire: a, shift: Shift::Srl(22) },  // a >> 22
        ShiftedWire { wire: a, shift: Shift::Sll(10) },  // a << 10
    ];
    
    // Create single AND constraint: (operand_a) & MASK_32 ^ result = 0
    constraint_builder.and_constraints.push(WireAndConstraint {
        a: operand_a,
        b: vec![ShiftedWire { wire: mask32, shift: Shift::None }],
        c: vec![ShiftedWire { wire: result, shift: Shift::None }],
    });
    
    result
    // Total: 1 AND constraint (3x reduction!)
}

/// Similarly optimized big_sigma_1
/// Σ1(e) = ROTR(e, 6) XOR ROTR(e, 11) XOR ROTR(e, 25)
fn big_sigma_1_optimal(
    builder: &CircuitBuilder,
    constraint_builder: &mut ConstraintBuilder,
    e: Wire
) -> Wire {
    let result = builder.add_internal();
    let mask32 = builder.add_constant(Word::MASK_32);
    
    let operand_a = vec![
        ShiftedWire { wire: e, shift: Shift::Srl(6) },   // e >> 6
        ShiftedWire { wire: e, shift: Shift::Sll(26) },  // e << 26
        ShiftedWire { wire: e, shift: Shift::Srl(11) },  // e >> 11
        ShiftedWire { wire: e, shift: Shift::Sll(21) },  // e << 21
        ShiftedWire { wire: e, shift: Shift::Srl(25) },  // e >> 25
        ShiftedWire { wire: e, shift: Shift::Sll(7) },   // e << 7
    ];
    
    constraint_builder.and_constraints.push(WireAndConstraint {
        a: operand_a,
        b: vec![ShiftedWire { wire: mask32, shift: Shift::None }],
        c: vec![ShiftedWire { wire: result, shift: Shift::None }],
    });
    
    result
}

/// Optimized small_sigma_0
/// σ0(x) = ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)
fn small_sigma_0_optimal(
    builder: &CircuitBuilder,
    constraint_builder: &mut ConstraintBuilder,
    x: Wire
) -> Wire {
    let result = builder.add_internal();
    let mask32 = builder.add_constant(Word::MASK_32);
    
    let operand_a = vec![
        // ROTR(x, 7) = (x >> 7) ^ (x << 25)
        ShiftedWire { wire: x, shift: Shift::Srl(7) },
        ShiftedWire { wire: x, shift: Shift::Sll(25) },
        // ROTR(x, 18) = (x >> 18) ^ (x << 14)
        ShiftedWire { wire: x, shift: Shift::Srl(18) },
        ShiftedWire { wire: x, shift: Shift::Sll(14) },
        // SHR(x, 3) - just a single right shift
        ShiftedWire { wire: x, shift: Shift::Srl(3) },
    ];
    
    constraint_builder.and_constraints.push(WireAndConstraint {
        a: operand_a,
        b: vec![ShiftedWire { wire: mask32, shift: Shift::None }],
        c: vec![ShiftedWire { wire: result, shift: Shift::None }],
    });
    
    result
}

/// Optimized small_sigma_1
/// σ1(x) = ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)
fn small_sigma_1_optimal(
    builder: &CircuitBuilder,
    constraint_builder: &mut ConstraintBuilder,
    x: Wire
) -> Wire {
    let result = builder.add_internal();
    let mask32 = builder.add_constant(Word::MASK_32);
    
    let operand_a = vec![
        // ROTR(x, 17) = (x >> 17) ^ (x << 15)
        ShiftedWire { wire: x, shift: Shift::Srl(17) },
        ShiftedWire { wire: x, shift: Shift::Sll(15) },
        // ROTR(x, 19) = (x >> 19) ^ (x << 13)
        ShiftedWire { wire: x, shift: Shift::Srl(19) },
        ShiftedWire { wire: x, shift: Shift::Sll(13) },
        // SHR(x, 10)
        ShiftedWire { wire: x, shift: Shift::Srl(10) },
    ];
    
    constraint_builder.and_constraints.push(WireAndConstraint {
        a: operand_a,
        b: vec![ShiftedWire { wire: mask32, shift: Shift::None }],
        c: vec![ShiftedWire { wire: result, shift: Shift::None }],
    });
    
    result
}

/// Example of how SHA-256 compression could be optimized
/// Current: ~12 AND constraints per round (3 each for big_sigma_0, big_sigma_1, small_sigma_0, small_sigma_1)
/// Optimal: ~4 AND constraints per round (1 each)
/// Savings: 64 rounds * 8 constraints = 512 fewer constraints!

// Note: This requires direct access to ConstraintBuilder, which would need to be 
// exposed or wrapped in a new API. The challenge is maintaining witness generation
// while allowing constraint fusion.

// Potential API design:
trait ConstraintFusable {
    /// Build constraint without forcing intermediate witnesses
    fn build_fused(&self, builder: &mut ConstraintBuilder) -> Wire;
    
    /// Build with witness materialization (current behavior)
    fn build_materialized(&self, builder: &CircuitBuilder) -> Wire;
}
// Simplest possible approach - store raw constraints directly

use crate::compiler::{CircuitBuilder, Wire};

// Add this to Shared struct in compiler/mod.rs:
struct Shared {
    graph: GateGraph,
    // NEW: Store raw constraints directly!
    raw_and_constraints: Vec<RawAndConstraint>,
    raw_mul_constraints: Vec<RawMulConstraint>,
}

// Simple struct - no gate overhead
struct RawAndConstraint {
    a: Vec<(Wire, ShiftOp)>,  // Operand A terms
    b: Vec<(Wire, ShiftOp)>,  // Operand B terms  
    c: Vec<(Wire, ShiftOp)>,  // Operand C terms
}

enum ShiftOp {
    None,
    Sll(u32),
    Srl(u32),
    Sar(u32),
}

// Add method to CircuitBuilder
impl CircuitBuilder {
    /// Add a raw AND constraint without creating a gate
    /// This is just storing data - no struct overhead!
    pub fn raw_and_constraint(
        &self,
        a: Vec<(Wire, ShiftOp)>,
        b: Vec<(Wire, ShiftOp)>,
        c: Vec<(Wire, ShiftOp)>,
    ) {
        let mut shared = self.shared.borrow_mut();
        shared.raw_and_constraints.push(RawAndConstraint { a, b, c });
    }
}

// Then in build(), after processing gates:
fn build(&self) -> Circuit {
    // ... existing code ...
    
    let mut builder = ConstraintBuilder::new();
    
    // Process gates as before
    for (gate_id, _) in graph.gates.iter() {
        gate::constrain(gate_id, &graph, &mut builder);
    }
    
    // NEW: Add raw constraints
    for raw in &shared.raw_and_constraints {
        builder
            .and()
            .a(convert_to_operand(&raw.a))
            .b(convert_to_operand(&raw.b))
            .c(convert_to_operand(&raw.c))
            .build();
    }
    
    // ... rest of build ...
}

// ============================================================================
// USAGE - Now big_sigma_0 is trivial:
// ============================================================================

fn big_sigma_0_optimal(b: &CircuitBuilder, a: Wire) -> Wire {
    use ShiftOp::*;
    
    let result = b.add_internal();
    let mask32 = b.add_constant(Word::MASK_32);
    
    // Just store the constraint directly - no gate!
    b.raw_and_constraint(
        // Operand A: all the rotation terms
        vec![
            (a, Srl(2)),  (a, Sll(30)),  // ROTR(a, 2)
            (a, Srl(13)), (a, Sll(19)),  // ROTR(a, 13)
            (a, Srl(22)), (a, Sll(10)),  // ROTR(a, 22)
        ],
        // Operand B: mask
        vec![(mask32, None)],
        // Operand C: result
        vec![(result, None)],
    );
    
    // BUT WAIT - who computes the witness value for 'result'?
    // We need to also store a witness computation function!
    
    result
}
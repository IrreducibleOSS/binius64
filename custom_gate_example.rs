// Example of how we could add a custom gate for optimized big_sigma_0

use crate::compiler::{
    gate::{Opcode, OpcodeShape},
    constraint_builder::{ConstraintBuilder, sll, srl, xor6},
    Wire,
};

// Define a new opcode
enum CustomOpcode {
    BigSigma0_32,  // Optimized big_sigma_0 for SHA-256
}

// Shape definition - what wires this gate needs
fn big_sigma_0_32_shape() -> OpcodeShape {
    OpcodeShape {
        const_in: &[Word::MASK_32],
        n_in: 1,      // input wire
        n_out: 1,     // output wire  
        n_internal: 0,
        n_scratch: 0,
        n_imm: 0,
    }
}

// Constraint generation - THE OPTIMIZED VERSION
fn big_sigma_0_32_constrain(
    gate: Gate,
    data: &GateData,
    builder: &mut ConstraintBuilder,
) {
    let GateParam { constants, inputs, outputs, .. } = data.gate_param();
    let [mask32] = constants else { unreachable!() };
    let [a] = inputs else { unreachable!() };
    let [result] = outputs else { unreachable!() };
    
    // Single AND constraint instead of 5!
    // Σ0(a) = ROTR(a,2) ⊕ ROTR(a,13) ⊕ ROTR(a,22)
    builder
        .and()
        .a(vec![
            srl(*a, 2),  sll(*a, 30),  // ROTR(a, 2)
            srl(*a, 13), sll(*a, 19),  // ROTR(a, 13)  
            srl(*a, 22), sll(*a, 10),  // ROTR(a, 22)
        ])
        .b(*mask32)
        .c(*result)
        .build();
}

// Witness generation - compute the actual value
fn big_sigma_0_32_eval(
    inputs: &[Word],
    outputs: &mut [Word],
) {
    let a = inputs[0].0 & 0xFFFFFFFF;  // Mask to 32 bits
    
    // Compute the three rotations
    let r1 = ((a >> 2) | (a << 30)) & 0xFFFFFFFF;
    let r2 = ((a >> 13) | (a << 19)) & 0xFFFFFFFF;
    let r3 = ((a >> 22) | (a << 10)) & 0xFFFFFFFF;
    
    // XOR them together
    outputs[0] = Word(r1 ^ r2 ^ r3);
}

// Extension trait to add to CircuitBuilder
impl CircuitBuilder {
    pub fn big_sigma_0_32_optimized(&self, a: Wire) -> Wire {
        let result = self.add_internal();
        let mut graph = self.graph_mut();
        graph.emit_gate(
            self.current_path,
            CustomOpcode::BigSigma0_32,
            [a],
            [result],
        );
        result
    }
}
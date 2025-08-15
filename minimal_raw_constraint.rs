// The absolute minimal approach - store raw constraints with witness functions

// Add to CircuitBuilder's Shared struct:
struct Shared {
    graph: GateGraph,
    // NEW: Just store raw constraints and how to compute witnesses
    raw_constraints: Vec<RawConstraint>,
}

struct RawConstraint {
    // The constraint
    constraint: ConstraintSpec,
    // Function to compute witness values for internal wires
    witness_fn: Box<dyn Fn(&[Word]) -> Vec<Word>>,
    // Which wires are inputs and outputs
    inputs: Vec<Wire>,
    outputs: Vec<Wire>,
}

enum ConstraintSpec {
    And { a: Vec<(Wire, Shift)>, b: Vec<(Wire, Shift)>, c: Vec<(Wire, Shift)> },
    Mul { a: Vec<(Wire, Shift)>, b: Vec<(Wire, Shift)>, hi: Vec<(Wire, Shift)>, lo: Vec<(Wire, Shift)> },
}

impl CircuitBuilder {
    /// The only method we need to add!
    pub fn raw_constraint(
        &self,
        inputs: Vec<Wire>,
        outputs: Vec<Wire>,
        constraint: ConstraintSpec,
        witness_fn: impl Fn(&[Word]) -> Vec<Word> + 'static,
    ) {
        let mut shared = self.shared.borrow_mut();
        shared.raw_constraints.push(RawConstraint {
            constraint,
            witness_fn: Box::new(witness_fn),
            inputs,
            outputs,
        });
    }
}

// Usage - optimized big_sigma_0:
fn big_sigma_0_optimal(b: &CircuitBuilder, a: Wire) -> Wire {
    let result = b.add_internal();
    let mask32 = b.add_constant(Word::MASK_32);
    
    b.raw_constraint(
        vec![a],           // inputs
        vec![result],      // outputs
        ConstraintSpec::And {
            a: vec![
                (a, Shift::Srl(2)),  (a, Shift::Sll(30)),
                (a, Shift::Srl(13)), (a, Shift::Sll(19)),
                (a, Shift::Srl(22)), (a, Shift::Sll(10)),
            ],
            b: vec![(mask32, Shift::None)],
            c: vec![(result, Shift::None)],
        },
        |inputs| {
            // Compute big_sigma_0
            let a = inputs[0].0 & 0xFFFFFFFF;
            let r1 = ((a >> 2) | (a << 30)) & 0xFFFFFFFF;
            let r2 = ((a >> 13) | (a << 19)) & 0xFFFFFFFF;
            let r3 = ((a >> 22) | (a << 10)) & 0xFFFFFFFF;
            vec![Word(r1 ^ r2 ^ r3)]
        },
    );
    
    result
}

// In build(), process raw constraints:
fn build(&self) -> Circuit {
    // ... existing code ...
    
    // Add raw constraints to ConstraintBuilder
    for raw in &shared.raw_constraints {
        match &raw.constraint {
            ConstraintSpec::And { a, b, c } => {
                builder.and()
                    .a(convert_terms(a))
                    .b(convert_terms(b))
                    .c(convert_terms(c))
                    .build();
            }
            ConstraintSpec::Mul { .. } => { /* similar */ }
        }
    }
    
    // For witness evaluation, raw constraints act like custom gates
    // The EvalForm builder would need to handle them
}
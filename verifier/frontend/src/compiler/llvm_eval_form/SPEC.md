# LLVM backed evaluation form

Given a [`GateGraph`] produce a native executable that will perform computations specified in that
gate graph filling out all the intermediate computations.


This is very similar to what the current eval_form is doing. Check out verifier/frontend/src/compiler/eval_form/builder.rs
verifier/frontend/src/compiler/eval_form/interpreter.rs

In fact, we could use it for ensuring the correctness of the translation.

[`GateGraph`]: verifier/frontend/src/compiler/gate_graph.rs

## Workflow

When we compile first we need to initialize the inkwell's (LLVM interface for Rust) and then iterate over the gates building the corresponding LLVM IR to compute the witness wires. Take
a look at the [`fax`] gate implementation to see what exactly it is doing.

[`fax`] verifier/frontend/src/compiler/gate/fax.rs

The evaluation form is not permitted to trap until it fills out everything. In case there is an
assertion failure, it should be noted and the evaluation should carry on.

Note that we assume that assertion failures happen extremely rarely. For the future optimizations
we are going to take that into account.

## `Context`

There is a context variable that is passed into the compiled code. It should have a predictable
layout, so it's `repr(C)`.

It should contain at least:

1. the base pointer to value vector.
2. the place where we are going to store information about failures.

## Lowering

The gates should compute wires and store them into temporaries. We should minimize memory traffic. Concretely, we should not store every wire into the value vec, we should store only the
ones that appear in the `constrained` set passed as an argument.

That means that every value that is not computed as an internal wire but rather is an input should
be loaded into a temporary upon the first access. Every value that is computed should be stored as
a temporary and read from the temporary next time it is needed. Finally, the values that are
constrained must be dumped into the value vec.

# Milestone 0

This is just a little scaffolding that generates some native code and executes it. This should come with a decent testing infrastructure. We could prepare gates for the next milestone.

# Milestone 1

This should be a simple implementation, proof of concept so to speak.

We need to make sure that keccak is working with our system. It uses the following gates:

1. 0x03 BXOR (Bitwise XOR) - 1,344 times per permutation
2. 0x06 BXOR_MULTI (Multi-operand XOR) - 120 times per permutation
3. 0x07 FAX (Fused AND-XOR: (A & B) ^ C) - 600 times per permutation
4. 0x43 ROTR (64-bit rotate right) - 696 times per permutation
5. 0x60 ASSERT_EQ (Assert equality) - 25 times total (validation)

Assertion failures should be handled as just counting. The evaluation succeeded only if the
assertion count is 0.

Hints are not supported at this point.

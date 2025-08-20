# Signed 64-bit Multiplication

This project contains an (incomplete) [Lean4](https://lean-lang.org) formalization of an algorithm to compute 64-bit × 64-bit → 128-bit signed multiplication using unsigned multiplication with high-word correction.

This is used in the [smul gate](../../crates/frontend/src/compiler/gate/smul.rs).

## Building

To build the project (i.e check the proofs) you must first install Lean4:

* https://lean-lang.org/install/manual

Then run:

* `lake build`

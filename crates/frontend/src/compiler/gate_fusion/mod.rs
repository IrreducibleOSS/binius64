//! Gate fusion optimization.
//!
//! The main cost of our system is coming from the number of AND constraints. The less we have the
//! cheaper it is.
//!
//! Our AND constraints are powerful construct construct. They can handle a single AND of two XOR
//! combinations where each of the values could be shifted.
//!
//! `ConstraintBuilder` which this pass operates consists of AND, MUL and linear constraints. Linear
//! constraints are basically are constraints that define a single wire using a XOR combination
//! and/or shifts. Since our system does not suppose standalone linear combinations they will have
//! to be promoted to AND constraints.
//!
//! BUT we have a chance of avoiding that if we manage to inline that wire into every consumer
//! constraint which means we don't have to commit that value and thus we don't need an AND
//! constraint!

use legraph::LeGraph;

use crate::compiler::{Wire, constraint_builder::ConstraintBuilder};

mod commit_set;
mod legraph;
mod patch;

mod stat;
#[cfg(test)]
mod tests;

use stat::Stat;

pub fn run_pass(cb: &mut ConstraintBuilder, all_one: Wire) {
	let mut stat = Stat::new(cb);

	let mut leg = LeGraph::new(cb, &mut stat);
	commit_set::run_decide_commit_set(&mut leg, &mut stat);
	let patches = patch::build(cb, &leg, all_one);
	patch::apply_patches(cb, patches);

	// Logic of identifying the commit_set.
	//
	// here we need to iteratively discover what is inlinable or what we should commit.
	//
	// We only consider inlining linear constraints. Linear constraints are either xor or shifts.
	//
	// An inlining decision is all-or-nothing. That means that either ALL users of a wire can be
	// inlined, or none of them can. To demonstrate this imagine:
	//
	//     x = ...
	//     y = x ^ ...
	//     z = x >> 2 ^ ...
	//
	// Assume `x` can be inlined into `y` but then we discover that we cannot inline it into `z`.
	// That means there is no sense to inline `x` into `y` either.
	//
	// A linear constraint can inline into other linear constraints or into non-linear constraints.
	// By inlining every use of a linear constraint into non-linear constraints we may get rid of
	// linear constraint, or equivalently avoid promiting it into non-linear one down the pipeline.
	//
	// For that we need to identify what can be inlined or not. We are performing this checking
	// starting scanning from the non-linear constraints. Any use of a linear definition in a
	// non-linear constraint is called a root.
	//
	// for every root:
	//   we descend through the root expressions sinking down the rotations (or emulating that).
	//   when we descend from x to y and
	//        discover that y is already committed ⇒ skip, otherwise:
	//        if we discover that `y` is non-linear ⇒ skip, otherwise:
	//        if we discover that it cannot be inlined (incompatible shift, ) ⇒ we mark y as
	//        committed.
	//
	// note we don't bail upon the first encountered committed wire. Instead we keep going. That is
	// imagine we are processing xor(a, b, c) and realized that a can be inlined, however b cannot.
	// before we return we still should process c. In other words, we must process the whole operand
	// before returning.
	//
	// note that when we discovered that a wire must be committed that wire will have to become an
	// AND constraint and therefore it will become a new root. So we must iterate until we reach
	// a fixed point. This also might affect the use-def.
	//
	// inlinable patterns:
	//
	// Xor with xor:
	// - xor(xor(a, b), c) -> xor(a, b, c)
	//
	// Shifts. Shifts are composable if of the same type.
	// - shl(shl(x, a), b) -> shl(x, a + b)
	// - shr(shr(x, a), b) -> shr(x, a + b)
	// - rotr(rotr(x, a), b) -> rotr(x, a + b)
	//
	// However, we cannot shift the stuff that's already shifted.
	//
	// - shl(shr(x, a), b) -> the inner shift is not inlineable
	//
	// Crucially, we should be able to rotate-over-xor:
	//
	// - rotr(xor(a, b), n) -> xor(rotr(a, n), rotr(b, n))
	//
	// Therefore, that means that upon we encounter the first shift we should recurse with that
	// shift, eg. for expression rotr(rotr(xor(a, b), x), y) those are going to be the steps.
	//
	// - rotr(x, a). recurse into x with shift type rotr(a)
	// - rotr(y, b). we encounter another rotr while shift type is rotr. we can combine them so we
	//   recurse into y with shift type rotr(a + b)
	// - xor(j, k, l). recurse into j, k, l in turn. j,k,l are all committed so we terminate there.
	//
	// let mut commit_set: BTreeSet<Wire> = BTreeSet::new();
	// plan::plan_phase(&linear_defs, &uses, &mut commit_set, &mut roots, &mut stat);

	// std::fs::write("/tmp/legraph.dot", leg.render_graphviz()).unwrap();
	// eprintln!("{:#?}", stat);
}

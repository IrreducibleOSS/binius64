use binius_core::constraint_system::{
	AndConstraint, MulConstraint, ShiftedValueIndex, ValueIndex, ZeroConstraint,
};
use cranelift_entity::SecondaryMap;
use smallvec::{SmallVec, smallvec};

use crate::compiler::Wire;

/// Builder for creating constraints using Wire references
pub struct ConstraintBuilder {
	pub and_constraints: Vec<WireAndConstraint>,
	pub mul_constraints: Vec<WireMulConstraint>,
	// pub linear_constraints: Vec<WireLinearConstraint>,
	pub zero_constraints: Vec<WireOperand>,
}

impl ConstraintBuilder {
	pub fn new() -> Self {
		Self {
			and_constraints: Vec::new(),
			mul_constraints: Vec::new(),
			zero_constraints: Vec::new(),
		}
	}

	/// Build an AND constraint: A ' B = C
	pub fn and(&mut self) -> AndConstraintBuilder<'_> {
		AndConstraintBuilder::new(self)
	}

	/// Build a MUL constraint: A * B = (HI << 64) | LO
	pub fn mul(&mut self) -> MulConstraintBuilder<'_> {
		MulConstraintBuilder::new(self)
	}

	/// Build a linear constraint: RHS = DST
	/// (where RHS is XOR of shifted values and DST is a
	/// single wire)
	pub fn zero(&mut self) -> ZeroConstraintBuilder<'_> {
		ZeroConstraintBuilder::new(self)
	}

	/// Convert all wire-based constraints to ValueIndex-based constraints.
	pub fn build(
		self,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	) -> (Vec<AndConstraint>, Vec<MulConstraint>, Vec<ZeroConstraint>) {
		let and_constraints = self
			.and_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect::<Vec<_>>();

		let mul_constraints = self
			.mul_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect();

		let zero_constraints = self
			.zero_constraints
			.into_iter()
			.map(|c| ZeroConstraint(expand_and_convert_operand(c, wire_mapping)))
			.collect();

		(and_constraints, mul_constraints, zero_constraints)
	}
}

impl Default for ConstraintBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Helper function to expand rotr operations and convert to ShiftedValueIndex
fn expand_and_convert_operand(
	operand: WireOperand,
	wire_mapping: &SecondaryMap<Wire, ValueIndex>,
) -> Vec<ShiftedValueIndex> {
	let mut result = Vec::new();
	for sw in operand {
		match sw.shift {
			Shift::Rotr(n) => {
				let idx = wire_mapping[sw.wire];
				if n == 0 {
					result.push(ShiftedValueIndex::plain(idx));
				} else {
					// Expand rotr(w, n) => srl(w, n) ⊕ sll(w, 64-n)
					result.push(ShiftedValueIndex::srl(idx, n as usize));
					result.push(ShiftedValueIndex::sll(idx, (64 - n) as usize));
				}
			}
			_ => {
				result.push(sw.to_shifted_value_index(wire_mapping));
			}
		}
	}
	result
}

/// AND constraint using Wire references
pub struct WireAndConstraint {
	pub a: WireOperand,
	pub b: WireOperand,
	pub c: WireOperand,
}

impl WireAndConstraint {
	fn into_constraint(self, wire_mapping: &SecondaryMap<Wire, ValueIndex>) -> AndConstraint {
		AndConstraint {
			a: expand_and_convert_operand(self.a, wire_mapping),
			b: expand_and_convert_operand(self.b, wire_mapping),
			c: expand_and_convert_operand(self.c, wire_mapping),
		}
	}
}

/// MUL constraint using Wire references
pub struct WireMulConstraint {
	pub a: WireOperand,
	pub b: WireOperand,
	pub hi: WireOperand,
	pub lo: WireOperand,
}

impl WireMulConstraint {
	fn into_constraint(self, wire_mapping: &SecondaryMap<Wire, ValueIndex>) -> MulConstraint {
		MulConstraint {
			a: expand_and_convert_operand(self.a, wire_mapping),
			b: expand_and_convert_operand(self.b, wire_mapping),
			hi: expand_and_convert_operand(self.hi, wire_mapping),
			lo: expand_and_convert_operand(self.lo, wire_mapping),
		}
	}
}

/// Operand built from wire expressions
pub type WireOperand = Vec<ShiftedWire>;

#[derive(Copy, Clone, Debug)]
pub struct ShiftedWire {
	pub wire: Wire,
	pub shift: Shift,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Shift {
	None,
	Sll(u32),
	Srl(u32),
	Sar(u32),
	Rotr(u32),
}

impl Shift {
	pub fn is_none(&self) -> bool {
		matches!(self, Self::None)
	}
}

impl ShiftedWire {
	fn to_shifted_value_index(
		self,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	) -> ShiftedValueIndex {
		let idx = wire_mapping[self.wire];
		match self.shift {
			Shift::None => ShiftedValueIndex::plain(idx),
			Shift::Sll(n) => {
				if n == 0 {
					ShiftedValueIndex::plain(idx)
				} else {
					ShiftedValueIndex::sll(idx, n as usize)
				}
			}
			Shift::Srl(n) => {
				if n == 0 {
					ShiftedValueIndex::plain(idx)
				} else {
					ShiftedValueIndex::srl(idx, n as usize)
				}
			}
			Shift::Sar(n) => {
				if n == 0 {
					ShiftedValueIndex::plain(idx)
				} else {
					ShiftedValueIndex::sar(idx, n as usize)
				}
			}
			Shift::Rotr(_) => {
				unreachable!("Rotr should be expanded in expand_and_convert_operand()")
			}
		}
	}
}

pub struct AndConstraintBuilder<'a> {
	builder: &'a mut ConstraintBuilder,
	a: WireOperand,
	b: WireOperand,
	c: WireOperand,
}

impl<'a> AndConstraintBuilder<'a> {
	fn new(builder: &'a mut ConstraintBuilder) -> Self {
		Self {
			builder,
			a: Vec::new(),
			b: Vec::new(),
			c: Vec::new(),
		}
	}

	/// Set the A operand
	pub fn a(mut self, expr: impl Into<WireExpr>) -> Self {
		self.a = expr.into().to_operand();
		self
	}

	/// Set the B operand
	pub fn b(mut self, expr: impl Into<WireExpr>) -> Self {
		self.b = expr.into().to_operand();
		self
	}

	/// Set the C operand
	pub fn c(mut self, expr: impl Into<WireExpr>) -> Self {
		self.c = expr.into().to_operand();
		self
	}

	/// Finalize and add the constraint
	pub fn build(self) {
		self.builder.and_constraints.push(WireAndConstraint {
			a: self.a,
			b: self.b,
			c: self.c,
		});
	}
}

pub struct MulConstraintBuilder<'a> {
	builder: &'a mut ConstraintBuilder,
	a: WireOperand,
	b: WireOperand,
	hi: WireOperand,
	lo: WireOperand,
}

impl<'a> MulConstraintBuilder<'a> {
	fn new(builder: &'a mut ConstraintBuilder) -> Self {
		Self {
			builder,
			a: Vec::new(),
			b: Vec::new(),
			hi: Vec::new(),
			lo: Vec::new(),
		}
	}

	pub fn a(mut self, expr: impl Into<WireExpr>) -> Self {
		self.a = expr.into().to_operand();
		self
	}

	pub fn b(mut self, expr: impl Into<WireExpr>) -> Self {
		self.b = expr.into().to_operand();
		self
	}

	pub fn hi(mut self, expr: impl Into<WireExpr>) -> Self {
		self.hi = expr.into().to_operand();
		self
	}

	pub fn lo(mut self, expr: impl Into<WireExpr>) -> Self {
		self.lo = expr.into().to_operand();
		self
	}

	pub fn build(self) {
		self.builder.mul_constraints.push(WireMulConstraint {
			a: self.a,
			b: self.b,
			hi: self.hi,
			lo: self.lo,
		});
	}
}

pub struct ZeroConstraintBuilder<'a> {
	builder: &'a mut ConstraintBuilder,
	operand: WireOperand,
}

impl<'a> ZeroConstraintBuilder<'a> {
	fn new(builder: &'a mut ConstraintBuilder) -> Self {
		Self {
			builder,
			operand: Vec::new(),
		}
	}

	/// XOR the expr with the existing operand to derive new operand
	pub fn xor(mut self, expr: impl Into<WireExpr>) -> Self {
		self.operand.extend_from_slice(&expr.into().to_operand());
		self
	}

	/// Finalize and add the zero constraint.
	pub fn build(self) {
		self.builder.zero_constraints.push(self.operand);
	}
}

/// Expression for building wire operands as an XOR accumulation of terms.
#[derive(Clone)]
pub struct WireExpr(SmallVec<[WireExprTerm; 4]>);

/// Individual term in XOR expression
#[derive(Copy, Clone)]
pub enum WireExprTerm {
	Wire(Wire),
	Shifted(Wire, ShiftOp),
}

#[derive(Copy, Clone)]
pub enum ShiftOp {
	Sll(u32),
	Srl(u32),
	Sar(u32),
	Rotr(u32),
}

impl WireExpr {
	#[allow(clippy::wrong_self_convention)]
	fn to_operand(self) -> WireOperand {
		let mut result = Vec::new();
		for term in self.0 {
			let shifted_wire = term.to_shifted_wire();

			result.push(shifted_wire);
		}
		result
	}
}

impl WireExprTerm {
	fn to_shifted_wire(self) -> ShiftedWire {
		match self {
			WireExprTerm::Wire(w) => ShiftedWire {
				wire: w,
				shift: Shift::None,
			},
			WireExprTerm::Shifted(w, op) => ShiftedWire {
				wire: w,
				shift: match op {
					ShiftOp::Sll(n) => Shift::Sll(n),
					ShiftOp::Srl(n) => Shift::Srl(n),
					ShiftOp::Sar(n) => Shift::Sar(n),
					ShiftOp::Rotr(n) => Shift::Rotr(n),
				},
			},
		}
	}
}

// Convenience functions
pub fn wire(w: Wire) -> WireExpr {
	WireExpr(smallvec![w.into()])
}

pub fn sll(w: Wire, n: u32) -> WireExprTerm {
	WireExprTerm::Shifted(w, ShiftOp::Sll(n))
}

pub fn srl(w: Wire, n: u32) -> WireExprTerm {
	WireExprTerm::Shifted(w, ShiftOp::Srl(n))
}

pub fn sar(w: Wire, n: u32) -> WireExprTerm {
	WireExprTerm::Shifted(w, ShiftOp::Sar(n))
}

pub fn rotr(w: Wire, n: u32) -> WireExprTerm {
	WireExprTerm::Shifted(w, ShiftOp::Rotr(n))
}

// XOR helpers for common cases
pub fn xor2(a: impl Into<WireExprTerm>, b: impl Into<WireExprTerm>) -> WireExpr {
	WireExpr(smallvec![a.into(), b.into()])
}

pub fn xor3(
	a: impl Into<WireExprTerm>,
	b: impl Into<WireExprTerm>,
	c: impl Into<WireExprTerm>,
) -> WireExpr {
	WireExpr(smallvec![a.into(), b.into(), c.into()])
}

pub fn xor4(
	a: impl Into<WireExprTerm>,
	b: impl Into<WireExprTerm>,
	c: impl Into<WireExprTerm>,
	d: impl Into<WireExprTerm>,
) -> WireExpr {
	WireExpr(smallvec![a.into(), b.into(), c.into(), d.into()])
}

pub fn xor_multi(terms: impl IntoIterator<Item = WireExprTerm>) -> WireExpr {
	WireExpr(terms.into_iter().collect())
}

// Empty operand helper
pub fn empty() -> WireExpr {
	WireExpr(smallvec![])
}

/// Create a linear constraint: rhs = dst
pub fn linear(rhs: impl Into<WireExpr>, dst: impl Into<WireExpr>) -> (WireExpr, WireExpr) {
	(rhs.into(), dst.into())
}

// Implement conversions
impl From<Wire> for WireExpr {
	fn from(w: Wire) -> Self {
		wire(w)
	}
}

impl From<Wire> for WireExprTerm {
	fn from(w: Wire) -> Self {
		WireExprTerm::Wire(w)
	}
}

impl From<WireExprTerm> for WireExpr {
	fn from(expr: WireExprTerm) -> Self {
		WireExpr(smallvec![expr])
	}
}

#[cfg(test)]
mod tests {
	use binius_core::constraint_system::ShiftVariant;
	use cranelift_entity::EntityRef;

	use super::*;

	#[test]
	fn test_rotr_zero_optimization_with_builder() {
		// Test that rotr(w, 0) is optimized to plain(w) using the builder API
		// and produces the expected final ConstraintSystem

		// Setup wire mapping
		let mut wire_mapping = SecondaryMap::new();
		let wire_a = Wire::new(0);
		let wire_b = Wire::new(1);
		let wire_c = Wire::new(2);
		let all_one_wire = Wire::new(3);

		wire_mapping[wire_a] = ValueIndex(0);
		wire_mapping[wire_b] = ValueIndex(1);
		wire_mapping[wire_c] = ValueIndex(2);
		wire_mapping[all_one_wire] = ValueIndex(3);

		// Test case 1: Linear constraint with rotr(0)
		// c = rotr(a, 0) ⊕ b
		{
			let mut builder = ConstraintBuilder::new();

			// Build: c = rotr(a, 0) ⊕ b
			builder
				.zero()
				.xor(xor2(rotr(wire_a, 0), wire_b))
				.xor(wire_c)
				.build();

			let (and_constraints, mul_constraints, _) = builder.build(&wire_mapping);

			// rotr(0) should be optimized to plain wire, so we expect:
			// (a ⊕ b) & all_one = c
			assert_eq!(and_constraints.len(), 1);
			assert_eq!(mul_constraints.len(), 0);

			let and_c = &and_constraints[0];

			// Check operand a: should have plain(0) and plain(1)
			assert_eq!(and_c.a.len(), 2);
			assert!(
				and_c
					.a
					.iter()
					.any(|svi| svi.value_index == ValueIndex(0) && svi.amount == 0)
			);
			assert!(
				and_c
					.a
					.iter()
					.any(|svi| svi.value_index == ValueIndex(1) && svi.amount == 0)
			);

			// Check operand b: should be all_one
			assert_eq!(and_c.b.len(), 1);
			assert_eq!(and_c.b[0].value_index, ValueIndex(3));
			assert_eq!(and_c.b[0].amount, 0);

			// Check operand c: should be wire_c
			assert_eq!(and_c.c.len(), 1);
			assert_eq!(and_c.c[0].value_index, ValueIndex(2));
			assert_eq!(and_c.c[0].amount, 0);
		}

		// Test case 2: Linear constraint with rotr(n) where n > 0
		// c = rotr(a, 5) ⊕ b
		{
			let mut builder = ConstraintBuilder::new();

			// Build: c = rotr(a, 5) ⊕ b
			builder
				.zero()
				.xor(xor2(rotr(wire_a, 5), wire_b))
				.xor(wire_c)
				.build();

			let (and_constraints, mul_constraints, _) = builder.build(&wire_mapping);

			assert_eq!(and_constraints.len(), 1);
			assert_eq!(mul_constraints.len(), 0);

			let and_c = &and_constraints[0];

			// rotr(5) should expand to srl(5) ⊕ sll(59)
			// So operand a should have: srl(a, 5), sll(a, 59), plain(b)
			assert_eq!(and_c.a.len(), 3);

			// Check for srl(a, 5)
			assert!(and_c.a.iter().any(|svi| {
				svi.value_index == ValueIndex(0)
					&& svi.amount == 5
					&& matches!(svi.shift_variant, ShiftVariant::Slr)
			}));

			// Check for sll(a, 59)
			assert!(and_c.a.iter().any(|svi| {
				svi.value_index == ValueIndex(0)
					&& svi.amount == 59
					&& matches!(svi.shift_variant, ShiftVariant::Sll)
			}));

			// Check for plain(b)
			assert!(
				and_c
					.a
					.iter()
					.any(|svi| svi.value_index == ValueIndex(1) && svi.amount == 0)
			);
		}
	}

	#[test]
	fn test_rotr_in_and_constraint() {
		// Test rotr in AND constraints: (a & rotr(b, 0)) ⊕ c = 0

		let mut wire_mapping = SecondaryMap::new();
		let wire_a = Wire::new(0);
		let wire_b = Wire::new(1);
		let wire_c = Wire::new(2);
		let all_one_wire = Wire::new(3);

		wire_mapping[wire_a] = ValueIndex(0);
		wire_mapping[wire_b] = ValueIndex(1);
		wire_mapping[wire_c] = ValueIndex(2);
		wire_mapping[all_one_wire] = ValueIndex(3);

		// Test with rotr(0)
		{
			let mut builder = ConstraintBuilder::new();

			// Build: a & rotr(b, 0) ⊕ c = 0
			builder.and().a(wire_a).b(rotr(wire_b, 0)).c(wire_c).build();

			let (and_constraints, _, _) = builder.build(&wire_mapping);

			assert_eq!(and_constraints.len(), 1);
			let and_c = &and_constraints[0];

			// Check operand a: plain wire_a
			assert_eq!(and_c.a.len(), 1);
			assert_eq!(and_c.a[0].value_index, ValueIndex(0));
			assert_eq!(and_c.a[0].amount, 0);

			// Check operand b: should be plain wire_b (rotr(0) optimized)
			assert_eq!(and_c.b.len(), 1);
			assert_eq!(and_c.b[0].value_index, ValueIndex(1));
			assert_eq!(and_c.b[0].amount, 0);

			// Check operand c: plain wire_c
			assert_eq!(and_c.c.len(), 1);
			assert_eq!(and_c.c[0].value_index, ValueIndex(2));
			assert_eq!(and_c.c[0].amount, 0);
		}

		// Test with rotr(8) - should expand
		{
			let mut builder = ConstraintBuilder::new();

			// Build: a & rotr(b, 8) ⊕ c = 0
			builder.and().a(wire_a).b(rotr(wire_b, 8)).c(wire_c).build();

			let (and_constraints, _, _) = builder.build(&wire_mapping);

			assert_eq!(and_constraints.len(), 1);
			let and_c = &and_constraints[0];

			// Check operand b: should have srl(b, 8) and sll(b, 56)
			assert_eq!(and_c.b.len(), 2);

			assert!(and_c.b.iter().any(|svi| {
				svi.value_index == ValueIndex(1)
					&& svi.amount == 8
					&& matches!(svi.shift_variant, ShiftVariant::Slr)
			}));

			assert!(and_c.b.iter().any(|svi| {
				svi.value_index == ValueIndex(1)
					&& svi.amount == 56
					&& matches!(svi.shift_variant, ShiftVariant::Sll)
			}));
		}
	}

	#[test]
	fn test_complex_expression_with_rotr() {
		// Test a more complex expression: c = rotr(a, 0) ⊕ sll(b, 5) ⊕ rotr(a, 12)

		let mut wire_mapping = SecondaryMap::new();
		let wire_a = Wire::new(0);
		let wire_b = Wire::new(1);
		let wire_c = Wire::new(2);
		let all_one_wire = Wire::new(3);

		wire_mapping[wire_a] = ValueIndex(0);
		wire_mapping[wire_b] = ValueIndex(1);
		wire_mapping[wire_c] = ValueIndex(2);
		wire_mapping[all_one_wire] = ValueIndex(3);

		let mut builder = ConstraintBuilder::new();

		// Build complex expression
		builder
			.zero()
			.xor(xor3(rotr(wire_a, 0), sll(wire_b, 5), rotr(wire_a, 12)))
			.xor(wire_c)
			.build();

		let (and_constraints, mul_constraints, _) = builder.build(&wire_mapping);

		assert_eq!(and_constraints.len(), 1);
		assert_eq!(mul_constraints.len(), 0);

		let and_c = &and_constraints[0];

		// Expected operand a components:
		// - plain(a) from rotr(a, 0)
		// - sll(b, 5)
		// - srl(a, 12) from rotr(a, 12)
		// - sll(a, 52) from rotr(a, 12)
		assert_eq!(and_c.a.len(), 4);

		// Check for plain(a) from rotr(0)
		assert!(
			and_c
				.a
				.iter()
				.any(|svi| svi.value_index == ValueIndex(0) && svi.amount == 0),
			"Should have plain(a) from rotr(a, 0)"
		);

		// Check for sll(b, 5)
		assert!(
			and_c.a.iter().any(|svi| {
				svi.value_index == ValueIndex(1)
					&& svi.amount == 5
					&& matches!(svi.shift_variant, ShiftVariant::Sll)
			}),
			"Should have sll(b, 5)"
		);

		// Check for srl(a, 12) from rotr expansion
		assert!(
			and_c.a.iter().any(|svi| {
				svi.value_index == ValueIndex(0)
					&& svi.amount == 12
					&& matches!(svi.shift_variant, ShiftVariant::Slr)
			}),
			"Should have srl(a, 12) from rotr(a, 12)"
		);

		// Check for sll(a, 52) from rotr expansion
		assert!(
			and_c.a.iter().any(|svi| {
				svi.value_index == ValueIndex(0)
					&& svi.amount == 52
					&& matches!(svi.shift_variant, ShiftVariant::Sll)
			}),
			"Should have sll(a, 52) from rotr(a, 12)"
		);
	}
}

use binius_core::constraint_system::{AndConstraint, MulConstraint, ShiftedValueIndex, ValueIndex};
use cranelift_entity::SecondaryMap;
use smallvec::{SmallVec, smallvec};

use crate::compiler::Wire;

/// Builder for creating constraints using Wire references
pub struct ConstraintBuilder {
	pub and_constraints: Vec<WireAndConstraint>,
	pub mul_constraints: Vec<WireMulConstraint>,
	pub linear_constraints: Vec<WireLinearConstraint>,
}

impl ConstraintBuilder {
	pub fn new() -> Self {
		Self {
			and_constraints: Vec::new(),
			mul_constraints: Vec::new(),
			linear_constraints: Vec::new(),
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
	pub fn linear(&mut self) -> LinearConstraintBuilder<'_> {
		LinearConstraintBuilder::new(self)
	}

	/// Convert all wire-based constraints to ValueIndex-based constraints.
	pub fn build(
		self,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
		all_one: Wire,
	) -> (Vec<AndConstraint>, Vec<MulConstraint>) {
		let mut and_constraints = self
			.and_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect::<Vec<_>>();

		let mul_constraints = self
			.mul_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect();

		// Convert linear constraints to AND constraints (rhs & all_one = dst)
		if !self.linear_constraints.is_empty() {
			let all_one = wire_mapping[all_one];
			for linear_constraint in self.linear_constraints {
				let and_constraint = linear_constraint.into_and_constraint(wire_mapping, all_one);
				and_constraints.push(and_constraint);
			}
		}

		(and_constraints, mul_constraints)
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
				// Expand rotr(w, n) => srl(w, n) ⊕ sll(w, 64-n)
				let idx = wire_mapping[sw.wire];
				result.push(ShiftedValueIndex::srl(idx, n as usize));
				result.push(ShiftedValueIndex::sll(idx, (64 - n) as usize));
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

/// LINEAR constraint using Wire references
pub struct WireLinearConstraint {
	pub rhs: WireOperand,
	pub dst: WireOperand,
}

impl WireLinearConstraint {
	fn into_and_constraint(
		self,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
		all_ones: ValueIndex,
	) -> AndConstraint {
		AndConstraint {
			a: expand_and_convert_operand(self.rhs, wire_mapping),
			b: vec![ShiftedValueIndex::plain(all_ones)],
			c: expand_and_convert_operand(self.dst, wire_mapping),
		}
	}
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
			Shift::Sll(n) => ShiftedValueIndex::sll(idx, n as usize),
			Shift::Srl(n) => ShiftedValueIndex::srl(idx, n as usize),
			Shift::Sar(n) => ShiftedValueIndex::sar(idx, n as usize),
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

pub struct LinearConstraintBuilder<'a> {
	builder: &'a mut ConstraintBuilder,
	rhs: WireOperand,
	dst: WireOperand,
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

impl<'a> LinearConstraintBuilder<'a> {
	fn new(builder: &'a mut ConstraintBuilder) -> Self {
		Self {
			builder,
			rhs: Vec::new(),
			dst: Vec::new(),
		}
	}

	/// Set the RHS operand (XOR combination of shifted values)
	pub fn rhs(mut self, expr: impl Into<WireExpr>) -> Self {
		self.rhs = expr.into().to_operand();
		self
	}

	/// Set the DST operand (destination wire)
	pub fn dst(mut self, expr: impl Into<WireExpr>) -> Self {
		self.dst = expr.into().to_operand();
		self
	}

	/// Finalize and add the linear constraint
	pub fn build(self) {
		self.builder.linear_constraints.push(WireLinearConstraint {
			rhs: self.rhs,
			dst: self.dst,
		});
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

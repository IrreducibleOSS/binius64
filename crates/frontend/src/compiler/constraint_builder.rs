use binius_core::constraint_system::{AndConstraint, MulConstraint, ShiftedValueIndex, ValueIndex};
use cranelift_entity::SecondaryMap;
use smallvec::{SmallVec, smallvec};

use crate::compiler::Wire;

/// Builder for creating constraints using Wire references
pub struct ConstraintBuilder {
	and_constraints: Vec<WireAndConstraint>,
	mul_constraints: Vec<WireMulConstraint>,
}

impl ConstraintBuilder {
	pub fn new() -> Self {
		Self {
			and_constraints: Vec::new(),
			mul_constraints: Vec::new(),
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

	/// Convert all wire-based constraints to ValueIndex-based constraints
	pub fn build(
		self,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	) -> (Vec<AndConstraint>, Vec<MulConstraint>) {
		let and_constraints = self
			.and_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect();

		let mul_constraints = self
			.mul_constraints
			.into_iter()
			.map(|c| c.into_constraint(wire_mapping))
			.collect();

		(and_constraints, mul_constraints)
	}
}

impl Default for ConstraintBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// AND constraint using Wire references
struct WireAndConstraint {
	a: WireOperand,
	b: WireOperand,
	c: WireOperand,
}

impl WireAndConstraint {
	fn into_constraint(self, wire_mapping: &SecondaryMap<Wire, ValueIndex>) -> AndConstraint {
		AndConstraint {
			a: self
				.a
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
			b: self
				.b
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
			c: self
				.c
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
		}
	}
}

/// MUL constraint using Wire references
struct WireMulConstraint {
	a: WireOperand,
	b: WireOperand,
	hi: WireOperand,
	lo: WireOperand,
}

impl WireMulConstraint {
	fn into_constraint(self, wire_mapping: &SecondaryMap<Wire, ValueIndex>) -> MulConstraint {
		MulConstraint {
			a: self
				.a
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
			b: self
				.b
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
			hi: self
				.hi
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
			lo: self
				.lo
				.into_iter()
				.map(|sw| sw.to_shifted_value_index(wire_mapping))
				.collect(),
		}
	}
}

/// Operand built from wire expressions
type WireOperand = Vec<ShiftedWire>;

#[derive(Copy, Clone)]
struct ShiftedWire {
	wire: Wire,
	shift: Shift,
}

#[derive(Copy, Clone)]
enum Shift {
	None,
	Sll(u32),
	Srl(u32),
	Sar(u32),
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
}

impl WireExpr {
	#[allow(clippy::wrong_self_convention)]
	fn to_operand(self) -> WireOperand {
		self.0
			.into_iter()
			.map(|term| term.to_shifted_wire())
			.collect()
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

// Empty operand helper
pub fn empty() -> WireExpr {
	WireExpr(smallvec![])
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

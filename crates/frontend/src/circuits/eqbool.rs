use super::basic::gt_const;
use crate::{
	circuits::basic::bool_not,
	compiler::{CircuitBuilder, Wire},
};

/// Computes `out = 1` if `x == y` else `out = 0`.
pub struct EqBool {
	pub x: Wire,
	pub y: Wire,
	pub out: Wire,
}

impl EqBool {
	pub fn new(builder: &mut CircuitBuilder) -> Self {
		let x = builder.add_inout();
		let y = builder.add_inout();
		let out = builder.add_inout();

		let diff = builder.bxor(x, y);

		// diff > 0 ? 1 : 0
		let neq = gt_const(builder, diff, 0);

		// !neq = 1 if diff == 0 else 0
		let eq_val = bool_not(builder, neq);

		builder.assert_eq("eq", eq_val, out);
		EqBool { x, y, out }
	}
}

#[cfg(test)]
mod tests {
	use super::EqBool;
	use crate::{compiler::CircuitBuilder, word::Word};

	#[test]
	fn eqbool_true() {
		let mut b = CircuitBuilder::new();
		let EqBool { x, y, out } = EqBool::new(&mut b);
		let circuit = b.build();

		let mut w = circuit.new_witness_filler();
		w[x] = Word(0x1234);
		w[y] = Word(0x1234);
		w[out] = Word(1);

		circuit.populate_wire_witness(&mut w);
	}

	#[test]
	fn eqbool_false() {
		let mut b = CircuitBuilder::new();
		let EqBool { x, y, out } = EqBool::new(&mut b);
		let circuit = b.build();

		let mut w = circuit.new_witness_filler();
		w[x] = Word(0x1234);
		w[y] = Word(0x1235);
		w[out] = Word(0);

		circuit.populate_wire_witness(&mut w);
	}

	#[test]
	#[should_panic]
	fn fail_if_out_wrong() {
		let mut b = CircuitBuilder::new();
		let EqBool { x, y, out } = EqBool::new(&mut b);
		let circuit = b.build();

		let mut w = circuit.new_witness_filler();
		w[x] = Word(0x1234);
		w[y] = Word(0x1234);
		w[out] = Word(0);

		circuit.populate_wire_witness(&mut w);
	}
}

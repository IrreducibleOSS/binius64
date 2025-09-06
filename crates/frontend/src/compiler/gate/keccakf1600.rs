//! Keccak-f/[1600/] permutation
//!
//! Takes 25 wires representing 5x5x64 state in lane order (column major, `i = x + 5*y`).
//! Commits to 24 * 25 = 600 words to represent states after each of the 24 rounds, where the
//! output of the last round is the output of the gate.
//!
//! # Constraints
//! Generates 25 AND constraints for each round χ step, which is allegedly optimal.

use std::{array, iter::once};

use binius_core::word::Word;
use itertools::izip;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, WireExpr, sll, srl, xor_multi},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

// Gate constants (ι round constants + all ones)
pub const CONSTS: [Word; 25] = [
	Word(0x0000_0000_0000_0001),
	Word(0x0000_0000_0000_8082),
	Word(0x8000_0000_0000_808A),
	Word(0x8000_0000_8000_8000),
	Word(0x0000_0000_0000_808B),
	Word(0x0000_0000_8000_0001),
	Word(0x8000_0000_8000_8081),
	Word(0x8000_0000_0000_8009),
	Word(0x0000_0000_0000_008A),
	Word(0x0000_0000_0000_0088),
	Word(0x0000_0000_8000_8009),
	Word(0x0000_0000_8000_000A),
	Word(0x0000_0000_8000_808B),
	Word(0x8000_0000_0000_008B),
	Word(0x8000_0000_0000_8089),
	Word(0x8000_0000_0000_8003),
	Word(0x8000_0000_0000_8002),
	Word(0x8000_0000_0000_0080),
	Word(0x0000_0000_0000_800A),
	Word(0x8000_0000_8000_000A),
	Word(0x8000_0000_8000_8081),
	Word(0x8000_0000_0000_8080),
	Word(0x0000_0000_8000_0001),
	Word(0x8000_0000_8000_8008),
	Word::ALL_ONE,
];

// ρ rotation offsets r[x,y] in lane order (i = x + 5*y)
pub const R: [u32; 25] = [
	0x00, 0x01, 0x3E, 0x1C, 0x1B, 0x24, 0x2C, 0x06, 0x37, 0x14, 0x03, 0x0A, 0x2B, 0x19, 0x27, 0x29,
	0x2D, 0x0F, 0x15, 0x08, 0x12, 0x02, 0x3D, 0x38, 0x0E,
];

#[derive(Clone, Copy)]
struct RotWire {
	amount: u32,
	wire: Wire,
}

fn plain(wire: Wire) -> RotWire {
	RotWire { wire, amount: 0 }
}

fn rot(amount: u32, operand: &[RotWire]) -> Vec<RotWire> {
	operand
		.iter()
		.map(|rot_wire| RotWire {
			amount: (rot_wire.amount + amount) % 64,
			wire: rot_wire.wire,
		})
		.collect()
}

fn xor(operand1: &[RotWire], operand2: &[RotWire]) -> Vec<RotWire> {
	[operand1, operand2].concat()
}

#[inline(always)]
pub const fn idx(x: usize, y: usize) -> usize {
	(x % 5) + 5 * (y % 5)
}

fn to_wire_expr_terms(wires: &[RotWire]) -> WireExpr {
	let mut terms = Vec::new();
	for &RotWire { wire, amount } in wires {
		if amount == 0 {
			terms.push(wire.into())
		} else {
			terms.extend([sll(wire, amount), srl(wire, 64 - amount)])
		}
	}

	xor_multi(terms)
}

fn emit_and(builder: &mut ConstraintBuilder, a: &[RotWire], b: &[RotWire], c: &[RotWire]) {
	let a = to_wire_expr_terms(a);
	let b = to_wire_expr_terms(b);
	let c = to_wire_expr_terms(c);
	builder.and().a(a).b(b).c(c).build()
}

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &CONSTS,
		n_in: 25,
		n_out: 25,
		n_aux: (24 - 1) * 25 + 24 * 10,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants,
		inputs,
		outputs,
		aux,
		..
	} = data.gate_param();

	assert_eq!(constants.len(), 24 + 1);
	assert_eq!(inputs.len(), 25);
	assert_eq!(outputs.len(), 25);
	assert_eq!(aux.len(), (24 - 1) * 25 + 24 * 10);

	let (all_one, round_constants) = constants.split_last().expect("RC[0..24] + ALL_ONE");

	let round_out = &aux[..(24 - 1) * 25];
	let c_wires = &aux[(24 - 1) * 25..(24 - 1) * 25 + 24 * 5];
	let d_wires = &aux[(24 - 1) * 25 + 24 * 5..];

	let inputs = once(inputs).chain(round_out.chunks(25));
	let c_wires = c_wires.chunks(5);
	let d_wires = d_wires.chunks(5);
	let outputs = round_out.chunks(25).chain(once(outputs));

	for (round, (pre, post, c, d)) in izip!(inputs, outputs, c_wires, d_wires).enumerate() {
		// θ
		let c: [_; 5] = c.try_into().unwrap();
		for i in 0..5 {
			let terms: [_; 5] = array::from_fn(|j| plain(pre[idx(i, j)]));
			emit_and(builder, &terms, &[plain(*all_one)], &[plain(c[i])]);
		}

		let d: [_; 5] = d.try_into().unwrap();
		for i in 0..5 {
			let terms = xor(&[plain(c[(i + 4) % 5])], &rot(1, &[plain(c[(i + 1) % 5])]));
			emit_and(builder, &terms, &[plain(*all_one)], &[plain(d[i])]);
		}

		let a: [Vec<RotWire>; 25] = array::from_fn(|i| xor(&[plain(pre[i])], &[plain(d[i % 5])]));

		// ρ & π
		let mut b: [Vec<RotWire>; 25] = Default::default();
		for x in 0..5 {
			for y in 0..5 {
				let i = idx(x, y);
				b[idx(y, 2 * x + 3 * y)] = rot(R[i], &a[i]);
			}
		}

		// χ & ι
		for x in 0..5 {
			for y in 0..5 {
				let i = idx(x, y);

				let and_a = xor(&[plain(*all_one)], &b[idx(x + 1, y)]);
				let and_b = &b[idx(x + 2, y)];

				let mut and_c = xor(&[plain(post[i])], &b[i]);
				if i == 0 {
					and_c.push(plain(round_constants[round]));
				}

				emit_and(builder, &and_a, and_b, &and_c);
			}
		}
	}
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		inputs,
		outputs,
		aux,
		..
	} = data.gate_param();

	assert_eq!(inputs.len(), 25);
	assert_eq!(outputs.len(), 25);
	assert_eq!(aux.len(), (24 - 1) * 25 + 24 * 10);

	let round_out = &aux[..(24 - 1) * 25];
	let c_wires = &aux[(24 - 1) * 25..(24 - 1) * 25 + 24 * 5];
	let d_wires = &aux[(24 - 1) * 25 + 24 * 5..];

	let mut wires = Vec::with_capacity((24 + 1) * 25 + 24 * 10);
	wires.extend_from_slice(inputs);

	let round_out_wires = round_out.chunks(25).chain(once(outputs));
	let c_wires = c_wires.chunks(5);
	let d_wires = d_wires.chunks(5);
	for (round_out, c_wires, d_wires) in izip!(round_out_wires, c_wires, d_wires) {
		wires.extend_from_slice(c_wires);
		wires.extend_from_slice(d_wires);
		wires.extend_from_slice(round_out);
	}

	let regs = wires.into_iter().map(wire_to_reg).collect::<Vec<_>>();

	builder.emit_keccakf1600(
		TryInto::<[u32; (24 + 1) * 25 + 24 * 10]>::try_into(regs)
			.expect("correct number of Keccak intermediates"),
	);
}

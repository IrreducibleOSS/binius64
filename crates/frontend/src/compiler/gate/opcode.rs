use crate::word::Word;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
	// Bitwise operations
	Band,
	Bxor,
	Bor,

	// Arithmetic
	IaddCinCout,
	Iadd32,
	Imul,

	// Shifts
	Shr,
	Shl,
	Shr32,
	Rotr32,

	// Comparisons
	IcmpUlt,
	IcmpEq,

	// Extraction
	ExtractByte,

	// Assertions
	AssertEq,
	Assert0,
	AssertBand0,
	AssertEqCond,
}

pub struct OpcodeShape {
	pub const_in: &'static [Word],
	pub n_in: usize,
	pub n_out: usize,
	pub n_internal: usize,
	pub n_imm: usize,
}

impl Opcode {
	pub fn shape(&self) -> OpcodeShape {
		match self {
			// Bitwise operations
			Opcode::Band => OpcodeShape {
				const_in: &[],
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Bxor => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Bor => OpcodeShape {
				const_in: &[],
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},

			// Arithmetic
			Opcode::IaddCinCout => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 3,
				n_out: 2,
				n_internal: 1,
				n_imm: 0,
			},
			Opcode::Iadd32 => OpcodeShape {
				const_in: &[Word::MASK_32],
				n_in: 2,
				n_out: 1,
				n_imm: 0,
				n_internal: 1,
			},
			Opcode::Imul => OpcodeShape {
				const_in: &[],
				n_in: 2,
				n_out: 2,
				n_internal: 0,
				n_imm: 0,
			},

			// Shifts
			Opcode::Shr => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 1,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Shl => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 1,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Shr32 => OpcodeShape {
				const_in: &[Word::MASK_32],
				n_in: 1,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Rotr32 => OpcodeShape {
				const_in: &[Word::MASK_32],
				n_in: 1,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},

			// Comparisons
			Opcode::IcmpUlt => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 2,
				n_out: 1,
				n_internal: 1,
				n_imm: 0,
			},
			Opcode::IcmpEq => OpcodeShape {
				const_in: &[],
				n_in: 3,
				n_out: 1,
				n_internal: 1,
				n_imm: 0,
			},

			// Extraction
			Opcode::ExtractByte => OpcodeShape {
				const_in: &[Word(0xFF), Word(0xFFFFFFFFFFFFFF00u64)],
				n_in: 1,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},

			// Assertions (no outputs)
			Opcode::AssertEq => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 2,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Assert0 => OpcodeShape {
				const_in: &[Word::ALL_ONE],
				n_in: 1,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::AssertBand0 => OpcodeShape {
				const_in: &[],
				n_in: 2,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::AssertEqCond => OpcodeShape {
				const_in: &[],
				n_in: 3,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
		}
	}
}

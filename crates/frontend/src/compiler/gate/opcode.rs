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
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Bxor => OpcodeShape {
				n_in: 3,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Bor => OpcodeShape {
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 0,
			},

			// Arithmetic
			Opcode::IaddCinCout => OpcodeShape {
				n_in: 4,
				n_out: 1,
				n_internal: 1,
				n_imm: 0,
			},
			Opcode::Iadd32 => OpcodeShape {
				n_in: 3,
				n_out: 1,
				n_imm: 0,
				n_internal: 1,
			},
			Opcode::Imul => OpcodeShape {
				n_in: 2,
				n_out: 2,
				n_internal: 0,
				n_imm: 0,
			},

			// Shifts
			Opcode::Shr => OpcodeShape {
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Shl => OpcodeShape {
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Shr32 => OpcodeShape {
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},
			Opcode::Rotr32 => OpcodeShape {
				n_in: 2,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},

			// Comparisons
			Opcode::IcmpUlt => OpcodeShape {
				n_in: 3,
				n_out: 1,
				n_internal: 1,
				n_imm: 0,
			},
			Opcode::IcmpEq => OpcodeShape {
				n_in: 3,
				n_out: 1,
				n_internal: 1,
				n_imm: 0,
			},

			// Extraction
			Opcode::ExtractByte => OpcodeShape {
				n_in: 3,
				n_out: 1,
				n_internal: 0,
				n_imm: 1,
			},

			// Assertions (no outputs)
			Opcode::AssertEq => OpcodeShape {
				n_in: 3,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::Assert0 => OpcodeShape {
				n_in: 2,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::AssertBand0 => OpcodeShape {
				n_in: 2,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
			Opcode::AssertEqCond => OpcodeShape {
				n_in: 3,
				n_out: 0,
				n_internal: 0,
				n_imm: 0,
			},
		}
	}
}

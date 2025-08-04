use binius_core::word::Word;

use crate::compiler::gate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opcode {
	// Bitwise operations
	Band,
	Bxor,
	Bor,

	// Arithmetic
	IaddCinCout,
	Iadd32,
	IsubBinBout,
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
			Opcode::Band => gate::band::shape(),
			Opcode::Bxor => gate::bxor::shape(),
			Opcode::Bor => gate::bor::shape(),

			// Arithmetic
			Opcode::IaddCinCout => gate::iadd_cin_cout::shape(),
			Opcode::Iadd32 => gate::iadd32::shape(),
			Opcode::IsubBinBout => gate::isub_bin_bout::shape(),
			Opcode::Imul => gate::imul::shape(),

			// Shifts
			Opcode::Shr => gate::shr::shape(),
			Opcode::Shl => gate::shl::shape(),
			Opcode::Shr32 => gate::shr32::shape(),
			Opcode::Rotr32 => gate::rotr32::shape(),

			// Comparisons
			Opcode::IcmpUlt => gate::icmp_ult::shape(),
			Opcode::IcmpEq => gate::icmp_eq::shape(),

			// Extraction
			Opcode::ExtractByte => gate::extract_byte::shape(),

			// Assertions (no outputs)
			Opcode::AssertEq => gate::assert_eq::shape(),
			Opcode::Assert0 => gate::assert_0::shape(),
			Opcode::AssertBand0 => gate::assert_band_0::shape(),
			Opcode::AssertEqCond => gate::assert_eq_cond::shape(),
		}
	}
}

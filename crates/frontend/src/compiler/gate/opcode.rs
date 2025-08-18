use binius_core::word::Word;

use crate::compiler::gate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opcode {
	// Bitwise operations
	Band,
	Bxor,
	BxorMulti,
	Bor,

	// Selection
	Select,

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
	Rotl64,

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

	// Hints
	BigUintDivideHint,
	ModInverseHint,
}

pub struct OpcodeShape {
	pub const_in: &'static [Word],
	pub n_in: usize,
	pub n_out: usize,
	pub n_internal: usize,
	pub n_scratch: usize,
	pub n_imm: usize,
}

impl Opcode {
	pub fn shape(&self, dimensions: &[usize]) -> OpcodeShape {
		assert_eq!(self.is_const_shape(), dimensions.is_empty());

		match self {
			// Bitwise operations
			Opcode::Band => gate::band::shape(),
			Opcode::Bxor => gate::bxor::shape(),
			Opcode::BxorMulti => gate::bxor_multi::shape(dimensions),
			Opcode::Bor => gate::bor::shape(),

			// Selection
			Opcode::Select => gate::select::shape(),

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
			Opcode::Rotl64 => gate::rotl64::shape(),

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

			// Hints (no constraints)
			Opcode::BigUintDivideHint => gate::biguint_divide_hint::shape(dimensions),
			Opcode::ModInverseHint => gate::mod_inverse_hint::shape(dimensions),
		}
	}

	pub fn is_const_shape(&self) -> bool {
		#[allow(clippy::match_like_matches_macro)]
		match self {
			Opcode::BigUintDivideHint => false,
			Opcode::ModInverseHint => false,
			Opcode::BxorMulti => false,
			_ => true,
		}
	}
}

use crate::compiler::{
	circuit,
	constraint_builder::ConstraintBuilder,
	gate_graph::{Gate, GateGraph},
};

pub mod opcode;

pub use opcode::Opcode;

pub mod assert_0;
pub mod assert_band_0;
pub mod assert_eq;
pub mod assert_eq_cond;
pub mod band;
pub mod bor;
pub mod bxor;
pub mod extract_byte;
pub mod iadd32;
pub mod iadd_cin_cout;
pub mod icmp_eq;
pub mod icmp_ult;
pub mod imul;
pub mod isub_bin_bout;
pub mod mod_reduce_hint;
pub mod rotl64;
pub mod rotr32;
pub mod shl;
pub mod shr;
pub mod shr32;

pub fn constrain(gate: Gate, graph: &GateGraph, builder: &mut ConstraintBuilder) {
	let data = &graph.gates[gate];
	match data.opcode {
		Opcode::Band => band::constrain(gate, data, builder),
		Opcode::Bxor => bxor::constrain(gate, data, builder),
		Opcode::Bor => bor::constrain(gate, data, builder),
		Opcode::IaddCinCout => iadd_cin_cout::constrain(gate, data, builder),
		Opcode::Iadd32 => iadd32::constrain(gate, data, builder),
		Opcode::IsubBinBout => isub_bin_bout::constrain(gate, data, builder),
		Opcode::Shr32 => shr32::constrain(gate, data, builder),
		Opcode::Rotr32 => rotr32::constrain(gate, data, builder),
		Opcode::Rotl64 => rotl64::constrain(gate, data, builder),
		Opcode::AssertEq => assert_eq::constrain(gate, data, builder),
		Opcode::Assert0 => assert_0::constrain(gate, data, builder),
		Opcode::AssertBand0 => assert_band_0::constrain(gate, data, builder),
		Opcode::Imul => imul::constrain(gate, data, builder),
		Opcode::AssertEqCond => assert_eq_cond::constrain(gate, data, builder),
		Opcode::IcmpUlt => icmp_ult::constrain(gate, data, builder),
		Opcode::IcmpEq => icmp_eq::constrain(gate, data, builder),
		Opcode::ExtractByte => extract_byte::constrain(gate, data, builder),
		Opcode::Shr => shr::constrain(gate, data, builder),
		Opcode::Shl => shl::constrain(gate, data, builder),
		// Hints do not introduce constraints
		Opcode::ModReduceHint => (),
	}
}

pub fn evaluate(gate: Gate, graph: &GateGraph, w: &mut circuit::WitnessFiller) {
	let data = &graph.gates[gate];
	let assertion_path = graph.assertion_names[gate];

	match data.opcode {
		Opcode::Band => band::evaluate(gate, data, w),
		Opcode::Bxor => bxor::evaluate(gate, data, w),
		Opcode::Bor => bor::evaluate(gate, data, w),
		Opcode::IaddCinCout => iadd_cin_cout::evaluate(gate, data, w),
		Opcode::Iadd32 => iadd32::evaluate(gate, data, w),
		Opcode::IsubBinBout => isub_bin_bout::evaluate(gate, data, w),
		Opcode::Shr32 => shr32::evaluate(gate, data, w),
		Opcode::Rotr32 => rotr32::evaluate(gate, data, w),
		Opcode::Rotl64 => rotl64::evaluate(gate, data, w),
		Opcode::AssertEq => assert_eq::evaluate(gate, data, assertion_path, w),
		Opcode::Assert0 => assert_0::evaluate(gate, data, assertion_path, w),
		Opcode::AssertBand0 => assert_band_0::evaluate(gate, data, assertion_path, w),
		Opcode::Imul => imul::evaluate(gate, data, w),
		Opcode::AssertEqCond => assert_eq_cond::evaluate(gate, data, assertion_path, w),
		Opcode::IcmpUlt => icmp_ult::evaluate(gate, data, w),
		Opcode::IcmpEq => icmp_eq::evaluate(gate, data, w),
		Opcode::ExtractByte => extract_byte::evaluate(gate, data, w),
		Opcode::Shr => shr::evaluate(gate, data, w),
		Opcode::Shl => shl::evaluate(gate, data, w),
		Opcode::ModReduceHint => mod_reduce_hint::evaluate(gate, data, w),
	}
}

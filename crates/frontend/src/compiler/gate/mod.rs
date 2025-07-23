use crate::{
	compiler::{
		circuit,
		gate_graph::{Gate, GateGraph},
	},
	constraint_system::ConstraintSystem,
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
pub mod rotr32;
pub mod shl;
pub mod shr;
pub mod shr32;

pub fn constrain(
	gate: Gate,
	graph: &GateGraph,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let data = &graph.gates[gate];
	match data.opcode {
		Opcode::Band => band::constrain(gate, data, circuit, cs),
		Opcode::Bxor => bxor::constrain(gate, data, circuit, cs),
		Opcode::Bor => bor::constrain(gate, data, circuit, cs),
		Opcode::IaddCinCout => iadd_cin_cout::constrain(gate, data, circuit, cs),
		Opcode::Iadd32 => iadd32::constrain(gate, data, circuit, cs),
		Opcode::Shr32 => shr32::constrain(gate, data, circuit, cs),
		Opcode::Rotr32 => rotr32::constrain(gate, data, circuit, cs),
		Opcode::AssertEq => assert_eq::constrain(gate, data, circuit, cs),
		Opcode::Assert0 => assert_0::constrain(gate, data, circuit, cs),
		Opcode::AssertBand0 => assert_band_0::constrain(gate, data, circuit, cs),
		Opcode::Imul => imul::constrain(gate, data, circuit, cs),
		Opcode::AssertEqCond => assert_eq_cond::constrain(gate, data, circuit, cs),
		Opcode::IcmpUlt => icmp_ult::constrain(gate, data, circuit, cs),
		Opcode::IcmpEq => icmp_eq::constrain(gate, data, circuit, cs),
		Opcode::ExtractByte => extract_byte::constrain(gate, data, circuit, cs),
		Opcode::Shr => shr::constrain(gate, data, circuit, cs),
		Opcode::Shl => shl::constrain(gate, data, circuit, cs),
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
		Opcode::Shr32 => shr32::evaluate(gate, data, w),
		Opcode::Rotr32 => rotr32::evaluate(gate, data, w),
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
	}
}

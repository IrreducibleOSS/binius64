use crate::compiler::{
	constraint_builder::ConstraintBuilder,
	eval_form::BytecodeBuilder,
	gate_graph::{Gate, GateData, GateGraph},
	hints::{BigUintDivideHint, HintRegistry, ModInverseHint},
};

pub mod opcode;

pub use opcode::Opcode;

pub mod assert_0;
pub mod assert_band_0;
pub mod assert_eq;
pub mod assert_eq_cond;
pub mod band;
pub mod biguint_divide_hint;
pub mod bor;
pub mod bxor;
pub mod extract_byte;
pub mod iadd32;
pub mod iadd_cin_cout;
pub mod icmp_eq;
pub mod icmp_ult;
pub mod imul;
pub mod isub_bin_bout;
pub mod mod_inverse_hint;
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
		Opcode::BigUintDivideHint => (),
		Opcode::ModInverseHint => (),
	}
}

/// Emit bytecode for a single gate
pub fn emit_gate_bytecode(
	gate: Gate,
	data: &GateData,
	graph: &GateGraph,
	builder: &mut BytecodeBuilder,
	wire_to_reg: impl Fn(crate::compiler::gate_graph::Wire) -> u32 + Copy,
	hint_registry: &mut HintRegistry,
) {
	match data.opcode {
		Opcode::Band => band::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Bxor => bxor::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Bor => bor::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::IaddCinCout => iadd_cin_cout::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Iadd32 => iadd32::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::IsubBinBout => isub_bin_bout::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Shr32 => shr32::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Rotr32 => rotr32::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Rotl64 => rotl64::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::AssertEq => {
			let assertion_path = graph.assertion_names[gate];
			assert_eq::emit_eval_bytecode(gate, data, assertion_path, builder, wire_to_reg)
		}
		Opcode::Assert0 => {
			let assertion_path = graph.assertion_names[gate];
			assert_0::emit_eval_bytecode(gate, data, assertion_path, builder, wire_to_reg)
		}
		Opcode::AssertBand0 => {
			let assertion_path = graph.assertion_names[gate];
			assert_band_0::emit_eval_bytecode(gate, data, assertion_path, builder, wire_to_reg)
		}
		Opcode::AssertEqCond => {
			let assertion_path = graph.assertion_names[gate];
			assert_eq_cond::emit_eval_bytecode(gate, data, assertion_path, builder, wire_to_reg)
		}
		Opcode::Imul => imul::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::IcmpUlt => icmp_ult::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::IcmpEq => icmp_eq::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::ExtractByte => extract_byte::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Shr => shr::emit_eval_bytecode(gate, data, builder, wire_to_reg),
		Opcode::Shl => shl::emit_eval_bytecode(gate, data, builder, wire_to_reg),

		// Hint-based gates
		Opcode::ModInverseHint => {
			let hint_id = hint_registry.register(Box::new(ModInverseHint::new()));
			mod_inverse_hint::emit_eval_bytecode(gate, data, builder, wire_to_reg, hint_id)
		}
		Opcode::BigUintDivideHint => {
			let hint_id = hint_registry.register(Box::new(BigUintDivideHint::new()));
			biguint_divide_hint::emit_eval_bytecode(gate, data, builder, wire_to_reg, hint_id)
		}
	}
}

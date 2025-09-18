// Copyright 2025 Irreducible Inc.

use std::{env, fs, mem::ManuallyDrop, path::PathBuf};

use binius_core::{ValueIndex, ValueVec, Word};
use cranelift_entity::{EntitySet, SecondaryMap};
use inkwell::{
	AddressSpace, IntPredicate, OptimizationLevel,
	builder::Builder,
	context::Context,
	execution_engine::ExecutionEngine,
	module::Module,
	passes::PassBuilderOptions,
	targets::{CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetMachine},
	types::{BasicType, IntType},
	values::{FunctionValue, IntValue, PointerValue},
};

use crate::{
	Wire,
	compiler::{
		circuit::PopulateError,
		gate::opcode::Opcode,
		gate_graph::{GateData, GateGraph, GateParam, WireKind},
		hints::HintRegistry,
	},
};

/// Runtime context passed to the compiled entry point.
#[allow(dead_code)]
#[repr(C)]
pub struct RuntimeContext {
	pub values_ptr: *mut Word,
	pub assertion_counter_ptr: *mut u32,
}

impl RuntimeContext {
	fn new(value_slice: &mut [Word], assertion_counter: &mut u32) -> Self {
		Self {
			values_ptr: value_slice.as_mut_ptr(),
			assertion_counter_ptr: assertion_counter as *mut u32,
		}
	}
}

/// Entry point signature for the generated machine code.
#[allow(dead_code)]
type EntryPoint = unsafe extern "C" fn(*mut RuntimeContext);

/// `LlvmEvalForm` encapsulates compiled code ready for evaluation of the circuit.
#[allow(dead_code)]
pub struct LlvmEvalForm {
	jit: OwnedJit,
	entry: EntryPoint,
	n_eval_insn: usize,
}

#[allow(dead_code)]
impl LlvmEvalForm {
	/// Evaluates the circuit with the given value vec.
	pub fn evaluate(
		&self,
		value_vec: &mut ValueVec,
		_hints: &HintRegistry,
	) -> Result<(), PopulateError> {
		let mut values = value_vec.as_mut_slice();
		let mut assertion_counter: u32 = 0;
		let mut runtime_ctx = RuntimeContext::new(&mut values, &mut assertion_counter);

		unsafe {
			(self.entry)(&mut runtime_ctx as *mut RuntimeContext);
		}

		if assertion_counter == 0 {
			Ok(())
		} else {
			Err(PopulateError {
				messages: Vec::new(),
				total_count: assertion_counter as usize,
			})
		}
	}

	/// Returns the number of evaluation instructions emitted.
	pub fn n_eval_insn(&self) -> usize {
		self.n_eval_insn
	}
}

/// Compiles the gate graph into a natively compiled LlvmEvalForm.
#[allow(dead_code)]
pub fn compile(
	gate_graph: &GateGraph,
	wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	constrained_wires: &EntitySet<Wire>,
) -> LlvmEvalForm {
	Target::initialize_native(&InitializationConfig::default())
		.expect("LLVM target initialization");

	let context_ptr = Box::into_raw(Box::new(Context::create()));
	let opt_selection = selected_optimization_level();
	let ir_paths = ir_dump_paths();
	let module = {
		let context_ref = unsafe { &*context_ptr };
		let mut max_index = 0usize;
		for (wire, _) in gate_graph.wires.iter() {
			if let Some(&value_index) = wire_mapping.get(wire) {
				max_index = max_index.max(value_index.0 as usize);
			}
		}
		let mut cache_len = max_index + 1;
		let mut store_mask = vec![false; cache_len];
		for (wire, data) in gate_graph.wires.iter() {
			let Some(&index) = wire_mapping.get(wire) else {
				continue;
			};
			let idx = index.0 as usize;
			if constrained_wires.contains(wire) || !matches!(data.kind, WireKind::Scratch) {
				store_mask[idx] = true;
			}
		}
		cache_len = cache_len.max(1);
		if store_mask.len() < cache_len {
			store_mask.resize(cache_len, true);
		}
		let mut codegen = CodeGenerator::new(context_ref, cache_len, store_mask);
		for (idx, (_, data)) in gate_graph.gates.iter().enumerate() {
			codegen.lower_gate(idx, data, wire_mapping);
		}
		if let Some(path) = ir_paths.0.as_ref() {
			codegen
				.module
				.print_to_file(path)
				.expect("write raw LLVM IR dump");
		}
		let module = codegen.finish();
		if opt_selection.custom_pipeline {
			run_custom_pipeline(&module);
		}
		if let Some(path) = ir_paths.1.as_ref() {
			module.print_to_file(path).expect("write LLVM IR dump");
		}
		if let Some(path) = assembly_dump_path() {
			dump_assembly(&module, opt_selection.level, path);
		}
		module
	};
	let (jit, entry) = unsafe { OwnedJit::from_raw(context_ptr, module, opt_selection.level) }
		.expect("LLVM JIT creation");

	LlvmEvalForm {
		jit,
		entry,
		n_eval_insn: gate_graph.gates.len(),
	}
}

#[allow(dead_code)]
struct OwnedJit {
	context: *mut Context,
	module: ManuallyDrop<Module<'static>>,
	engine: ManuallyDrop<ExecutionEngine<'static>>,
}

#[allow(dead_code)]
impl OwnedJit {
	unsafe fn from_raw<'ctx>(
		context: *mut Context,
		module: Module<'ctx>,
		opt_level: OptimizationLevel,
	) -> Result<(Self, EntryPoint), String> {
		let engine = module
			.create_jit_execution_engine(opt_level)
			.map_err(|err| err.to_string())?;
		let addr = engine
			.get_function_address("eval_entry")
			.map_err(|err| err.to_string())?;
		let entry: EntryPoint = unsafe { std::mem::transmute(addr as usize) };

		let module = unsafe { std::mem::transmute::<Module<'ctx>, Module<'static>>(module) };
		let engine = unsafe {
			std::mem::transmute::<ExecutionEngine<'ctx>, ExecutionEngine<'static>>(engine)
		};

		let owned = Self {
			context,
			module: ManuallyDrop::new(module),
			engine: ManuallyDrop::new(engine),
		};
		Ok((owned, entry))
	}
}

impl Drop for OwnedJit {
	fn drop(&mut self) {
		unsafe {
			ManuallyDrop::drop(&mut self.engine);
			ManuallyDrop::drop(&mut self.module);
			drop(Box::from_raw(self.context));
		}
	}
}

#[allow(dead_code)]
struct CodeGenerator<'ctx> {
	context: &'ctx Context,
	builder: Builder<'ctx>,
	function: FunctionValue<'ctx>,
	word_type: IntType<'ctx>,
	index_type: IntType<'ctx>,
	counter_type: IntType<'ctx>,
	values_ptr: PointerValue<'ctx>,
	assertion_ptr: PointerValue<'ctx>,
	value_cache: Vec<Option<IntValue<'ctx>>>,
	store_mask: Vec<bool>,
	module: Module<'ctx>,
}

#[allow(dead_code)]
impl<'ctx> CodeGenerator<'ctx> {
	#[allow(deprecated)]
	fn new(context: &'ctx Context, cache_len: usize, store_mask: Vec<bool>) -> Self {
		let module = context.create_module("llvm_eval_form");
		let builder = context.create_builder();

		let word_type = context.i64_type();
		let index_type = context.i64_type();
		let counter_type = context.i32_type();

		let ctx_type = context.struct_type(
			&[
				word_type
					.ptr_type(AddressSpace::default())
					.as_basic_type_enum(),
				counter_type
					.ptr_type(AddressSpace::default())
					.as_basic_type_enum(),
			],
			false,
		);

		let fn_type = context
			.void_type()
			.fn_type(&[ctx_type.ptr_type(AddressSpace::default()).into()], false);
		let function = module.add_function("eval_entry", fn_type, None);

		let entry_block = context.append_basic_block(function, "entry");
		builder.position_at_end(entry_block);

		let ctx_param = function
			.get_first_param()
			.expect("entry has parameter")
			.into_pointer_value();

		let values_ptr = {
			let ptr_ptr = builder
				.build_struct_gep(ctx_type, ctx_param, 0, "values_ptr_ptr")
				.expect("ctx.values");
			builder
				.build_load(word_type.ptr_type(AddressSpace::default()), ptr_ptr, "values_ptr")
				.expect("load ctx.values")
				.into_pointer_value()
		};

		let assertion_ptr = {
			let ptr_ptr = builder
				.build_struct_gep(ctx_type, ctx_param, 1, "assert_ptr_ptr")
				.expect("ctx.assertion_counter");
			builder
				.build_load(counter_type.ptr_type(AddressSpace::default()), ptr_ptr, "assert_ptr")
				.expect("load ctx.assertion_counter")
				.into_pointer_value()
		};

		Self {
			context,
			builder,
			function,
			word_type,
			index_type,
			counter_type,
			values_ptr,
			assertion_ptr,
			value_cache: vec![None; cache_len],
			store_mask,
			module,
		}
	}

	fn lower_gate(
		&mut self,
		gate_index: usize,
		data: &GateData,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	) {
		match data.opcode {
			Opcode::Bxor => self.lower_bxor(data, wire_mapping),
			Opcode::BxorMulti => self.lower_bxor_multi(data, wire_mapping),
			Opcode::Fax => self.lower_fax(data, wire_mapping),
			Opcode::Rotr => self.lower_rotr(data, wire_mapping),
			Opcode::AssertEq => self.lower_assert_eq(gate_index, data, wire_mapping),
			_ => panic!("unsupported gate in LLVM eval form backend: {:?}", data.opcode),
		}
	}

	fn lower_bxor(&mut self, data: &GateData, wire_mapping: &SecondaryMap<Wire, ValueIndex>) {
		let GateParam {
			inputs, outputs, ..
		} = data.gate_param();
		let [lhs, rhs] = inputs else { unreachable!() };
		let [dst] = outputs else { unreachable!() };

		let lhs_val = self.load_value(wire_mapping[*lhs]);
		let rhs_val = self.load_value(wire_mapping[*rhs]);
		let result = self
			.builder
			.build_xor(lhs_val, rhs_val, "bxor")
			.expect("bxor");
		self.store_value(wire_mapping[*dst], result);
	}

	fn lower_bxor_multi(&mut self, data: &GateData, wire_mapping: &SecondaryMap<Wire, ValueIndex>) {
		let GateParam {
			inputs, outputs, ..
		} = data.gate_param();
		let [dst] = outputs else { unreachable!() };

		let mut iter = inputs.iter();
		let first = iter.next().map(|wire| self.load_value(wire_mapping[*wire]));

		let Some(mut acc) = first else {
			// No inputs: store zero.
			let zero = self.word_type.const_zero();
			self.store_value(wire_mapping[*dst], zero);
			return;
		};

		for wire in iter {
			let value = self.load_value(wire_mapping[*wire]);
			acc = self
				.builder
				.build_xor(acc, value, "bxor_multi")
				.expect("bxor_multi");
		}

		self.store_value(wire_mapping[*dst], acc);
	}

	fn lower_fax(&mut self, data: &GateData, wire_mapping: &SecondaryMap<Wire, ValueIndex>) {
		let GateParam {
			inputs, outputs, ..
		} = data.gate_param();
		let [x, y, w] = inputs else { unreachable!() };
		let [dst] = outputs else { unreachable!() };

		let x_val = self.load_value(wire_mapping[*x]);
		let y_val = self.load_value(wire_mapping[*y]);
		let w_val = self.load_value(wire_mapping[*w]);

		let and_val = self
			.builder
			.build_and(x_val, y_val, "fax_and")
			.expect("fax and");
		let result = self
			.builder
			.build_xor(and_val, w_val, "fax_xor")
			.expect("fax xor");
		self.store_value(wire_mapping[*dst], result);
	}

	fn lower_rotr(&mut self, data: &GateData, wire_mapping: &SecondaryMap<Wire, ValueIndex>) {
		let GateParam {
			inputs,
			outputs,
			imm,
			..
		} = data.gate_param();
		let [value_wire] = inputs else { unreachable!() };
		let [dst] = outputs else { unreachable!() };
		let [amount_raw] = imm else { unreachable!() };

		let amount = amount_raw % 64;
		let value = self.load_value(wire_mapping[*value_wire]);

		let result = if amount == 0 {
			value
		} else {
			let right = self
				.builder
				.build_right_shift(
					value,
					self.word_type.const_int(amount as u64, false),
					false,
					"rotr_shr",
				)
				.expect("rotr shr");
			let left_amt = self.word_type.const_int((64 - amount) as u64, false);
			let left = self
				.builder
				.build_left_shift(value, left_amt, "rotr_shl")
				.expect("rotr shl");
			self.builder
				.build_or(right, left, "rotr_or")
				.expect("rotr or")
		};

		self.store_value(wire_mapping[*dst], result);
	}

	fn lower_assert_eq(
		&mut self,
		gate_index: usize,
		data: &GateData,
		wire_mapping: &SecondaryMap<Wire, ValueIndex>,
	) {
		let GateParam { inputs, .. } = data.gate_param();
		let [lhs, rhs] = inputs else { unreachable!() };

		let lhs_val = self.load_value(wire_mapping[*lhs]);
		let rhs_val = self.load_value(wire_mapping[*rhs]);
		let predicate = self
			.builder
			.build_int_compare(IntPredicate::NE, lhs_val, rhs_val, "assert_ne")
			.expect("assert cmp");

		let then_block = self
			.context
			.append_basic_block(self.function, &format!("assert_fail_{gate_index}"));
		let cont_block = self
			.context
			.append_basic_block(self.function, &format!("assert_cont_{gate_index}"));

		self.builder
			.build_conditional_branch(predicate, then_block, cont_block)
			.expect("assert branch");

		self.builder.position_at_end(then_block);
		let loaded = self
			.builder
			.build_load(self.counter_type, self.assertion_ptr, "assert_count")
			.expect("load assert counter")
			.into_int_value();
		let incremented = self
			.builder
			.build_int_add(loaded, self.counter_type.const_int(1, false), "assert_inc")
			.expect("assert add");
		self.builder
			.build_store(self.assertion_ptr, incremented)
			.expect("store assert counter");
		self.builder
			.build_unconditional_branch(cont_block)
			.expect("branch to cont");

		self.builder.position_at_end(cont_block);
	}

	fn finish(self) -> Module<'ctx> {
		let Self {
			builder, module, ..
		} = self;
		builder.build_return(None).expect("build return");
		module
	}

	fn load_value(&mut self, index: ValueIndex) -> IntValue<'ctx> {
		let idx = index.0 as usize;
		if let Some(Some(value)) = self.value_cache.get(idx).copied() {
			return value;
		}
		let ptr = self.value_ptr(index);
		let loaded = self
			.builder
			.build_load(self.word_type, ptr, "load_word")
			.expect("load value")
			.into_int_value();
		if let Some(slot) = self.value_cache.get_mut(idx) {
			*slot = Some(loaded);
		}
		loaded
	}

	fn store_value(&mut self, index: ValueIndex, value: IntValue<'ctx>) {
		let idx = index.0 as usize;
		if let Some(slot) = self.value_cache.get_mut(idx) {
			*slot = Some(value);
		}
		if self.store_mask.get(idx).copied().unwrap_or(true) {
			let ptr = self.value_ptr(index);
			self.builder.build_store(ptr, value).expect("store value");
		}
	}

	fn value_ptr(&mut self, index: ValueIndex) -> PointerValue<'ctx> {
		let offset = self.index_type.const_int(index.0 as u64, false);
		unsafe {
			self.builder
				.build_in_bounds_gep(self.word_type, self.values_ptr, &[offset], "value_ptr")
				.expect("geps")
		}
	}
}

struct OptSelection {
	level: OptimizationLevel,
	custom_pipeline: bool,
}

fn selected_optimization_level() -> OptSelection {
	match env::var("MONBIJOU_LLVM_OPT")
		.unwrap_or_default()
		.to_ascii_lowercase()
		.as_str()
	{
		"default" => OptSelection {
			level: OptimizationLevel::Default,
			custom_pipeline: false,
		},
		"less" => OptSelection {
			level: OptimizationLevel::Less,
			custom_pipeline: false,
		},
		"aggressive" => OptSelection {
			level: OptimizationLevel::Aggressive,
			custom_pipeline: false,
		},
		"custom" => OptSelection {
			level: OptimizationLevel::None,
			custom_pipeline: true,
		},
		"none" | "" => OptSelection {
			level: OptimizationLevel::None,
			custom_pipeline: false,
		},
		_ => OptSelection {
			level: OptimizationLevel::None,
			custom_pipeline: false,
		},
	}
}

fn assembly_dump_path() -> Option<PathBuf> {
	env::var_os("MONBIJOU_LLVM_DUMP_ASM").map(PathBuf::from)
}

fn ir_dump_paths() -> (Option<PathBuf>, Option<PathBuf>) {
	let raw = env::var_os("MONBIJOU_LLVM_DUMP_IR_RAW").map(PathBuf::from);
	let final_path = env::var_os("MONBIJOU_LLVM_DUMP_IR").map(PathBuf::from);
	(raw, final_path)
}

fn dump_assembly(module: &Module<'_>, opt_level: OptimizationLevel, path: PathBuf) {
	let triple = TargetMachine::get_default_triple();
	let target = Target::from_triple(&triple).expect("target");
	let target_machine = target
		.create_target_machine(
			&triple,
			"generic",
			"",
			opt_level,
			RelocMode::Default,
			CodeModel::Default,
		)
		.expect("target machine");
	let buffer = target_machine
		.write_to_memory_buffer(module, FileType::Assembly)
		.expect("emit assembly");
	if let Err(err) = fs::write(&path, buffer.as_slice()) {
		eprintln!("failed to write assembly dump to {:?}: {err}", path);
	}
}

fn run_custom_pipeline(module: &Module<'_>) {
	let triple = TargetMachine::get_default_triple();
	let target = Target::from_triple(&triple).expect("target");
	let target_machine = target
		.create_target_machine(
			&triple,
			"generic",
			"",
			OptimizationLevel::None,
			RelocMode::Default,
			CodeModel::Default,
		)
		.expect("target machine");

	let passes = [
		"mem2reg",
		"instcombine",
		"reassociate",
		"gvn",
		"simplifycfg",
		"adce",
	]
	.join(",");
	let options = PassBuilderOptions::create();
	module
		.run_passes(&passes, &target_machine, options)
		.expect("run custom LLVM pipeline");
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;
	use cranelift_entity::EntitySet;

	use super::*;
	use crate::compiler::{
		gate::opcode::Opcode,
		gate_graph::{GateGraph, WireKind},
		value_vec_alloc::{self, Alloc},
	};

	fn assign_wires(graph: &GateGraph) -> value_vec_alloc::Assignment {
		let mut alloc = Alloc::new();
		for (wire, data) in graph.wires.iter() {
			match data.kind {
				WireKind::Constant(value) => alloc.add_constant(wire, value),
				WireKind::Inout => alloc.add_inout(wire),
				WireKind::Witness => alloc.add_witness(wire),
				WireKind::Internal => alloc.add_internal(wire),
				WireKind::Scratch => alloc.add_scratch(wire),
			}
		}
		alloc.into_assignment()
	}

	fn fill_constants(value_vec: &mut ValueVec, constants: &[Word]) {
		for (idx, constant) in constants.iter().enumerate() {
			value_vec.set(idx, *constant);
		}
	}

	#[test]
	fn bxor_gate_executes() {
		let mut graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		let a = graph.add_inout();
		let b = graph.add_inout();
		let out = graph.add_internal();
		graph.emit_gate(root, Opcode::Bxor, [a, b], [out]);
		graph.rebuild_use_def_chains();

		let assignment = assign_wires(&graph);
		let value_vec_layout = assignment.value_vec_layout.clone();
		let wire_mapping = assignment.wire_mapping;
		let constants = assignment.constants;

		let mut value_vec = ValueVec::new(value_vec_layout);
		fill_constants(&mut value_vec, &constants);
		value_vec[wire_mapping[a]] = Word(0x1234_5678_9ABC_DEF0);
		value_vec[wire_mapping[b]] = Word(0x0FED_CBA9_8765_4321);

		let constrained = EntitySet::new();
		let eval_form = compile(&graph, &wire_mapping, &constrained);
		let hints = HintRegistry::new();
		eval_form.evaluate(&mut value_vec, &hints).unwrap();

		let expected = Word(0x1234_5678_9ABC_DEF0 ^ 0x0FED_CBA9_8765_4321);
		assert_eq!(value_vec[wire_mapping[out]], expected);
	}

	#[test]
	fn fax_gate_executes() {
		let mut graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		let x = graph.add_inout();
		let y = graph.add_inout();
		let w = graph.add_inout();
		let out = graph.add_internal();
		graph.emit_gate(root, Opcode::Fax, [x, y, w], [out]);
		graph.rebuild_use_def_chains();

		let assignment = assign_wires(&graph);
		let value_vec_layout = assignment.value_vec_layout.clone();
		let wire_mapping = assignment.wire_mapping;
		let constants = assignment.constants;

		let mut value_vec = ValueVec::new(value_vec_layout);
		fill_constants(&mut value_vec, &constants);

		let xv = Word(0xFFFF_0000_F0F0_AAAA);
		let yv = Word(0x0F0F_0F0F_3333_3333);
		let wv = Word(0xAAAA_AAAA_5555_5555);
		value_vec[wire_mapping[x]] = xv;
		value_vec[wire_mapping[y]] = yv;
		value_vec[wire_mapping[w]] = wv;

		let constrained = EntitySet::new();
		let eval_form = compile(&graph, &wire_mapping, &constrained);
		let hints = HintRegistry::new();
		eval_form.evaluate(&mut value_vec, &hints).unwrap();

		let expected = Word((xv.0 & yv.0) ^ wv.0);
		assert_eq!(value_vec[wire_mapping[out]], expected);
	}

	#[test]
	fn bxor_multi_executes() {
		let mut graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		let inputs: Vec<_> = (0..4).map(|_| graph.add_inout()).collect();
		let out = graph.add_internal();
		graph.emit_gate_generic(
			root,
			Opcode::BxorMulti,
			inputs.clone(),
			[out],
			&[inputs.len()],
			&[],
		);
		graph.rebuild_use_def_chains();

		let assignment = assign_wires(&graph);
		let value_vec_layout = assignment.value_vec_layout.clone();
		let wire_mapping = assignment.wire_mapping;
		let constants = assignment.constants;

		let mut value_vec = ValueVec::new(value_vec_layout);
		fill_constants(&mut value_vec, &constants);

		let mut expected: u64 = 0;
		for (idx, wire) in inputs.iter().enumerate() {
			let val = Word((idx as u64 + 1) * 0x1111_1111_1111_1111);
			expected ^= val.0;
			value_vec[wire_mapping[*wire]] = val;
		}

		let constrained = EntitySet::new();
		let eval_form = compile(&graph, &wire_mapping, &constrained);
		let hints = HintRegistry::new();
		eval_form.evaluate(&mut value_vec, &hints).unwrap();

		assert_eq!(value_vec[wire_mapping[out]], Word(expected));
	}

	#[test]
	fn rotr_gate_executes() {
		let mut graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		let x = graph.add_inout();
		let out = graph.add_internal();
		let amount = 13_u32;
		graph.emit_gate_imm(root, Opcode::Rotr, [x], [out], amount);
		graph.rebuild_use_def_chains();

		let assignment = assign_wires(&graph);
		let value_vec_layout = assignment.value_vec_layout.clone();
		let wire_mapping = assignment.wire_mapping;
		let constants = assignment.constants;

		let mut value_vec = ValueVec::new(value_vec_layout);
		fill_constants(&mut value_vec, &constants);

		let xv = Word(0x0123_4567_89AB_CDEF);
		value_vec[wire_mapping[x]] = xv;

		let constrained = EntitySet::new();
		let eval_form = compile(&graph, &wire_mapping, &constrained);
		let hints = HintRegistry::new();
		eval_form.evaluate(&mut value_vec, &hints).unwrap();

		let rot = xv.0.rotate_right(amount % 64);
		assert_eq!(value_vec[wire_mapping[out]], Word(rot));
	}

	#[test]
	fn assert_eq_counts_failures() {
		let mut graph = GateGraph::new();
		let root = graph.path_spec_tree.root();
		let x = graph.add_inout();
		let y = graph.add_inout();
		graph.emit_gate(root, Opcode::AssertEq, [x, y], std::iter::empty());
		graph.rebuild_use_def_chains();

		let assignment = assign_wires(&graph);
		let value_vec_layout = assignment.value_vec_layout.clone();
		let wire_mapping = assignment.wire_mapping;
		let constants = assignment.constants;

		let mut value_vec = ValueVec::new(value_vec_layout);
		fill_constants(&mut value_vec, &constants);
		value_vec[wire_mapping[x]] = Word(5);
		value_vec[wire_mapping[y]] = Word(7);

		let constrained = EntitySet::new();
		let eval_form = compile(&graph, &wire_mapping, &constrained);
		let hints = HintRegistry::new();

		let err = eval_form.evaluate(&mut value_vec, &hints).unwrap_err();
		assert_eq!(err.total_count, 1);
		assert!(err.messages.is_empty());

		value_vec[wire_mapping[y]] = Word(5);
		assert!(eval_form.evaluate(&mut value_vec, &hints).is_ok());
	}
}

//! Bytecode interpreter for circuit evaluation

use binius_core::{ValueIndex, ValueVec, Word};

use crate::compiler::{circuit::PopulateError, hints::HintRegistry};

const MAX_ASSERTION_FAILURES: usize = 100;

/// Assertion failure information
pub struct AssertionFailure {
	pub error_id: u32,
	pub message: String,
}

/// Execution context holds a reference to ValueVec during execution
pub struct ExecutionContext<'a> {
	value_vec: &'a mut ValueVec,
	/// The scratch space.
	scratch: Vec<Word>,
	/// Assertion failures recorded during the evaluation of the circuit.
	///
	/// This list is capped by [`MAX_ASSERTION_FAILURES`].
	assertion_failures: Vec<AssertionFailure>,
	/// The total number of assert violations recorded.
	assertion_count: usize,
}

impl<'a> ExecutionContext<'a> {
	pub fn new(value_vec: &'a mut ValueVec, scratch: Vec<Word>) -> Self {
		Self {
			value_vec,
			scratch,
			assertion_failures: Vec::new(),
			assertion_count: 0,
		}
	}

	/// Record an assertion failure with the given error ID and message.
	///
	/// Note that this assertion might be discarded in case there is already too many recorded
	/// assertions.
	#[cold]
	fn note_assertion_failure(&mut self, error_id: u32, message: String) {
		self.assertion_count += 1;
		if self.assertion_failures.len() < MAX_ASSERTION_FAILURES {
			self.assertion_failures
				.push(AssertionFailure { error_id, message });
		}
	}

	/// Check assertions and return error if any failed
	pub fn check_assertions(self) -> Result<(), PopulateError> {
		if !self.assertion_failures.is_empty() {
			Err(PopulateError {
				messages: self
					.assertion_failures
					.into_iter()
					.map(|f| f.message)
					.collect(),
				total_count: self.assertion_count,
			})
		} else {
			Ok(())
		}
	}
}

pub struct Interpreter<'a> {
	bytecode: &'a [u8],
	hints: &'a HintRegistry,
	pc: usize,
}

impl<'a> Interpreter<'a> {
	pub fn new(bytecode: &'a [u8], hints: &'a HintRegistry) -> Self {
		Self {
			bytecode,
			hints,
			pc: 0,
		}
	}

	pub fn run_with_value_vec(
		&mut self,
		value_vec: &mut ValueVec,
		scratch: Vec<Word>,
	) -> Result<(), PopulateError> {
		let mut ctx = ExecutionContext::new(value_vec, scratch);
		self.run(&mut ctx)?;
		ctx.check_assertions()
	}

	pub fn run(&mut self, ctx: &mut ExecutionContext<'_>) -> Result<(), PopulateError> {
		while self.pc < self.bytecode.len() {
			let opcode = self.read_u8();

			match opcode {
				// Bitwise operations
				0x01 => self.exec_band(ctx),
				0x02 => self.exec_bor(ctx),
				0x03 => self.exec_bxor(ctx),
				0x04 => self.exec_bnot(ctx),
				0x05 => self.exec_select(ctx),
				0x06 => self.exec_bxor_multi(ctx),
				0x07 => self.exec_fax(ctx),

				// Shifts
				0x10 => self.exec_sll(ctx),
				0x11 => self.exec_slr(ctx),
				0x12 => self.exec_sar(ctx),

				// Arithmetic
				0x20 => self.exec_iadd_cout(ctx),
				0x21 => self.exec_iadd_cin_cout(ctx),
				0x22 => self.exec_isub_bout(ctx),
				0x23 => self.exec_isub_bin_bout(ctx),
				0x30 => self.exec_imul(ctx),
				0x31 => self.exec_smul(ctx),

				// 32-bit operations
				0x40 => self.exec_iadd_cout32(ctx),
				0x41 => self.exec_rotr32(ctx),
				0x42 => self.exec_shr32(ctx),
				0x43 => self.exec_rotr(ctx),

				// Masks
				0x50 => self.exec_mask_low(ctx),
				0x51 => self.exec_mask_high(ctx),

				// Assertions
				0x60 => self.exec_assert_eq(ctx),
				0x61 => self.exec_assert_eq_cond(ctx),
				0x62 => self.exec_assert_zero(ctx),
				0x63 => self.exec_assert_non_zero(ctx),
				0x64 => self.exec_assert_false(ctx),
				0x65 => self.exec_assert_true(ctx),

				// Hint calls
				0x80 => self.exec_hint(ctx),

				_ => panic!("Unknown opcode: {:#x} at pc={}", opcode, self.pc - 1),
			}
		}
		Ok(())
	}

	// Bitwise operations
	fn exec_band(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let val = self.load(ctx, src1) & self.load(ctx, src2);
		self.store(ctx, dst, val);
	}

	fn exec_bor(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let val = self.load(ctx, src1) | self.load(ctx, src2);
		self.store(ctx, dst, val);
	}

	fn exec_bxor(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let val = self.load(ctx, src1) ^ self.load(ctx, src2);
		self.store(ctx, dst, val);
	}

	fn exec_bnot(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let val = !self.load(ctx, src);
		self.store(ctx, dst, val);
	}

	fn exec_select(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let a = self.read_reg();
		let b = self.read_reg();
		let cond = self.read_reg();
		// Select b if MSB(cond) is 1, otherwise select a
		let cond_val = self.load(ctx, cond);
		let val = if (cond_val.0 as i64) < 0 {
			self.load(ctx, b)
		} else {
			self.load(ctx, a)
		};
		self.store(ctx, dst, val);
	}

	fn exec_bxor_multi(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let n = self.read_u32() as usize;
		let mut val = Word::ZERO;
		for _ in 0..n {
			let src = self.read_reg();
			val = val ^ self.load(ctx, src);
		}
		self.store(ctx, dst, val);
	}

	fn exec_fax(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let src3 = self.read_reg();
		let val = (self.load(ctx, src1) & self.load(ctx, src2)) ^ self.load(ctx, src3);
		self.store(ctx, dst, val);
	}

	// Shifts
	fn exec_sll(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let shift = self.read_u8() as u32;
		let val = self.load(ctx, src) << shift;
		self.store(ctx, dst, val);
	}

	fn exec_slr(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let shift = self.read_u8() as u32;
		let val = self.load(ctx, src) >> shift;
		self.store(ctx, dst, val);
	}

	fn exec_sar(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let shift = self.read_u8() as u32;
		let val = self.load(ctx, src).sar(shift);
		self.store(ctx, dst, val);
	}

	// Arithmetic operations
	fn exec_iadd_cout(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_sum = self.read_reg();
		let dst_cout = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let (sum, cout) = self
			.load(ctx, src1)
			.iadd_cin_cout(self.load(ctx, src2), Word::ZERO);
		self.store(ctx, dst_sum, sum);
		self.store(ctx, dst_cout, cout);
	}

	fn exec_iadd_cin_cout(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_sum = self.read_reg();
		let dst_cout = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let cin = self.read_reg();
		let cin_bit = self.load(ctx, cin) >> 63; // Use MSB as carry bit
		let (sum, cout) = self
			.load(ctx, src1)
			.iadd_cin_cout(self.load(ctx, src2), cin_bit);
		self.store(ctx, dst_sum, sum);
		self.store(ctx, dst_cout, cout);
	}

	fn exec_isub_bout(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_diff = self.read_reg();
		let dst_bout = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let (diff, bout) = self
			.load(ctx, src1)
			.isub_bin_bout(self.load(ctx, src2), Word::ZERO);
		self.store(ctx, dst_diff, diff);
		self.store(ctx, dst_bout, bout);
	}

	fn exec_isub_bin_bout(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_diff = self.read_reg();
		let dst_bout = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let bin = self.read_reg();
		let bin_bit = self.load(ctx, bin) >> 63; // Use MSB as borrow bit
		let (diff, bout) = self
			.load(ctx, src1)
			.isub_bin_bout(self.load(ctx, src2), bin_bit);
		self.store(ctx, dst_diff, diff);
		self.store(ctx, dst_bout, bout);
	}

	fn exec_imul(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_hi = self.read_reg();
		let dst_lo = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let (hi, lo) = self.load(ctx, src1).imul(self.load(ctx, src2));
		self.store(ctx, dst_hi, hi);
		self.store(ctx, dst_lo, lo);
	}

	fn exec_smul(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_hi = self.read_reg();
		let dst_lo = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let (hi, lo) = self.load(ctx, src1).smul(self.load(ctx, src2));
		self.store(ctx, dst_hi, hi);
		self.store(ctx, dst_lo, lo);
	}

	// 32-bit operations
	fn exec_iadd_cout32(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst_sum = self.read_reg();
		let dst_cout = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let (sum, cout) = self.load(ctx, src1).iadd_cout_32(self.load(ctx, src2));
		self.store(ctx, dst_sum, sum);
		self.store(ctx, dst_cout, cout);
	}

	fn exec_rotr32(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let rotate = self.read_u8() as u32;
		let val = self.load(ctx, src).rotr_32(rotate);
		self.store(ctx, dst, val);
	}

	fn exec_shr32(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let shift = self.read_u8() as u32;
		let val = self.load(ctx, src).shr_32(shift);
		self.store(ctx, dst, val);
	}

	fn exec_rotr(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let rotate = self.read_u8() as u32;
		let val = self.load(ctx, src).rotr(rotate);
		self.store(ctx, dst, val);
	}

	// Mask operations
	fn exec_mask_low(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let n_bits = self.read_u8();
		let mask = if n_bits >= 64 {
			Word::ALL_ONE
		} else {
			Word::from_u64((1u64 << n_bits) - 1)
		};
		let val = self.load(ctx, src) & mask;
		self.store(ctx, dst, val);
	}

	fn exec_mask_high(&mut self, ctx: &mut ExecutionContext<'_>) {
		let dst = self.read_reg();
		let src = self.read_reg();
		let n_bits = self.read_u8();
		let mask = if n_bits >= 64 {
			Word::ALL_ONE
		} else {
			Word::from_u64(!((1u64 << (64 - n_bits)) - 1))
		};
		let val = self.load(ctx, src) & mask;
		self.store(ctx, dst, val);
	}

	// Assertions
	fn exec_assert_eq(&mut self, ctx: &mut ExecutionContext<'_>) {
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let error_id = self.read_u32();

		let val1 = self.load(ctx, src1);
		let val2 = self.load(ctx, src2);

		if val1 != val2 {
			ctx.note_assertion_failure(error_id, format!("{val1:?} != {val2:?}"));
		}
	}

	fn exec_assert_eq_cond(&mut self, ctx: &mut ExecutionContext<'_>) {
		let cond = self.read_reg();
		let src1 = self.read_reg();
		let src2 = self.read_reg();
		let error_id = self.read_u32();

		let cond_val = self.load(ctx, cond);

		// Only assert if condition is non-zero
		if cond_val != Word::ZERO {
			let val1 = self.load(ctx, src1);
			let val2 = self.load(ctx, src2);

			if val1 != val2 {
				ctx.note_assertion_failure(
					error_id,
					format!("conditional assert: {val1:?} != {val2:?}"),
				);
			}
		}
	}

	fn exec_assert_zero(&mut self, ctx: &mut ExecutionContext<'_>) {
		let src = self.read_reg();
		let error_id = self.read_u32();

		let val = self.load(ctx, src);

		if val != Word::ZERO {
			ctx.note_assertion_failure(error_id, format!("{val:?} != 0"));
		}
	}

	fn exec_assert_non_zero(&mut self, ctx: &mut ExecutionContext<'_>) {
		let src = self.read_reg();
		let error_id = self.read_u32();

		let val = self.load(ctx, src);

		if val == Word::ZERO {
			ctx.note_assertion_failure(error_id, format!("{val:?} == 0"));
		}
	}

	fn exec_assert_false(&mut self, ctx: &mut ExecutionContext<'_>) {
		let src = self.read_reg();
		let error_id = self.read_u32();

		let val = self.load(ctx, src);

		if val.is_msb_true() {
			ctx.note_assertion_failure(error_id, format!("{val:?} MSB is true"));
		}
	}

	fn exec_assert_true(&mut self, ctx: &mut ExecutionContext<'_>) {
		let src = self.read_reg();
		let error_id = self.read_u32();

		let val = self.load(ctx, src);

		if val.is_msb_false() {
			ctx.note_assertion_failure(error_id, format!("{val:?} MSB is false"));
		}
	}

	// Hint execution
	fn exec_hint(&mut self, ctx: &mut ExecutionContext<'_>) {
		let hint_id = self.read_u32() as usize;

		// Read dimensions
		let n_dimensions = self.read_u16() as usize;
		let mut dimensions = Vec::with_capacity(n_dimensions);
		for _ in 0..n_dimensions {
			dimensions.push(self.read_u32() as usize);
		}

		let n_inputs = self.read_u16() as usize;
		let n_outputs = self.read_u16() as usize;

		// Collect input values
		let mut inputs = Vec::with_capacity(n_inputs);
		for _ in 0..n_inputs {
			let reg = self.read_reg();
			inputs.push(self.load(ctx, reg));
		}

		// Prepare output buffer
		let mut outputs = vec![Word::ZERO; n_outputs];

		self.hints
			.execute(hint_id, &dimensions, &inputs, &mut outputs);

		// Store outputs
		for output_val in outputs {
			let dst = self.read_reg();
			self.store(ctx, dst, output_val);
		}
	}

	fn load(&self, ctx: &ExecutionContext<'_>, reg: u32) -> Word {
		if let Some(scratch_reg) = as_scratch_reg(reg) {
			ctx.scratch[scratch_reg as usize]
		} else {
			ctx.value_vec[ValueIndex(reg)]
		}
	}

	fn store(&self, ctx: &mut ExecutionContext<'_>, reg: u32, value: Word) {
		if let Some(scratch_reg) = as_scratch_reg(reg) {
			ctx.scratch[scratch_reg as usize] = value;
		} else {
			ctx.value_vec.set(reg as usize, value);
		}
	}

	// Bytecode reading helpers
	fn read_u8(&mut self) -> u8 {
		let val = self.bytecode[self.pc];
		self.pc += 1;
		val
	}

	fn read_u16(&mut self) -> u16 {
		let val = u16::from_le_bytes([self.bytecode[self.pc], self.bytecode[self.pc + 1]]);
		self.pc += 2;
		val
	}

	fn read_u32(&mut self) -> u32 {
		let val = u32::from_le_bytes([
			self.bytecode[self.pc],
			self.bytecode[self.pc + 1],
			self.bytecode[self.pc + 2],
			self.bytecode[self.pc + 3],
		]);
		self.pc += 4;
		val
	}

	fn read_reg(&mut self) -> u32 {
		self.read_u32()
	}
}

fn as_scratch_reg(reg: u32) -> Option<u32> {
	if reg & 0x8000_0000 != 0 {
		Some(reg & 0x7FFF_FFFF)
	} else {
		None
	}
}

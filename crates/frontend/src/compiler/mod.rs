use std::{
	cell::{RefCell, RefMut},
	collections::HashMap,
	fmt,
	rc::Rc,
};

use gate::{
	Assert0, AssertBand0, AssertEq, AssertEqCond, Band, Bor, Bxor, ExtractByte, Gate, Iadd32,
	IaddCinCout, IcmpEq, IcmpUlt, Imul, Rotr32, Shl, Shr, Shr32,
};

use crate::{
	constraint_system::{ConstraintSystem, ValueIndex, ValueVec},
	word::Word,
};

mod gate;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct ConstPool {
	pool: HashMap<Word, Wire>,
}

impl ConstPool {
	pub fn new() -> Self {
		ConstPool::default()
	}

	pub fn get(&self, value: Word) -> Option<Wire> {
		self.pool.get(&value).cloned()
	}

	pub fn insert(&mut self, word: Word, wire: Wire) {
		let prev = self.pool.insert(word, wire);
		assert!(prev.is_none());
	}
}

/// A wire through which a value flows in and out of gates.
///
/// The difference from `ValueIndex` is that a wire is abstract. Some wires could be moved during
/// compilation and some wires might be pruned altogether.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Wire(u32);

#[derive(Copy, Clone)]
enum WireKind {
	Constant(Word),
	Inout,
	Private,
}

#[derive(Copy, Clone)]
pub struct WireData {
	kind: WireKind,
}

struct Shared {
	cp: ConstPool,
	n_inout: usize,
	n_witness: usize,
	wires: Vec<WireData>,
	gates: Vec<Box<dyn Gate>>,
}

/// # Clone
///
/// This is a light-weight reference. Cloning is cheap.
#[derive(Clone)]
pub struct CircuitBuilder {
	name: String,
	shared: Rc<RefCell<Option<Shared>>>,
}

impl Default for CircuitBuilder {
	fn default() -> Self {
		CircuitBuilder {
			name: String::new(),
			shared: Rc::new(RefCell::new(Some(Shared {
				cp: ConstPool::new(),
				n_witness: 0,
				n_inout: 0,
				wires: Vec::new(),
				gates: Vec::new(),
			}))),
		}
	}
}

impl CircuitBuilder {
	pub fn new() -> Self {
		CircuitBuilder::default()
	}

	/// # Preconditions
	///
	/// Must be called only once.
	pub fn build(&self) -> Circuit {
		let shared = self.shared.borrow_mut().take();
		let Some(shared) = shared else {
			panic!("CircuitBuilder::build called twice");
		};

		// `ValueVec` expects the wires to be in a certain order. Specifically:
		//
		// 1. const
		// 2. inout
		// 3. witness
		//
		// So we create a mapping between a `Wire` to the final `ValueIndex`.

		// Create a vector of (original_index, priority) pairs and sort by priority.
		let mut indexed_wires: Vec<(usize, u8)> = shared
			.wires
			.iter()
			.enumerate()
			.map(|(i, wire_data)| {
				let priority = match wire_data.kind {
					WireKind::Constant(_) => 0,
					WireKind::Inout => 1,
					WireKind::Private => 2,
				};
				(i, priority)
			})
			.collect();

		indexed_wires.sort_by_key(|(_, priority)| *priority);

		// Create the mapping from original wire index to sorted ValueIndex.
		let mut wire_mapping = vec![ValueIndex(0); shared.wires.len()];
		for (sorted_index, (original_index, _)) in indexed_wires.iter().enumerate() {
			wire_mapping[*original_index] = ValueIndex(sorted_index as u32);
		}

		Circuit {
			shared,
			wire_mapping,
		}
	}

	pub fn subcircuit(&self, name: impl Into<String>) -> CircuitBuilder {
		let name = name.into();
		CircuitBuilder {
			name: format!("{}.{name}", self.name),
			shared: self.shared.clone(),
		}
	}

	fn shared_mut(&self) -> RefMut<'_, Shared> {
		RefMut::map(self.shared.borrow_mut(), |shared| shared.as_mut().unwrap())
	}

	fn emit(&self, gate: impl Gate + 'static) {
		self.shared_mut().gates.push(Box::new(gate))
	}

	fn namespaced(&self, name: String) -> String {
		format!("{}.{name}", self.name)
	}

	fn add_wire(&self, wire_data: WireData) -> Wire {
		let mut shared = self.shared_mut();
		let id = shared.wires.len();
		shared.wires.push(wire_data);
		Wire(id as u32)
	}

	/// Creates a wire from a 64-bit word.
	///
	/// # Arguments
	///
	/// * `word` -  The word to add to the circuit.
	///
	/// # Returns
	///
	/// A `Wire` representing the constant value. The wire might be aliased because the constants
	/// are deduplicated.
	///
	/// # Cost
	///
	/// Constants have no constraint cost - they are "free" in the circuit.
	pub fn add_constant(&self, word: Word) -> Wire {
		if let Some(wire) = self.shared_mut().cp.get(word) {
			return wire;
		}
		let wire = self.add_wire(WireData {
			kind: WireKind::Constant(word),
		});
		self.shared_mut().cp.insert(word, wire);
		wire
	}

	/// Creates a constant wire from a 64-bit unsigned integer.
	///
	/// This method adds a 64-bit constant value to the circuit. The constant is stored
	/// as a `Word` and can be used in constraints and operations.
	///
	/// Constants are automatically deduplicated - multiple calls with the same value
	/// will return the same wire.
	///
	/// # Arguments
	/// * `c` - The 64-bit constant value to add to the circuit
	///
	/// # Returns
	/// A `Wire` representing the constant value that can be used in circuit operations
	pub fn add_constant_64(&self, c: u64) -> Wire {
		self.add_constant(Word(c))
	}

	/// Creates a constant wire from an 8-bit value, zero-extended to 64 bits.
	///
	/// This method takes an 8-bit unsigned integer (byte) and zero-extends it to
	/// a 64-bit value before adding it as a constant to the circuit. The resulting
	/// wire contains the byte value in the lower 8 bits and zeros in the upper 56 bits.
	/// This is commonly used for byte constants in circuits that process byte data.
	///
	/// # Arguments
	/// * `c` - The 8-bit constant value (0-255) to add to the circuit
	pub fn add_constant_zx_8(&self, c: u8) -> Wire {
		self.add_constant(Word(c as u64))
	}

	pub fn add_inout(&self) -> Wire {
		self.shared_mut().n_inout += 1;
		self.add_wire(WireData {
			kind: WireKind::Inout,
		})
	}

	pub fn add_witness(&self) -> Wire {
		self.shared_mut().n_witness += 1;
		self.add_wire(WireData {
			kind: WireKind::Private,
		})
	}

	pub fn band(&self, a: Wire, b: Wire) -> Wire {
		let gate = Band::new(self, a, b);
		let out = gate.c;
		self.emit(gate);
		out
	}

	pub fn bxor(&self, a: Wire, b: Wire) -> Wire {
		let gate = Bxor::new(self, a, b);
		let out = gate.c;
		self.emit(gate);
		out
	}

	/// Bitwise Not
	pub fn bnot(&self, a: Wire) -> Wire {
		let all_one = self.add_constant(Word::ALL_ONE);
		self.bxor(a, all_one)
	}

	pub fn bor(&self, a: Wire, b: Wire) -> Wire {
		let gate = Bor::new(self, a, b);
		let out = gate.c;
		self.emit(gate);
		out
	}

	pub fn iadd_32(&self, a: Wire, b: Wire) -> Wire {
		let gate = Iadd32::new(self, a, b);
		let out = gate.c;
		self.emit(gate);
		out
	}

	/// 64-bit addition with carry input and output.
	///
	/// Performs full 64-bit unsigned addition of two wires plus a carry input.
	///
	/// Returns (sum, carry_out) where sum is the 64-bit result and carry_out
	/// indicates overflow.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn iadd_cin_cout(&self, a: Wire, b: Wire, cin: Wire) -> (Wire, Wire) {
		let gate = IaddCinCout::new(self, a, b, cin);
		let sum = gate.sum;
		let cout = gate.cout;
		self.emit(gate);
		(sum, cout)
	}

	pub fn rotr_32(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 32, "shift amount n={n} out of range");
		let gate = Rotr32::new(self, a, n);
		let out = gate.c;
		self.emit(gate);
		out
	}

	pub fn shr_32(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 32, "shift amount n={n} out of range");
		let gate = Shr32::new(self, a, n);
		let out = gate.c;
		self.emit(gate);
		out
	}

	/// Logical left shift.
	///
	/// Shifts a 64-bit wire left by n bits, filling with zeros from the right.
	///
	/// Returns a << n
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn shl(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 64, "shift amount n={n} out of range");
		let gate = Shl::new(self, a, n);
		let out = gate.c;
		self.emit(gate);
		out
	}

	/// Logical right shift.
	///
	/// Shifts a 64-bit wire right by n bits, filling with zeros from the left.
	///
	/// Returns a >> n
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn shr(&self, a: Wire, n: u32) -> Wire {
		assert!(n < 64, "shift amount n={n} out of range");
		let gate = Shr::new(self, a, n);
		let out = gate.c;
		self.emit(gate);
		out
	}

	/// Equality assertion.
	///
	/// Asserts that two 64-bit wires are equal.
	///
	/// Takes wires x and y and enforces x == y.
	/// If the assertion fails, the circuit will report an error with the given name.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_eq(&self, name: impl Into<String>, x: Wire, y: Wire) {
		let name = self.namespaced(name.into());
		self.emit(AssertEq::new(self, name, x, y))
	}

	/// Vector equality assertion.
	///
	/// Asserts that two arrays of 64-bit wires are equal element-wise.
	///
	/// Takes wire arrays x and y and enforces `x[i] == y[i]` for all `i`.
	/// Each element assertion is named with the base name and index.
	///
	/// # Cost
	///
	/// N AND constraints (one per element).
	pub fn assert_eq_v<const N: usize>(&self, name: impl Into<String>, x: [Wire; N], y: [Wire; N]) {
		let base_name = name.into();
		for i in 0..N {
			self.assert_eq(format!("{base_name}[{i}]"), x[i], y[i]);
		}
	}

	/// Asserts that the given wire equals zero using a single AND constraint.
	/// This is more efficient than using assert_eq with a zero constant.
	pub fn assert_0(&self, name: impl Into<String>, a: Wire) {
		let name = self.namespaced(name.into());
		self.emit(Assert0::new(self, name, a))
	}

	/// Bitwise AND assertion with constant equals zero.
	///
	/// Asserts that the bitwise AND of a wire with a constant equals zero.
	/// This is useful for checking that specific bits are unset.
	///
	/// Takes wire a and constant c and enforces a & c = 0.
	/// If the assertion fails, the circuit will report an error with the given name.
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_band_0(&self, name: impl Into<String>, a: Wire, constant: Word) {
		let name = self.namespaced(name.into());
		self.emit(AssertBand0::new(self, name, a, constant))
	}

	/// 64-bit × 64-bit → 128-bit unsigned multiplication.
	/// Returns (hi, lo) where result = (hi << 64) | lo
	pub fn imul(&self, a: Wire, b: Wire) -> (Wire, Wire) {
		let gate = Imul::new(self, a, b);
		let hi = gate.hi;
		let lo = gate.lo;
		self.emit(gate);
		(hi, lo)
	}

	/// Conditional equality assertion.
	///
	/// Asserts that two 64-bit wires are equal, but only when the mask is all-1.
	/// When mask is all-0, the assertion is a no-op.
	///
	/// Takes wires a, b, and mask and enforces:
	/// - If mask is all-1: a must equal b
	/// - If mask is all-0: no constraint (assertion is ignored)
	///
	/// Pattern: AND((a ^ b), mask, 0)
	///
	/// # Cost
	///
	/// 1 AND constraint.
	pub fn assert_eq_cond(&self, name: impl Into<String>, a: Wire, b: Wire, mask: Wire) {
		let name = self.namespaced(name.into());
		self.emit(AssertEqCond::new(name, a, b, mask))
	}

	/// Unsigned less-than comparison.
	///
	/// Compares two 64-bit wires as unsigned integers.
	///
	/// Returns:
	/// - all-1 if a < b
	/// - all-0 if a >= b
	///
	/// # Cost
	///
	/// 3 AND constraints.
	pub fn icmp_ult(&self, a: Wire, b: Wire) -> Wire {
		let gate = IcmpUlt::new(self, a, b);
		let out = gate.out_mask;
		self.emit(gate);
		out
	}

	/// Equality comparison.
	///
	/// Compares two 64-bit wires for equality.
	///
	/// Returns:
	/// - all-1 if a == b
	/// - all-0 if a != b
	///
	/// # Cost
	///
	/// 8 AND constraints.
	pub fn icmp_eq(&self, a: Wire, b: Wire) -> Wire {
		let gate = IcmpEq::new(self, a, b);
		let out = gate.result;
		self.emit(gate);
		out
	}

	/// Byte extraction.
	///
	/// Extracts byte j from a 64-bit word (j=0 is least significant byte).
	///
	/// Returns the extracted byte (0-255) in the low 8 bits, with high 56 bits zero.
	///
	/// # Panics
	///
	/// Panics if j is greater than or equal to 8.
	///
	/// # Cost
	///
	/// 2 AND constraints.
	pub fn extract_byte(&self, word: Wire, j: u32) -> Wire {
		assert!(j < 8, "byte index out of range");
		let gate = ExtractByte::new(self, word, j);
		let out = gate.b;
		self.emit(gate);
		out
	}
}

const MAX_ASSERTION_MESSAGES: usize = 100;

/// Error returned when populating wire witness fails due to assertion failures.
#[derive(Debug)]
pub struct PopulateError {
	/// List of assertion failure messages (limited to MAX_ASSERTION_MESSAGES).
	messages: Vec<String>,
	/// Total count of assertion failures (may exceed messages.len()).
	total_count: usize,
}

impl fmt::Display for PopulateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		writeln!(f, "assertions failed:")?;
		for message in &self.messages {
			writeln!(f, "{message}")?;
		}
		if self.total_count > self.messages.len() {
			writeln!(f, "(Some assertions are omitted. Total: {})", self.total_count)?;
		}
		Ok(())
	}
}

impl std::error::Error for PopulateError {}

pub struct WitnessFiller<'a> {
	circuit: &'a Circuit,
	value_vec: ValueVec,
	assertion_failed_message_vec: Vec<String>,
	assertion_failed_count: usize,
}

impl<'a> WitnessFiller<'a> {
	pub fn flag_assertion_failed(&mut self, condition: String) {
		self.assertion_failed_count += 1;
		if self.assertion_failed_message_vec.len() < MAX_ASSERTION_MESSAGES {
			self.assertion_failed_message_vec.push(condition);
		}
	}

	pub fn into_value_vec(self) -> ValueVec {
		self.value_vec
	}
}

impl<'a> std::ops::Index<Wire> for WitnessFiller<'a> {
	type Output = Word;

	fn index(&self, wire: Wire) -> &Self::Output {
		&self.value_vec[self.circuit.witness_index(wire)]
	}
}

impl<'a> std::ops::IndexMut<Wire> for WitnessFiller<'a> {
	fn index_mut(&mut self, wire: Wire) -> &mut Self::Output {
		&mut self.value_vec[self.circuit.witness_index(wire)]
	}
}

pub struct Circuit {
	shared: Shared,
	wire_mapping: Vec<ValueIndex>,
}

impl Circuit {
	/// For the given wire, returns its index in the witness vector.
	#[inline(always)]
	pub fn witness_index(&self, wire: Wire) -> ValueIndex {
		self.wire_mapping[wire.0 as usize]
	}

	pub fn new_witness_filler(&self) -> WitnessFiller<'_> {
		WitnessFiller {
			circuit: self,
			value_vec: ValueVec::new(
				self.shared.cp.pool.len(),
				self.shared.n_inout,
				self.shared.n_witness,
			),
			assertion_failed_message_vec: Vec::new(),
			assertion_failed_count: 0,
		}
	}

	/// Populates non-input values (wires) in the witness.
	///
	/// Specifically, this will evaluate the circuit gate-by-gate and save the results in the
	/// witness vector.
	///
	/// This function expects that the input wires are already filled. The input wires are
	///
	/// - [`CircuitBuilder::add_inout`],
	/// - [`CircuitBuilder::add_witness`] that were not created by the gates,
	///
	/// The wires created by [`CircuitBuilder::add_constant`] (and its convenience methods) are
	/// automatically populated by this function as well.
	///
	/// # Errors
	///
	/// In case the circuit is not satisfiable (any assertion fails), this function will return an
	/// error with a list of assertion failure messages.
	pub fn populate_wire_witness(&self, w: &mut WitnessFiller) -> Result<(), PopulateError> {
		for (i, wire) in self.shared.wires.iter().enumerate() {
			if let WireKind::Constant(value) = wire.kind {
				// TODO: don't conjure up a wire.
				w[Wire(i as u32)] = value;
			}
		}

		use std::time::Instant;
		let start = Instant::now();

		for gate in self.shared.gates.iter() {
			gate.populate_wire_witness(w);
		}

		let elapsed = start.elapsed();
		println!("fill_witness took {} microseconds", elapsed.as_micros());

		if w.assertion_failed_count > 0 {
			return Err(PopulateError {
				messages: w.assertion_failed_message_vec.clone(),
				total_count: w.assertion_failed_count,
			});
		}

		Ok(())
	}

	/// Builds a constraint system from this circuit.
	pub fn constraint_system(&self) -> ConstraintSystem {
		let mut cs = ConstraintSystem::new(
			self.shared.cp.pool.keys().cloned().collect::<Vec<_>>(),
			self.shared.n_inout,
			self.shared.n_witness,
		);
		for gate in self.shared.gates.iter() {
			gate.constrain(self, &mut cs);
		}
		cs
	}

	/// Returns the number of gates in this circuit.
	///
	/// Depending on what type of gates this circuit uses, the number of constraints might be
	/// significantly larger.
	pub fn n_gates(&self) -> usize {
		self.shared.gates.len()
	}
}

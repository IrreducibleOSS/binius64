use std::{
	borrow::Cow,
	cmp,
	ops::{Index, IndexMut},
};

use binius_utils::serialization::{DeserializeBytes, SerializationError, SerializeBytes};
use bytes::{Buf, BufMut};

use crate::{consts, error::ConstraintSystemError, word::Word};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ValueIndex(pub u32);

impl ValueIndex {
	/// The value index that is not considered to be valid.
	pub const INVALID: ValueIndex = ValueIndex(u32::MAX);
}

// The most sensible default for a value index is to make it invalid.
impl Default for ValueIndex {
	fn default() -> Self {
		Self::INVALID
	}
}

impl SerializeBytes for ValueIndex {
	fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.0.serialize(write_buf)
	}
}

impl DeserializeBytes for ValueIndex {
	fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		Ok(ValueIndex(u32::deserialize(read_buf)?))
	}
}

/// A different variants of shifting a value.
///
/// Note that there is no shift left arithmetic because it is redundant.
#[derive(Copy, Clone, Debug)]
pub enum ShiftVariant {
	/// Shift logical left.
	Sll,
	/// Shift logical right.
	Slr,
	/// Shift arithmetic right.
	Sar,
}

impl SerializeBytes for ShiftVariant {
	fn serialize(&self, write_buf: impl BufMut) -> Result<(), SerializationError> {
		let index = match self {
			ShiftVariant::Sll => 0u8,
			ShiftVariant::Slr => 1u8,
			ShiftVariant::Sar => 2u8,
		};
		index.serialize(write_buf)
	}
}

impl DeserializeBytes for ShiftVariant {
	fn deserialize(read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let index = u8::deserialize(read_buf)?;
		match index {
			0 => Ok(ShiftVariant::Sll),
			1 => Ok(ShiftVariant::Slr),
			2 => Ok(ShiftVariant::Sar),
			_ => Err(SerializationError::UnknownEnumVariant {
				name: "ShiftVariant",
				index,
			}),
		}
	}
}

#[derive(Copy, Clone, Debug)]
pub struct ShiftedValueIndex {
	/// The index of this value in the input values vector `z`.
	pub value_index: ValueIndex,
	/// The flavour of the shift that the value must be shifted by.
	pub shift_variant: ShiftVariant,
	/// The number of bits by which the value must be shifted by.
	///
	/// Must be less than 64.
	pub amount: usize,
}

impl ShiftedValueIndex {
	/// Create a value index that just uses the specified value.
	pub fn plain(value_index: ValueIndex) -> Self {
		Self {
			value_index,
			shift_variant: ShiftVariant::Sll,
			amount: 0,
		}
	}

	/// Shift Left Logical by the given number of bits.
	pub fn sll(value_index: ValueIndex, amount: usize) -> Self {
		assert!(amount < 64, "shift amount n={amount} out of range");
		Self {
			value_index,
			shift_variant: ShiftVariant::Sll,
			amount,
		}
	}

	pub fn srl(value_index: ValueIndex, amount: usize) -> Self {
		assert!(amount < 64, "shift amount n={amount} out of range");
		Self {
			value_index,
			shift_variant: ShiftVariant::Slr,
			amount,
		}
	}

	pub fn sar(value_index: ValueIndex, amount: usize) -> Self {
		assert!(amount < 64, "shift amount n={amount} out of range");
		Self {
			value_index,
			shift_variant: ShiftVariant::Sar,
			amount,
		}
	}
}

impl SerializeBytes for ShiftedValueIndex {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.value_index.serialize(&mut write_buf)?;
		self.shift_variant.serialize(&mut write_buf)?;
		self.amount.serialize(write_buf)
	}
}

impl DeserializeBytes for ShiftedValueIndex {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let value_index = ValueIndex::deserialize(&mut read_buf)?;
		let shift_variant = ShiftVariant::deserialize(&mut read_buf)?;
		let amount = usize::deserialize(read_buf)?;

		// Validate that amount is within valid range
		if amount >= 64 {
			return Err(SerializationError::InvalidConstruction {
				name: "ShiftedValueIndex::amount",
			});
		}

		Ok(ShiftedValueIndex {
			value_index,
			shift_variant,
			amount,
		})
	}
}

pub type Operand = Vec<ShiftedValueIndex>;

#[derive(Debug, Clone, Default)]
pub struct AndConstraint {
	pub a: Operand,
	pub b: Operand,
	pub c: Operand,
}

impl AndConstraint {
	pub fn plain_abc(
		a: impl IntoIterator<Item = ValueIndex>,
		b: impl IntoIterator<Item = ValueIndex>,
		c: impl IntoIterator<Item = ValueIndex>,
	) -> AndConstraint {
		AndConstraint {
			a: a.into_iter().map(ShiftedValueIndex::plain).collect(),
			b: b.into_iter().map(ShiftedValueIndex::plain).collect(),
			c: c.into_iter().map(ShiftedValueIndex::plain).collect(),
		}
	}

	pub fn abc(
		a: impl IntoIterator<Item = ShiftedValueIndex>,
		b: impl IntoIterator<Item = ShiftedValueIndex>,
		c: impl IntoIterator<Item = ShiftedValueIndex>,
	) -> AndConstraint {
		AndConstraint {
			a: a.into_iter().collect(),
			b: b.into_iter().collect(),
			c: c.into_iter().collect(),
		}
	}
}

impl SerializeBytes for AndConstraint {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.a.serialize(&mut write_buf)?;
		self.b.serialize(&mut write_buf)?;
		self.c.serialize(write_buf)
	}
}

impl DeserializeBytes for AndConstraint {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let a = Vec::<ShiftedValueIndex>::deserialize(&mut read_buf)?;
		let b = Vec::<ShiftedValueIndex>::deserialize(&mut read_buf)?;
		let c = Vec::<ShiftedValueIndex>::deserialize(read_buf)?;

		Ok(AndConstraint { a, b, c })
	}
}

#[derive(Debug, Clone, Default)]
pub struct MulConstraint {
	pub a: Operand,
	pub b: Operand,
	pub hi: Operand,
	pub lo: Operand,
}

impl SerializeBytes for MulConstraint {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.a.serialize(&mut write_buf)?;
		self.b.serialize(&mut write_buf)?;
		self.hi.serialize(&mut write_buf)?;
		self.lo.serialize(write_buf)
	}
}

impl DeserializeBytes for MulConstraint {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let a = Vec::<ShiftedValueIndex>::deserialize(&mut read_buf)?;
		let b = Vec::<ShiftedValueIndex>::deserialize(&mut read_buf)?;
		let hi = Vec::<ShiftedValueIndex>::deserialize(&mut read_buf)?;
		let lo = Vec::<ShiftedValueIndex>::deserialize(read_buf)?;

		Ok(MulConstraint { a, b, hi, lo })
	}
}

#[derive(Debug, Clone)]
pub struct ConstraintSystem {
	pub value_vec_layout: ValueVecLayout,
	pub constants: Vec<Word>,
	pub and_constraints: Vec<AndConstraint>,
	pub mul_constraints: Vec<MulConstraint>,
}

impl ConstraintSystem {
	/// Serialization format version for compatibility checking
	pub const SERIALIZATION_VERSION: u32 = 1;
}

impl ConstraintSystem {
	pub fn new(
		constants: Vec<Word>,
		value_vec_layout: ValueVecLayout,
		and_constraints: Vec<AndConstraint>,
		mul_constraints: Vec<MulConstraint>,
	) -> Self {
		assert_eq!(constants.len(), value_vec_layout.n_const);
		ConstraintSystem {
			constants,
			value_vec_layout,
			and_constraints,
			mul_constraints,
		}
	}

	/// Validates and prepares this constraint system for proving/verifying.
	///
	/// This function performs the following:
	/// 1. Validates the value vector layout (including public input checks)
	/// 2. Pads the AND and MUL constraints to the next po2 size
	pub fn validate_and_prepare(&mut self) -> Result<(), ConstraintSystemError> {
		// Validate the value vector layout
		self.value_vec_layout.validate()?;

		// Both AND and MUL constraint list have requirements wrt their sizes.
		let and_target_size =
			cmp::max(consts::MIN_AND_CONSTRAINTS, self.and_constraints.len()).next_power_of_two();
		let mul_target_size =
			cmp::max(consts::MIN_MUL_CONSTRAINTS, self.mul_constraints.len()).next_power_of_two();

		self.and_constraints
			.resize_with(and_target_size, AndConstraint::default);
		self.mul_constraints
			.resize_with(mul_target_size, MulConstraint::default);

		Ok(())
	}

	pub fn add_and_constraint(&mut self, and_constraint: AndConstraint) {
		self.and_constraints.push(and_constraint);
	}

	pub fn add_mul_constraint(&mut self, mul_constraint: MulConstraint) {
		self.mul_constraints.push(mul_constraint);
	}

	pub fn n_and_constraints(&self) -> usize {
		self.and_constraints.len()
	}

	pub fn n_mul_constraints(&self) -> usize {
		self.mul_constraints.len()
	}

	/// The total length of the [`ValueVec`] expected by this constraint system.
	pub fn value_vec_len(&self) -> usize {
		self.value_vec_layout.total_len
	}

	/// Create a new [`ValueVec`] with the size expected by this constraint system.
	pub fn new_value_vec(&self) -> ValueVec {
		ValueVec::new(self.value_vec_layout.clone())
	}
}

impl SerializeBytes for ConstraintSystem {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		Self::SERIALIZATION_VERSION.serialize(&mut write_buf)?;

		self.value_vec_layout.serialize(&mut write_buf)?;
		self.constants.serialize(&mut write_buf)?;
		self.and_constraints.serialize(&mut write_buf)?;
		self.mul_constraints.serialize(write_buf)
	}
}

impl DeserializeBytes for ConstraintSystem {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let version = u32::deserialize(&mut read_buf)?;
		if version != Self::SERIALIZATION_VERSION {
			return Err(SerializationError::InvalidConstruction {
				name: "ConstraintSystem::version",
			});
		}

		let value_vec_layout = ValueVecLayout::deserialize(&mut read_buf)?;
		let constants = Vec::<Word>::deserialize(&mut read_buf)?;
		let and_constraints = Vec::<AndConstraint>::deserialize(&mut read_buf)?;
		let mul_constraints = Vec::<MulConstraint>::deserialize(read_buf)?;

		if constants.len() != value_vec_layout.n_const {
			return Err(SerializationError::InvalidConstruction {
				name: "ConstraintSystem::constants",
			});
		}

		Ok(ConstraintSystem {
			value_vec_layout,
			constants,
			and_constraints,
			mul_constraints,
		})
	}
}

/// Description of a layout of the value vector for a particular circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueVecLayout {
	/// The number of the constants declared by the circuit.
	pub n_const: usize,
	/// The number of the input output parameters declared by the circuit.
	pub n_inout: usize,
	/// The number of the witness parameters declared by the circuit.
	pub n_witness: usize,
	/// The number of the internal values declared by the circuit.
	///
	/// Those are outputs and intermediaries created by the gates.
	pub n_internal: usize,

	/// The offset at which `inout` parameters start.
	pub offset_inout: usize,
	/// The offset at which `witness` parameters start.
	///
	/// The public section of the value vec has the power-of-two size and is greater than the
	/// minimum number of words. By public section we mean the constants and the inout values.
	pub offset_witness: usize,
	/// The total size of the value vec vector.
	///
	/// This must be a power-of-two.
	pub total_len: usize,
}

impl ValueVecLayout {
	/// Validates that the value vec layout has a correct shape.
	pub fn validate(&self) -> Result<(), ConstraintSystemError> {
		if !self.total_len.is_power_of_two() {
			return Err(ConstraintSystemError::ValueVecLenNotPowerOfTwo);
		}

		if !self.offset_witness.is_power_of_two() {
			return Err(ConstraintSystemError::PublicInputPowerOfTwo);
		}

		let pub_input_size = self.offset_witness;
		if pub_input_size < consts::MIN_WORDS_PER_SEGMENT {
			return Err(ConstraintSystemError::PublicInputTooShort { pub_input_size });
		}

		Ok(())
	}
}

impl SerializeBytes for ValueVecLayout {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		self.n_const.serialize(&mut write_buf)?;
		self.n_inout.serialize(&mut write_buf)?;
		self.n_witness.serialize(&mut write_buf)?;
		self.n_internal.serialize(&mut write_buf)?;
		self.offset_inout.serialize(&mut write_buf)?;
		self.offset_witness.serialize(&mut write_buf)?;
		self.total_len.serialize(write_buf)
	}
}

impl DeserializeBytes for ValueVecLayout {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let n_const = usize::deserialize(&mut read_buf)?;
		let n_inout = usize::deserialize(&mut read_buf)?;
		let n_witness = usize::deserialize(&mut read_buf)?;
		let n_internal = usize::deserialize(&mut read_buf)?;
		let offset_inout = usize::deserialize(&mut read_buf)?;
		let offset_witness = usize::deserialize(&mut read_buf)?;
		let total_len = usize::deserialize(read_buf)?;

		Ok(ValueVecLayout {
			n_const,
			n_inout,
			n_witness,
			n_internal,
			offset_inout,
			offset_witness,
			total_len,
		})
	}
}

/// The vector of values.
///
/// This is a prover-only structure.
///
/// The size of the value vec is always a power-of-two.
#[derive(Clone, Debug)]
pub struct ValueVec {
	layout: ValueVecLayout,
	data: Vec<Word>,
}

impl ValueVec {
	pub fn new(layout: ValueVecLayout) -> ValueVec {
		let size = layout.total_len;
		ValueVec {
			layout,
			data: vec![Word::ZERO; size],
		}
	}

	/// The total size of the vector.
	pub fn size(&self) -> usize {
		self.data.len()
	}

	pub fn get(&self, index: usize) -> Word {
		self.data[index]
	}

	pub fn set(&mut self, index: usize, value: Word) {
		self.data[index] = value;
	}

	/// Returns the public portion of the values vector.
	pub fn public(&self) -> &[Word] {
		&self.data[..self.layout.offset_witness]
	}

	/// Returns the witness portion of the values vector.
	pub fn witness(&self) -> &[Word] {
		let start = self.layout.offset_witness;
		let end = start + self.layout.n_witness;
		&self.data[start..end]
	}

	/// Returns the combined values vector.
	pub fn combined_witness(&self) -> &[Word] {
		&self.data
	}
}

impl Index<ValueIndex> for ValueVec {
	type Output = Word;

	fn index(&self, index: ValueIndex) -> &Self::Output {
		&self.data[index.0 as usize]
	}
}

impl IndexMut<ValueIndex> for ValueVec {
	fn index_mut(&mut self, index: ValueIndex) -> &mut Self::Output {
		&mut self.data[index.0 as usize]
	}
}

/// Public witness data for zero-knowledge proofs.
///
/// This structure holds the public portion of witness data that needs to be shared
/// with verifiers. It uses `Cow<[Word]>` to avoid unnecessary clones while supporting
/// both borrowed and owned data.
///
/// The public witness consists of:
/// - Constants: Fixed values defined in the constraint system
/// - Inputs/Outputs: Public values that are part of the statement being proven
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicWitness<'a> {
	data: Cow<'a, [Word]>,
}

impl<'a> PublicWitness<'a> {
	/// Serialization format version for compatibility checking
	pub const SERIALIZATION_VERSION: u32 = 1;

	/// Create a new PublicWitness from borrowed data
	pub fn borrowed(data: &'a [Word]) -> Self {
		Self {
			data: Cow::Borrowed(data),
		}
	}

	/// Create a new PublicWitness from owned data
	pub fn owned(data: Vec<Word>) -> Self {
		Self {
			data: Cow::Owned(data),
		}
	}

	/// Get the public witness data as a slice
	pub fn as_slice(&self) -> &[Word] {
		&self.data
	}

	/// Get the number of words in the public witness
	pub fn len(&self) -> usize {
		self.data.len()
	}

	/// Check if the public witness is empty
	pub fn is_empty(&self) -> bool {
		self.data.is_empty()
	}

	/// Convert to owned data, consuming self
	pub fn into_owned(self) -> Vec<Word> {
		self.data.into_owned()
	}

	/// Convert to owned version of PublicWitness
	pub fn to_owned(&self) -> PublicWitness<'static> {
		PublicWitness {
			data: Cow::Owned(self.data.to_vec()),
		}
	}
}

impl<'a> SerializeBytes for PublicWitness<'a> {
	fn serialize(&self, mut write_buf: impl BufMut) -> Result<(), SerializationError> {
		Self::SERIALIZATION_VERSION.serialize(&mut write_buf)?;

		self.data.as_ref().serialize(write_buf)
	}
}

impl DeserializeBytes for PublicWitness<'static> {
	fn deserialize(mut read_buf: impl Buf) -> Result<Self, SerializationError>
	where
		Self: Sized,
	{
		let version = u32::deserialize(&mut read_buf)?;
		if version != Self::SERIALIZATION_VERSION {
			return Err(SerializationError::InvalidConstruction {
				name: "PublicWitness::version",
			});
		}

		let data = Vec::<Word>::deserialize(read_buf)?;

		Ok(PublicWitness::owned(data))
	}
}

impl<'a> From<&'a [Word]> for PublicWitness<'a> {
	fn from(data: &'a [Word]) -> Self {
		PublicWitness::borrowed(data)
	}
}

impl From<Vec<Word>> for PublicWitness<'static> {
	fn from(data: Vec<Word>) -> Self {
		PublicWitness::owned(data)
	}
}

impl<'a> From<&'a ValueVec> for PublicWitness<'a> {
	fn from(value_vec: &'a ValueVec) -> Self {
		PublicWitness::borrowed(value_vec.public())
	}
}

impl<'a> AsRef<[Word]> for PublicWitness<'a> {
	fn as_ref(&self) -> &[Word] {
		self.as_slice()
	}
}

impl<'a> std::ops::Deref for PublicWitness<'a> {
	type Target = [Word];

	fn deref(&self) -> &Self::Target {
		self.as_slice()
	}
}

#[cfg(test)]
mod serialization_tests {
	use rand::{RngCore, SeedableRng, rngs::StdRng};

	use super::*;

	fn create_test_constraint_system() -> ConstraintSystem {
		let constants = vec![
			Word::from_u64(1),
			Word::from_u64(42),
			Word::from_u64(0xDEADBEEF),
		];

		let value_vec_layout = ValueVecLayout {
			n_const: 3,
			n_inout: 2,
			n_witness: 10,
			n_internal: 3,
			offset_inout: 4,   // Must be power of 2 and >= n_const
			offset_witness: 8, // Must be power of 2 and >= offset_inout + n_inout
			total_len: 16,     // Must be power of 2 and >= offset_witness + n_witness
		};

		let and_constraints = vec![
			AndConstraint::plain_abc(
				vec![ValueIndex(0), ValueIndex(1)],
				vec![ValueIndex(2)],
				vec![ValueIndex(3), ValueIndex(4)],
			),
			AndConstraint::abc(
				vec![ShiftedValueIndex::sll(ValueIndex(0), 5)],
				vec![ShiftedValueIndex::srl(ValueIndex(1), 10)],
				vec![ShiftedValueIndex::sar(ValueIndex(2), 15)],
			),
		];

		let mul_constraints = vec![MulConstraint {
			a: vec![ShiftedValueIndex::plain(ValueIndex(0))],
			b: vec![ShiftedValueIndex::plain(ValueIndex(1))],
			hi: vec![ShiftedValueIndex::plain(ValueIndex(2))],
			lo: vec![ShiftedValueIndex::plain(ValueIndex(3))],
		}];

		ConstraintSystem::new(constants, value_vec_layout, and_constraints, mul_constraints)
	}

	#[test]
	fn test_word_serialization_round_trip() {
		let mut rng = StdRng::seed_from_u64(0);
		let word = Word::from_u64(rng.next_u64());

		let mut buf = Vec::new();
		word.serialize(&mut buf).unwrap();

		let deserialized = Word::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(word, deserialized);
	}

	#[test]
	fn test_shift_variant_serialization_round_trip() {
		let variants = [ShiftVariant::Sll, ShiftVariant::Slr, ShiftVariant::Sar];

		for variant in variants {
			let mut buf = Vec::new();
			variant.serialize(&mut buf).unwrap();

			let deserialized = ShiftVariant::deserialize(&mut buf.as_slice()).unwrap();
			match (variant, deserialized) {
				(ShiftVariant::Sll, ShiftVariant::Sll)
				| (ShiftVariant::Slr, ShiftVariant::Slr)
				| (ShiftVariant::Sar, ShiftVariant::Sar) => {}
				_ => panic!("ShiftVariant round trip failed: {:?} != {:?}", variant, deserialized),
			}
		}
	}

	#[test]
	fn test_shift_variant_unknown_variant() {
		// Create invalid variant index
		let mut buf = Vec::new();
		255u8.serialize(&mut buf).unwrap();

		let result = ShiftVariant::deserialize(&mut buf.as_slice());
		assert!(result.is_err());
		match result.unwrap_err() {
			SerializationError::UnknownEnumVariant { name, index } => {
				assert_eq!(name, "ShiftVariant");
				assert_eq!(index, 255);
			}
			_ => panic!("Expected UnknownEnumVariant error"),
		}
	}

	#[test]
	fn test_value_index_serialization_round_trip() {
		let value_index = ValueIndex(12345);

		let mut buf = Vec::new();
		value_index.serialize(&mut buf).unwrap();

		let deserialized = ValueIndex::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(value_index, deserialized);
	}

	#[test]
	fn test_shifted_value_index_serialization_round_trip() {
		let shifted_value_index = ShiftedValueIndex::srl(ValueIndex(42), 23);

		let mut buf = Vec::new();
		shifted_value_index.serialize(&mut buf).unwrap();

		let deserialized = ShiftedValueIndex::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(shifted_value_index.value_index, deserialized.value_index);
		assert_eq!(shifted_value_index.amount, deserialized.amount);
		match (shifted_value_index.shift_variant, deserialized.shift_variant) {
			(ShiftVariant::Slr, ShiftVariant::Slr) => {}
			_ => panic!("ShiftVariant mismatch"),
		}
	}

	#[test]
	fn test_shifted_value_index_invalid_amount() {
		// Create a buffer with invalid shift amount (>= 64)
		let mut buf = Vec::new();
		ValueIndex(0).serialize(&mut buf).unwrap();
		ShiftVariant::Sll.serialize(&mut buf).unwrap();
		64usize.serialize(&mut buf).unwrap(); // Invalid amount

		let result = ShiftedValueIndex::deserialize(&mut buf.as_slice());
		assert!(result.is_err());
		match result.unwrap_err() {
			SerializationError::InvalidConstruction { name } => {
				assert_eq!(name, "ShiftedValueIndex::amount");
			}
			_ => panic!("Expected InvalidConstruction error"),
		}
	}

	#[test]
	fn test_and_constraint_serialization_round_trip() {
		let constraint = AndConstraint::abc(
			vec![ShiftedValueIndex::sll(ValueIndex(1), 5)],
			vec![ShiftedValueIndex::srl(ValueIndex(2), 10)],
			vec![
				ShiftedValueIndex::sar(ValueIndex(3), 15),
				ShiftedValueIndex::plain(ValueIndex(4)),
			],
		);

		let mut buf = Vec::new();
		constraint.serialize(&mut buf).unwrap();

		let deserialized = AndConstraint::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(constraint.a.len(), deserialized.a.len());
		assert_eq!(constraint.b.len(), deserialized.b.len());
		assert_eq!(constraint.c.len(), deserialized.c.len());

		// Check individual elements
		for (orig, deser) in constraint.a.iter().zip(deserialized.a.iter()) {
			assert_eq!(orig.value_index, deser.value_index);
			assert_eq!(orig.amount, deser.amount);
		}
	}

	#[test]
	fn test_mul_constraint_serialization_round_trip() {
		let constraint = MulConstraint {
			a: vec![ShiftedValueIndex::plain(ValueIndex(0))],
			b: vec![ShiftedValueIndex::srl(ValueIndex(1), 32)],
			hi: vec![ShiftedValueIndex::plain(ValueIndex(2))],
			lo: vec![ShiftedValueIndex::plain(ValueIndex(3))],
		};

		let mut buf = Vec::new();
		constraint.serialize(&mut buf).unwrap();

		let deserialized = MulConstraint::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(constraint.a.len(), deserialized.a.len());
		assert_eq!(constraint.b.len(), deserialized.b.len());
		assert_eq!(constraint.hi.len(), deserialized.hi.len());
		assert_eq!(constraint.lo.len(), deserialized.lo.len());
	}

	#[test]
	fn test_value_vec_layout_serialization_round_trip() {
		let layout = ValueVecLayout {
			n_const: 5,
			n_inout: 3,
			n_witness: 12,
			n_internal: 7,
			offset_inout: 8,
			offset_witness: 16,
			total_len: 32,
		};

		let mut buf = Vec::new();
		layout.serialize(&mut buf).unwrap();

		let deserialized = ValueVecLayout::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(layout, deserialized);
	}

	#[test]
	fn test_constraint_system_serialization_round_trip() {
		let original = create_test_constraint_system();

		let mut buf = Vec::new();
		original.serialize(&mut buf).unwrap();

		let deserialized = ConstraintSystem::deserialize(&mut buf.as_slice()).unwrap();

		// Check version
		assert_eq!(ConstraintSystem::SERIALIZATION_VERSION, 1);

		// Check value_vec_layout
		assert_eq!(original.value_vec_layout, deserialized.value_vec_layout);

		// Check constants
		assert_eq!(original.constants.len(), deserialized.constants.len());
		for (orig, deser) in original.constants.iter().zip(deserialized.constants.iter()) {
			assert_eq!(orig, deser);
		}

		// Check and_constraints
		assert_eq!(original.and_constraints.len(), deserialized.and_constraints.len());

		// Check mul_constraints
		assert_eq!(original.mul_constraints.len(), deserialized.mul_constraints.len());
	}

	#[test]
	fn test_constraint_system_version_mismatch() {
		// Create a buffer with wrong version
		let mut buf = Vec::new();
		999u32.serialize(&mut buf).unwrap(); // Wrong version

		let result = ConstraintSystem::deserialize(&mut buf.as_slice());
		assert!(result.is_err());
		match result.unwrap_err() {
			SerializationError::InvalidConstruction { name } => {
				assert_eq!(name, "ConstraintSystem::version");
			}
			_ => panic!("Expected InvalidConstruction error"),
		}
	}

	#[test]
	fn test_constraint_system_constants_length_mismatch() {
		// Create valid components but with mismatched constants length
		let value_vec_layout = ValueVecLayout {
			n_const: 5, // Expect 5 constants
			n_inout: 2,
			n_witness: 10,
			n_internal: 3,
			offset_inout: 8,
			offset_witness: 16,
			total_len: 32,
		};

		let constants = vec![Word::from_u64(1), Word::from_u64(2)]; // Only 2 constants
		let and_constraints: Vec<AndConstraint> = vec![];
		let mul_constraints: Vec<MulConstraint> = vec![];

		// Serialize components manually
		let mut buf = Vec::new();
		ConstraintSystem::SERIALIZATION_VERSION
			.serialize(&mut buf)
			.unwrap();
		value_vec_layout.serialize(&mut buf).unwrap();
		constants.serialize(&mut buf).unwrap();
		and_constraints.serialize(&mut buf).unwrap();
		mul_constraints.serialize(&mut buf).unwrap();

		let result = ConstraintSystem::deserialize(&mut buf.as_slice());
		assert!(result.is_err());
		match result.unwrap_err() {
			SerializationError::InvalidConstruction { name } => {
				assert_eq!(name, "ConstraintSystem::constants");
			}
			_ => panic!("Expected InvalidConstruction error"),
		}
	}

	#[test]
	fn test_serialization_with_different_sources() {
		let original = create_test_constraint_system();

		// Test with Vec<u8> (memory buffer)
		let mut vec_buf = Vec::new();
		original.serialize(&mut vec_buf).unwrap();
		let deserialized1 = ConstraintSystem::deserialize(&mut vec_buf.as_slice()).unwrap();
		assert_eq!(original.constants.len(), deserialized1.constants.len());

		// Test with bytes::BytesMut (another common buffer type)
		let mut bytes_buf = bytes::BytesMut::new();
		original.serialize(&mut bytes_buf).unwrap();
		let deserialized2 = ConstraintSystem::deserialize(bytes_buf.freeze()).unwrap();
		assert_eq!(original.constants.len(), deserialized2.constants.len());
	}

	/// Helper function to create or update the reference binary file for version compatibility
	/// testing. This is not run automatically but can be used to regenerate the reference file
	/// when needed.
	#[test]
	#[ignore] // Use `cargo test -- --ignored create_reference_binary` to run this
	fn create_reference_binary_file() {
		let constraint_system = create_test_constraint_system();

		// Serialize to binary data
		let mut buf = Vec::new();
		constraint_system.serialize(&mut buf).unwrap();

		// Write to reference file
		let test_data_path = std::path::Path::new("crates/core/test_data/constraint_system_v1.bin");

		// Create directory if it doesn't exist
		if let Some(parent) = test_data_path.parent() {
			std::fs::create_dir_all(parent).unwrap();
		}

		std::fs::write(test_data_path, &buf).unwrap();

		println!("Created reference binary file at: {:?}", test_data_path);
		println!("Binary data length: {} bytes", buf.len());
	}

	/// Test deserialization from a reference binary file to ensure version compatibility.
	/// This test will fail if breaking changes are made without incrementing the version.
	#[test]
	fn test_deserialize_from_reference_binary_file() {
		let test_data_path = std::path::Path::new("crates/core/test_data/constraint_system_v1.bin");

		let binary_data = std::fs::read(test_data_path).unwrap();

		let deserialized = ConstraintSystem::deserialize(&mut binary_data.as_slice()).unwrap();

		assert_eq!(deserialized.value_vec_layout.n_const, 3);
		assert_eq!(deserialized.value_vec_layout.n_inout, 2);
		assert_eq!(deserialized.value_vec_layout.n_witness, 10);
		assert_eq!(deserialized.value_vec_layout.n_internal, 3);
		assert_eq!(deserialized.value_vec_layout.offset_inout, 4);
		assert_eq!(deserialized.value_vec_layout.offset_witness, 8);
		assert_eq!(deserialized.value_vec_layout.total_len, 16);

		assert_eq!(deserialized.constants.len(), 3);
		assert_eq!(deserialized.constants[0].as_u64(), 1);
		assert_eq!(deserialized.constants[1].as_u64(), 42);
		assert_eq!(deserialized.constants[2].as_u64(), 0xDEADBEEF);

		assert_eq!(deserialized.and_constraints.len(), 2);
		assert_eq!(deserialized.mul_constraints.len(), 1);

		// Verify that the version is what we expect
		// This is implicitly checked during deserialization, but we can also verify
		// the file starts with the correct version bytes
		let version_bytes = &binary_data[0..4]; // First 4 bytes should be version
		let expected_version_bytes = 1u32.to_le_bytes(); // Version 1 in little-endian
		assert_eq!(
			version_bytes, expected_version_bytes,
			"Binary file version mismatch. If you made breaking changes, increment ConstraintSystem::SERIALIZATION_VERSION"
		);
	}

	#[test]
	fn test_public_witness_from_value_vec() {
		let constraint_system = create_test_constraint_system();
		let value_vec = constraint_system.new_value_vec();

		let public_witness: PublicWitness = (&value_vec).into();

		assert_eq!(public_witness.len(), value_vec.public().len());
		assert_eq!(public_witness.as_slice(), value_vec.public());
	}

	#[test]
	fn test_public_witness_serialization_round_trip_owned() {
		let data = vec![
			Word::from_u64(1),
			Word::from_u64(42),
			Word::from_u64(0xDEADBEEF),
			Word::from_u64(0x1234567890ABCDEF),
		];
		let witness = PublicWitness::owned(data.clone());

		let mut buf = Vec::new();
		witness.serialize(&mut buf).unwrap();

		let deserialized = PublicWitness::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(witness, deserialized);
		assert_eq!(deserialized.as_slice(), data.as_slice());
	}

	#[test]
	fn test_public_witness_serialization_round_trip_borrowed() {
		let data = vec![Word::from_u64(123), Word::from_u64(456)];
		let witness = PublicWitness::borrowed(&data);

		let mut buf = Vec::new();
		witness.serialize(&mut buf).unwrap();

		let deserialized = PublicWitness::deserialize(&mut buf.as_slice()).unwrap();
		assert_eq!(witness, deserialized);
		assert_eq!(deserialized.as_slice(), data.as_slice());
	}

	#[test]
	fn test_public_witness_version_mismatch() {
		let mut buf = Vec::new();
		999u32.serialize(&mut buf).unwrap(); // Wrong version
		vec![Word::from_u64(1)].serialize(&mut buf).unwrap(); // Some data

		let result = PublicWitness::deserialize(&mut buf.as_slice());
		assert!(result.is_err());
		match result.unwrap_err() {
			SerializationError::InvalidConstruction { name } => {
				assert_eq!(name, "PublicWitness::version");
			}
			_ => panic!("Expected version mismatch error"),
		}
	}

	/// Helper function to create or update the reference binary file for PublicWitness version
	/// compatibility testing.
	#[test]
	#[ignore] // Use `cargo test -- --ignored create_public_witness_reference_binary` to run this
	fn create_public_witness_reference_binary_file() {
		let data = vec![
			Word::from_u64(1),
			Word::from_u64(42),
			Word::from_u64(0xDEADBEEF),
			Word::from_u64(0x1234567890ABCDEF),
		];
		let public_witness = PublicWitness::owned(data);

		let mut buf = Vec::new();
		public_witness.serialize(&mut buf).unwrap();

		let test_data_path = std::path::Path::new("crates/core/test_data/public_witness_v1.bin");

		if let Some(parent) = test_data_path.parent() {
			std::fs::create_dir_all(parent).unwrap();
		}

		std::fs::write(test_data_path, &buf).unwrap();

		println!("Created PublicWitness reference binary file at: {:?}", test_data_path);
		println!("Binary data length: {} bytes", buf.len());
	}

	/// Test deserialization from a reference binary file to ensure PublicWitness version
	/// compatibility. This test will fail if breaking changes are made without incrementing the
	/// version.
	#[test]
	fn test_public_witness_deserialize_from_reference_binary_file() {
		let test_data_path = std::path::Path::new("crates/core/test_data/public_witness_v1.bin");

		let binary_data = std::fs::read(test_data_path).unwrap();

		let deserialized = PublicWitness::deserialize(&mut binary_data.as_slice()).unwrap();

		assert_eq!(deserialized.len(), 4);
		assert_eq!(deserialized.as_slice()[0].as_u64(), 1);
		assert_eq!(deserialized.as_slice()[1].as_u64(), 42);
		assert_eq!(deserialized.as_slice()[2].as_u64(), 0xDEADBEEF);
		assert_eq!(deserialized.as_slice()[3].as_u64(), 0x1234567890ABCDEF);

		// Verify that the version is what we expect
		// This is implicitly checked during deserialization, but we can also verify
		// the file starts with the correct version bytes
		let version_bytes = &binary_data[0..4]; // First 4 bytes should be version
		let expected_version_bytes = 1u32.to_le_bytes(); // Version 1 in little-endian
		assert_eq!(
			version_bytes, expected_version_bytes,
			"PublicWitness binary file version mismatch. If you made breaking changes, increment PublicWitness::SERIALIZATION_VERSION"
		);
	}
}

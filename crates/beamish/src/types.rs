//! Type markers for phantom types

/// GF(2^64) field element
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field64;

/// 32-bit unsigned integer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32;

/// 64-bit unsigned integer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64;

/// Boolean value (single bit in 64-bit word)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bool;

// Type aliases for common patterns
pub type F64 = Field64;

// Marker traits for type categories
pub trait BitType: Sized {}
pub trait IntType: Sized {}
pub trait FieldType: Sized {}

impl BitType for Field64 {}
impl BitType for U32 {}
impl BitType for U64 {}
impl BitType for Bool {}

impl IntType for U32 {}
impl IntType for U64 {}

impl FieldType for Field64 {}
//! Type system for Binius64 values
//!
//! Provides typed wrappers for 32-bit and 64-bit operations.

use std::marker::PhantomData;

/// Trait for bit-level types in Binius64
pub trait BitType: Clone + 'static {
    const BITS: u8;
    
    /// Zero value for this type
    fn zero() -> u64;
    
    /// All-ones value for this type  
    fn ones() -> u64;
}

/// 32-bit unsigned type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32;

impl BitType for U32 {
    const BITS: u8 = 32;
    
    fn zero() -> u64 { 0 }
    fn ones() -> u64 { u32::MAX as u64 }
}

/// 64-bit unsigned type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64;

impl BitType for U64 {
    const BITS: u8 = 64;
    
    fn zero() -> u64 { 0 }
    fn ones() -> u64 { u64::MAX }
}

/// Boolean type (represented as U64 with 0/all-1s semantics)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bool;

impl BitType for Bool {
    const BITS: u8 = 64;  // Booleans are represented as full 64-bit masks
    
    fn zero() -> u64 { 0 }
    fn ones() -> u64 { u64::MAX }
}
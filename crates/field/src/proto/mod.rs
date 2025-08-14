// Proto module - exploring different field crate architectures
// Each approach is in its own isolated module to avoid naming conflicts

pub mod binary_algebra;
pub mod functional_core;
pub mod enum_tags;
pub mod unified_const;
pub mod intrinsics;
// pub mod phantom_types;  // Has compilation issues with move semantics
// Copyright 2024-2025 Irreducible Inc.

// If the macro is not used in the same module, rustc thinks it is unused for some reason
#[allow(unused_macros, unused_imports)]
pub mod macros {
	#[macro_export]
	macro_rules! felts {
		($f:ident[$($elem:expr),* $(,)?]) => { vec![$($f::from($elem)),*] };
	}
	pub use felts;
}

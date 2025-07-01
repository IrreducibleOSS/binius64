// Copyright 2025 Irreducible Inc.

/// A macro to implement the `Debug` trait for a given struct or type using JSON serialization.
#[macro_export]
macro_rules! impl_debug_with_json {
	($name:ident) => {
		impl std::fmt::Debug for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
				write!(f, "{}", json)
			}
		}
	};
	() => {};
}

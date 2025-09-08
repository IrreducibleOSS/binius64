// Copyright 2024-2025 Irreducible Inc.

#[cfg(feature = "bail_panic")]
#[macro_export]
macro_rules! bail {
	($err:expr) => {
		panic!("{}", $err);
	};
}

#[cfg(not(feature = "bail_panic"))]
#[macro_export]
macro_rules! bail {
	($err:expr) => {
		return Err($err.into());
	};
}

#[macro_export]
macro_rules! ensure {
	($cond:expr, $err:expr) => {
		if !$cond {
			$crate::bail!($err);
		}
	};
}

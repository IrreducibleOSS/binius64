// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, PackedField};
use binius_utils::rayon::get_log_max_threads;

use super::{
	additive_ntt::{AdditiveNTT, NTTShape},
	error::Error,
	multithreaded::MultithreadedNTT,
	single_threaded::SingleThreadedNTT,
	twiddle::PrecomputedTwiddleAccess,
};
use crate::BinarySubspace;

/// How many threads to use (threads number is a power of 2).
#[derive(Default, Debug, Clone, Copy)]
pub enum ThreadingSettings {
	/// Use a single thread for calculations.
	#[default]
	SingleThreaded,
	/// Use the default number of threads based on the number of cores.
	MultithreadedDefault,
	/// Explicitly set the logarithm of number of threads.
	ExplicitThreadsCount { log_threads: usize },
}

impl ThreadingSettings {
	/// Get the log2 of the number of threads to use.
	pub fn log_threads_count(&self) -> usize {
		match self {
			Self::SingleThreaded => 0,
			Self::MultithreadedDefault => get_log_max_threads(),
			Self::ExplicitThreadsCount { log_threads } => *log_threads,
		}
	}

	/// Check if settings imply multithreading.
	pub const fn is_multithreaded(&self) -> bool {
		match self {
			Self::SingleThreaded => false,
			Self::MultithreadedDefault => true,
			Self::ExplicitThreadsCount { log_threads } => *log_threads > 0,
		}
	}
}

#[derive(Default)]
pub struct NTTOptions {
	pub precompute_twiddles: bool,
	pub thread_settings: ThreadingSettings,
}

/// An enum that can be used to switch between different NTT implementations without passing
/// AdditiveNTT as a type parameter.
#[derive(Debug)]
pub enum DynamicDispatchNTT<F: BinaryField> {
	SingleThreaded(SingleThreadedNTT<F>),
	SingleThreadedPrecompute(SingleThreadedNTT<F, PrecomputedTwiddleAccess<F>>),
	MultiThreaded(MultithreadedNTT<F>),
	MultiThreadedPrecompute(MultithreadedNTT<F, PrecomputedTwiddleAccess<F>>),
}

impl<F: BinaryField> DynamicDispatchNTT<F> {
	/// Create a new AdditiveNTT based on the given settings.
	pub fn new(log_domain_size: usize, options: &NTTOptions) -> Result<Self, Error> {
		let log_threads = options.thread_settings.log_threads_count();
		let result = match (options.precompute_twiddles, log_threads) {
			(false, 0) => Self::SingleThreaded(SingleThreadedNTT::new(log_domain_size)?),
			(true, 0) => Self::SingleThreadedPrecompute(
				SingleThreadedNTT::new(log_domain_size)?.precompute_twiddles(),
			),
			(false, _) => Self::MultiThreaded(
				SingleThreadedNTT::new(log_domain_size)?
					.multithreaded_with_max_threads(log_threads),
			),
			(true, _) => Self::MultiThreadedPrecompute(
				SingleThreadedNTT::new(log_domain_size)?
					.precompute_twiddles()
					.multithreaded_with_max_threads(log_threads),
			),
		};

		Ok(result)
	}
}

impl<F: BinaryField> AdditiveNTT<F> for DynamicDispatchNTT<F> {
	fn log_domain_size(&self) -> usize {
		match self {
			Self::SingleThreaded(ntt) => ntt.log_domain_size(),
			Self::SingleThreadedPrecompute(ntt) => ntt.log_domain_size(),
			Self::MultiThreaded(ntt) => ntt.log_domain_size(),
			Self::MultiThreadedPrecompute(ntt) => ntt.log_domain_size(),
		}
	}

	fn subspace(&self, i: usize) -> BinarySubspace<F> {
		match self {
			Self::SingleThreaded(ntt) => ntt.subspace(i),
			Self::SingleThreadedPrecompute(ntt) => ntt.subspace(i),
			Self::MultiThreaded(ntt) => ntt.subspace(i),
			Self::MultiThreadedPrecompute(ntt) => ntt.subspace(i),
		}
	}

	fn get_subspace_eval(&self, i: usize, j: usize) -> F {
		match self {
			Self::SingleThreaded(ntt) => ntt.get_subspace_eval(i, j),
			Self::SingleThreadedPrecompute(ntt) => ntt.get_subspace_eval(i, j),
			Self::MultiThreaded(ntt) => ntt.get_subspace_eval(i, j),
			Self::MultiThreadedPrecompute(ntt) => ntt.get_subspace_eval(i, j),
		}
	}

	fn forward_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		match self {
			Self::SingleThreaded(ntt) => {
				ntt.forward_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::SingleThreadedPrecompute(ntt) => {
				ntt.forward_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::MultiThreaded(ntt) => {
				ntt.forward_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::MultiThreadedPrecompute(ntt) => {
				ntt.forward_transform(data, shape, coset, coset_bits, skip_rounds)
			}
		}
	}

	fn inverse_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		match self {
			Self::SingleThreaded(ntt) => {
				ntt.inverse_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::SingleThreadedPrecompute(ntt) => {
				ntt.inverse_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::MultiThreaded(ntt) => {
				ntt.inverse_transform(data, shape, coset, coset_bits, skip_rounds)
			}
			Self::MultiThreadedPrecompute(ntt) => {
				ntt.inverse_transform(data, shape, coset, coset_bits, skip_rounds)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use binius_field::BinaryField8b;

	use super::*;

	#[test]
	fn test_creation() {
		fn make_ntt(options: &NTTOptions) -> DynamicDispatchNTT<BinaryField8b> {
			DynamicDispatchNTT::<BinaryField8b>::new(6, options).unwrap()
		}

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: false,
			thread_settings: ThreadingSettings::SingleThreaded,
		});
		assert!(matches!(ntt, DynamicDispatchNTT::SingleThreaded(_)));

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: true,
			thread_settings: ThreadingSettings::SingleThreaded,
		});
		assert!(matches!(ntt, DynamicDispatchNTT::SingleThreadedPrecompute(_)));

		let multithreaded = get_log_max_threads() > 0;
		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: false,
			thread_settings: ThreadingSettings::MultithreadedDefault,
		});
		if multithreaded {
			assert!(matches!(ntt, DynamicDispatchNTT::MultiThreaded(_)));
		} else {
			assert!(matches!(ntt, DynamicDispatchNTT::SingleThreaded(_)));
		}

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: true,
			thread_settings: ThreadingSettings::MultithreadedDefault,
		});
		if multithreaded {
			assert!(matches!(ntt, DynamicDispatchNTT::MultiThreadedPrecompute(_)));
		} else {
			assert!(matches!(ntt, DynamicDispatchNTT::SingleThreadedPrecompute(_)));
		}

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: false,
			thread_settings: ThreadingSettings::ExplicitThreadsCount { log_threads: 2 },
		});
		assert!(matches!(ntt, DynamicDispatchNTT::MultiThreaded(_)));

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: true,
			thread_settings: ThreadingSettings::ExplicitThreadsCount { log_threads: 0 },
		});
		assert!(matches!(ntt, DynamicDispatchNTT::SingleThreadedPrecompute(_)));

		let ntt = make_ntt(&NTTOptions {
			precompute_twiddles: false,
			thread_settings: ThreadingSettings::ExplicitThreadsCount { log_threads: 0 },
		});
		assert!(matches!(ntt, DynamicDispatchNTT::SingleThreaded(_)));
	}
}

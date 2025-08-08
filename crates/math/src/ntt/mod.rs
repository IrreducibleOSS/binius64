// Copyright 2024-2025 Irreducible Inc.

//! Efficient implementations of the binary field additive NTT.
//!
//! See [LCH14] and [DP24] Section 2.3 for mathematical background.
//!
//! [LCH14]: <https://arxiv.org/abs/1404.3458>
//! [DP24]: <https://eprint.iacr.org/2024/504>

pub mod domain_context;
mod neighbors_last;
#[cfg(test)]
mod tests_evaluation;
#[cfg(test)]
pub mod tests_reference;

use std::ops::DerefMut;

use binius_field::{BinaryField, PackedField};
pub use neighbors_last::{
	NeighborsLastMultiThread, NeighborsLastReference, NeighborsLastSingleThread,
};

use crate::FieldBuffer;

use super::BinarySubspace;

/// The binary field additive NTT.
///
/// A number-theoretic transform (NTT) is a linear transformation on a finite field analogous to
/// the discrete fourier transform. The version of the additive NTT we use is originally described
/// in [LCH14]. In [DP24] Section 4.1, the authors present the LCH additive NTT algorithm in a way
/// that makes apparent its compatibility with the FRI proximity test. Throughout the
/// documentation, we will refer to the notation used in [DP24].
///
/// The additive NTT is parameterized by a binary field $K$ and $\mathbb{F}\_2$-linear subspace. We
/// write $\beta_0, \ldots, \beta_{\ell-1}$ for the ordered basis elements of the subspace. The
/// basis determines a novel polynomial basis and an evaluation domain. In the forward direction,
/// the additive NTT transforms a vector of polynomial coefficients, with respect to the novel
/// polynomial basis, into a vector of their evaluations over the evaluation domain. The inverse
/// transformation interpolates polynomial values over the domain into novel polynomial basis
/// coefficients.
///
/// An [`AdditiveNTT`] implementation with a maximum domain dimension of $\ell$ can be applied on
/// a sequence of $\ell + 1$ evaluation domains of sizes $2^0, \ldots, 2^\ell$. These are the
/// domains $S^{(\ell)}, S^{(\ell - 1)}, \ldots, S^{(0)}$ defined in [DP24] Section 4. The methods
/// [`Self::forward_transform`] and [`Self::inverse_transform`] require a parameter
/// `log_domain_size` that indicates which of the $S^(i)$ domains to use for the transformation's
/// evaluation domain and novel polynomial basis. (Remember, the novel polynomial basis is itself
/// parameterized by basis). **Counterintuitively, the space $S^(i+1)$ is not necessarily
/// a subset of $S^i$**. We choose this behavior for the [`AdditiveNTT`] trait because it
/// facilitates compatibility with FRI when batching proximity tests for codewords of different
/// dimensions.
///
/// [LCH14]: <https://arxiv.org/abs/1404.3458>
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub trait AdditiveNTT {
	type Field: BinaryField;

	/// Forward transformation as defined in [DP24], Section 2.3.
	///
	/// Arguments:
	/// - `data` is the data on which the NTT is performed.
	/// - `skip_early` is the number of early layers that should be skipped
	/// - `skip_late` is the number of late layers that should be skipped
	///
	/// ## Preconditons
	///
	/// - `data.len()` is a power of 2
	/// - `skip_early + skip_late <= log2(data.len()) + P::LOG_WIDTH`
	/// - `log2(data.len()) + P::LOG_WIDTH <= self.log_domain_size() + skip_late`
	///
	/// [DP24]: <https://eprint.iacr.org/2024/504>
	fn forward_transform<P: PackedField<Scalar = Self::Field>, Data: DerefMut<Target = [P]>>(
		&self,
		data: FieldBuffer<P, Data>,
		skip_early: usize,
		skip_late: usize,
	);

	/// Inverse transformation of [`Self::forward_transform`].
	///
	/// Note that "early" layers here refer to "early" time in the forward transform, i.e. layers with low index in the forward transform.
	///
	/// ## Preconditions
	///
	/// - same as [`Self::forward_transform`]
	fn inverse_transform<P: PackedField<Scalar = Self::Field>, Data: DerefMut<Target = [P]>>(
		&self,
		data: FieldBuffer<P, Data>,
		skip_early: usize,
		skip_late: usize,
	);

	/// The associated [`DomainContext`].
	fn domain_context(&self) -> &impl DomainContext<Field = Self::Field>;

	/// See [`DomainContext::log_domain_size`].
	fn log_domain_size(&self) -> usize {
		self.domain_context().log_domain_size()
	}

	/// See [`DomainContext::subspace`].
	fn subspace(&self, i: usize) -> BinarySubspace<Self::Field> {
		self.domain_context().subspace(i)
	}

	/// See [`DomainContext::twiddle`].
	fn twiddle(&self, i: usize, j: usize) -> Self::Field {
		self.domain_context().twiddle(i, j)
	}
}

/// Provides information about the domains $S^{(i)}$ and the associated twiddle factors.
///
/// Needed by the NTT and by FRI.
pub trait DomainContext {
	type Field: BinaryField;

	/// Base 2 logarithm of the size of $S^{(0)}$, i.e., $\ell$.
	///
	/// In other words: Index of the first layer that can _not_ be computed anymore.
	/// I.e., number of the latest layer that _can_ be computed, plus one.
	/// Layers are indexed starting from 0.
	///
	/// If you intend to call the NTT with `skip_late = 0`, then this should be equal to the base 2
	/// logarithm of the number of scalars in the input.
	fn log_domain_size(&self) -> usize;

	/// Returns the binary subspace with dimension $i$.
	///
	/// In [DP24], this subspace is referred to as $S^{(\ell - i)}$, where $\ell$ is the maximum
	/// domain size of the NTT, i.e., `self.log_domain_size()`. We choose to reverse the indexing
	/// order with respect to the paper because it is more natural in code that the $i$th subspace
	/// has dimension $i$.
	///
	/// ## Preconditions
	///
	/// - `i` must be less than or equal to `self.log_domain_size()`
	///
	/// [DP24]: <https://eprint.iacr.org/2024/504>
	fn subspace(&self, i: usize) -> BinarySubspace<Self::Field>;

	/// Returns the twiddle of a certain block in a certain layer.
	///
	/// The layer numbers start from 0, i.e., the earliest layer is layer 0.
	///
	/// ## Preconditions
	///
	/// - `layer < self.log_domain_size()`
	/// - `block < 2^layer`
	fn twiddle(&self, layer: usize, block: usize) -> Self::Field;
}

/// Make it so that references to a [`DomainContext` implement [`DomainContext`] themselves.
///
/// This is useful, for example, if you need two objects that each want to _own_ a
/// [`DomainContext`], but you don't want to clone the [`DomainContext`].
impl<T: DomainContext> DomainContext for &T {
	type Field = T::Field;

	fn log_domain_size(&self) -> usize {
		(*self).log_domain_size()
	}

	fn subspace(&self, i: usize) -> BinarySubspace<Self::Field> {
		(*self).subspace(i)
	}

	fn twiddle(&self, layer: usize, block: usize) -> Self::Field {
		(*self).twiddle(layer, block)
	}
}

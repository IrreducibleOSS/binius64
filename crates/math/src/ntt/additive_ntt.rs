// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, PackedExtension, PackedField};

use super::error::Error;
use crate::BinarySubspace;

/// Shape of a batched NTT operation on a 3-dimensional tensor.
///
/// The tensor has three dimensions. Elements are indexed first along axis X (width),
/// then axis Y (height), then axis Z (depth). In other words, the range of elements sharing Y and
/// Z coordinates are contiguous in memory, elements sharing X and Z coordinates are strided by the
/// tensor width, and elements sharing X and Y coordinates are strided by the width times height.
///
/// The tensor has power-of-two length in each dimension.
///
/// The NTT operation performs a parallel NTT along the _Y axis_, meaning each the operation
/// transforms each column independently.
#[derive(Debug, Default, Clone, Copy)]
pub struct NTTShape {
	/// Log length along the X axis (width). This is the interleaved batch size.
	pub log_x: usize,
	/// Log length along the Y axis (height). This is the size of the NTT transform.
	pub log_y: usize,
	/// Log length along the Z axis (depth). This is the consecutive batch size.
	pub log_z: usize,
}

/// The binary field additive NTT.
///
/// A number-theoretic transform (NTT) is a linear transformation on a finite field analogous to
/// the discrete fourier transform. The version of the additive NTT we use is originally described
/// in [LCH14]. In [DP24] Section 3.1, the authors present the LCH additive NTT algorithm in a way
/// that makes apparent its compatibility with the FRI proximity test. Throughout the
/// documentation, we will refer to the notation used in [DP24].
///
/// The additive NTT is parameterized by a binary field $K$ and $\mathbb{F}\_2$-linear subspace. We
/// write $\beta_0, \ldots, \beta_{\ell-1}$ for the ordered basis elements of the subspace and
/// require $\beta_0 = 1$. The basis determines a novel polynomial basis and an evaluation domain.
/// In the forward direction, the additive NTT transforms a vector of polynomial coefficients, with
/// respect to the novel polynomial basis, into a vector of their evaluations over the evaluation
/// domain. The inverse transformation interpolates polynomial values over the domain into novel
/// polynomial basis coefficients.
///
/// An [`AdditiveNTT`] implementation with a maximum domain dimension of $\ell$ can be applied on
/// a sequence of $\ell + 1$ evaluation domains of sizes $2^0, \ldots, 2^\ell$. These are the
/// domains $S^{(\ell)}, S^{(\ell - 1)}, \ldots, S^{(0)}$ defined in [DP24] Section 4. The methods
/// [`Self::forward_transform`] and [`Self::inverse_transform`] require a parameter
/// `log_domain_size` that indicates which of the $S^(i)$ domains to use for the transformation's
/// evaluation domain and novel polynomial basis. (Remember, the novel polynomial basis is itself
/// parameterized by basis). **Counterintuitively, the field subspace $S^(i+1)$ is not necessarily
/// a subset of $S^i$**. We choose this behavior for the [`AdditiveNTT`] trait because it
/// facilitates compatibility with FRI when batching proximity tests for codewords of different
/// dimensions.
///
/// [LCH14]: <https://arxiv.org/abs/1404.3458>
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub trait AdditiveNTT<F: BinaryField> {
	/// Base-2 logarithm of the maximum size of the NTT domain, $\ell$.
	fn log_domain_size(&self) -> usize;

	/// Returns the binary subspace with dimension $i$.
	///
	/// In [DP24], this subspace is referred to as $S^{(\ell - i)}$, where $\ell$ is the maximum
	/// domain size of the NTT. We choose to reverse the indexing order with respect to the paper
	/// because it is more natural in code that $i$th subspace have dimension $i$.
	///
	/// ## Preconditions
	///
	/// * `i` must be less than `self.log_domain_size()`
	///
	/// [DP24]: <https://eprint.iacr.org/2024/504>
	fn subspace(&self, i: usize) -> BinarySubspace<F>;

	/// Get the $j$'th basis element of the $i$'th subspace.
	///
	/// ## Preconditions
	///
	/// * `i` must be less than `self.log_domain_size()`
	/// * `j` must be less than `i`
	fn get_subspace_eval(&self, i: usize, j: usize) -> F {
		self.subspace(i).basis()[j]
	}

	/// Batched forward transformation defined in [DP24], Section 2.3.
	///
	/// The scalars of `data`, viewed in natural order, represent a tensor of `shape` dimensions.
	/// See [`NTTShape`] for layout details. The transform is inplace, output adheres to `shape`.
	///
	/// The `coset` specifies the evaluation domain as an indexed coset of the subspace. The coset
	/// index must representable in `coset_bits` bits. The evaluation domain of the NTT is chosen
	/// to be the subspace $S^{(i)}$ with dimension `shape.log_y + coset_bits`. Choosing the NTT
	/// domain in this way ensures consistency of the domains when using FRI with different
	/// codeword lengths.
	///
	/// The transformation accepts a `skip_rounds` parameter, which is a number of NTT layers to
	/// skip at the beginning of the forward transform. This corresponds to parallel NTTs on
	/// multiple adjacent subspace cosets, but beginning with messages interpreted as coefficients
	/// in a modified novel polynomial basis. See [DP24] Remark 4.15.
	///
	/// [DP24]: <https://eprint.iacr.org/2024/504>
	fn forward_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error>;

	/// Batched inverse transformation defined in [DP24], Section 2.3.
	///
	/// The scalars of `data`, viewed in natural order, represent a tensor of `shape` dimensions.
	/// See [`NTTShape`] for layout details. The transform is inplace, output adheres to `shape`.
	///
	/// The `coset` specifies the evaluation domain as an indexed coset of the subspace. The coset
	/// index must representable in `coset_bits` bits. The evaluation domain of the NTT is chosen
	/// to be the subspace $S^{(i)}$ with dimension `shape.log_y + coset_bits`. Choosing the NTT
	/// domain in this way ensures consistency of the domains when using FRI with different
	/// codeword lengths.
	///
	/// The transformation accepts a `skip_rounds` parameter, which is a number of NTT layers to
	/// skip at the end of the inverse transform. This corresponds to parallel NTTs on multiple
	/// adjacent subspace cosets, but returning with messages interpreted as coefficients in a
	/// modified novel polynomial basis. See [DP24] Remark 4.15.
	///
	/// [DP24]: <https://eprint.iacr.org/2024/504>
	fn inverse_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error>;

	fn forward_transform_ext<PE: PackedExtension<F>>(
		&self,
		data: &mut [PE],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		let shape_ext = NTTShape {
			log_x: shape.log_x + PE::Scalar::LOG_DEGREE,
			..shape
		};
		self.forward_transform(PE::cast_bases_mut(data), shape_ext, coset, coset_bits, skip_rounds)
	}

	fn inverse_transform_ext<PE: PackedExtension<F>>(
		&self,
		data: &mut [PE],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		let shape_ext = NTTShape {
			log_x: shape.log_x + PE::Scalar::LOG_DEGREE,
			..shape
		};
		self.inverse_transform(PE::cast_bases_mut(data), shape_ext, coset, coset_bits, skip_rounds)
	}
}

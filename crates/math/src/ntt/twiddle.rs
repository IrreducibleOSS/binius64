// Copyright 2024-2025 Irreducible Inc.

use std::{iter, marker::PhantomData, ops::Deref};

use binius_field::{BinaryField, Field};
use binius_utils::bail;

use super::error::Error;
use crate::BinarySubspace;

/// A trait for accessing twiddle factors in a single NTT round.
///
/// Twiddle factors in the additive NTT are subspace polynomial evaluations over linear subspaces,
/// with an implicit NTT round $i$.
/// Setup: let $K \mathbin{/} \mathbb{F}\_2$ be a finite extension of degree $d$, and let
/// $\beta_0,\ldots ,\beta_{d-1}$ be an $\mathbb{F}\_2$-basis. Let $U_i$ be the
/// $\mathbb{F}\_2$-linear span of $\beta_0,\ldots ,\beta_{i-1}$. Let $\hat{W}_i(X)$
/// be the normalized subspace polynomial of degree $2^i$ that vanishes on $U_i$ and is $1$ on
/// $\beta_i$. Evaluating $\hat{W}_i(X)$ turns out to yield an $\mathbb{F}\_2$-linear function $K
/// \rightarrow K$.
///
/// This trait accesses the subspace polynomial evaluations for $\hat{W}\_i(X)$.
/// The evaluations of the vanishing polynomial over all elements in any coset of the subspace
/// are equal. Equivalently, the evaluations of $\hat{W}\_i(X)$ are well-defined on
/// the $d-i$-dimensional vector space $K \mathbin{/} U_i$. Note that $K \mathbin{/} U_i$ has a
/// natural induced basis. Write $\{j\}$ for the $j$th coset of the subspace, where $j$ is in
/// $[0,2^{d-i})$, with respect to this natural basis. This means: write $j$ in binary: $j = j_0 +
/// \cdots + j_{d-i-1} \cdot 2^{d-i-1}$ and consider the following element of $K$: $j_0 \cdot
/// \beta_i + \cdots  + j_{d-i-1} \cdot \beta_{d-1}$. This element determines an element of $K
/// \mathbin{/} U_i$. The twiddle factor $t_{i,j}$ is then $\hat{W}\_i(\{j\})$, i.e., $\hat{W}\_j$
/// evaluated at the aforementioned element of the quotient $K \mathbin{/} U_i$.
///
/// As explained, the evaluations of these polynomial yield linear functions, which allows for
/// flexibility in how they are computed. Namely, for an evaluation domain of size $2^{i}$, there is
/// a strategy for computing polynomial evaluations "on-the-fly" with $O(\ell)$ field additions
/// using $O(\ell)$ stored elements or precomputing the $2^\ell$ evaluations and looking them up in
/// constant time (see the [`OnTheFlyTwiddleAccess`] and [`PrecomputedTwiddleAccess`]
/// implementations, respectively).
///
/// See [LCH14] and [DP24] Section 2.3 for more details.
///
/// [LCH14]: <https://arxiv.org/abs/1404.3458>
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub trait TwiddleAccess<F: BinaryField> {
	/// Base-2 logarithm of the number of twiddle factors in this round.
	fn log_n(&self) -> usize;

	/// The twiddle values are the span of this binary subspace, excluding 1 as a basis element,
	/// and with an affine shift.
	///
	/// Returns a tuple with the subspace and shift value.
	fn affine_subspace(&self) -> (BinarySubspace<F>, F);

	/// Get the twiddle factor at the given index.
	///
	/// Evaluate $\hat{W}\_i(X)$ at the element `index`: write `index` in binary
	/// and evaluate at the element $index_0\beta_{i+1} \ldots + index_{d-i-2}\beta_{d-1}$.
	///
	/// Panics if `index` is not in the range 0 to `1 << self.log_n()`.
	fn get(&self, index: usize) -> F;

	/// Get the pair of twiddle factors at the indices `index` and `(1 << index_bits) | index`.
	///
	/// Panics if `index_bits` is not in the range 0 to `self.log_n()` or `index` is not in the
	/// range 0 to `1 << index_bits`.
	fn get_pair(&self, index_bits: usize, index: usize) -> (F, F);

	/// Returns a scoped twiddle access for the coset that fixes the upper `coset_bits` of the
	/// index to `coset`.
	///
	/// Recall that a `TwiddleAccess` has an implicit NTT round $i$. Let $j=d-coset_{bits}$.
	/// Then`coset` returns a `TwiddleAccess` object (of NTT round i) for the following affine
	/// subspace of $K/U_{i-1}$: the set of all elements of $K/U_{i-1}$
	/// whose coordinates in the basis $\beta_i,\ldots ,\beta_{d-1}$ is:
	/// $(*, \cdots, *, coset_{0}, \ldots , coset_{bits-1})$, where the first $j$ coordinates are
	/// arbitrary. Here $coset = coset_0 + \ldots  + coset_{bits-1}2^{bits-1}$. In sum, this
	/// amounts to *evaluations* of $\hat{W}\_i$ at all such elements.
	///
	/// Therefore, the `self.log_n` of the new `TwiddleAccess` object is computed as `self.log_n() -
	/// coset_bits`.
	///
	/// Panics if `coset_bits` is not in the range 0 to `self.log_n()` or `coset` is not in the
	/// range 0 to `1 << coset_bits`.
	fn coset(&self, coset_bits: usize, coset: usize) -> impl TwiddleAccess<F>;
}

/// Twiddle access method that does on-the-fly computation to reduce its memory footprint.
///
/// This implementation uses a small amount of precomputed constants from which the twiddle factors
/// are derived on the fly (OTF). The number of constants is ~$1/2 d^2$ field elements for a domain
/// of size $2^d$.
#[derive(Debug)]
pub struct OnTheFlyTwiddleAccess<F, SEvals = Vec<F>> {
	log_n: usize,
	/// `offset` is a constant that is added to all twiddle factors.
	offset: F,
	/// `s_evals` is $<\hat{W}\_i(\beta_{i+1}),\ldots ,\hat{W}\_i(\beta_{d-1})>$ for the implicit
	/// round $i$.
	s_evals: SEvals,
}

impl<F: BinaryField> OnTheFlyTwiddleAccess<F> {
	/// Generate a vector of OnTheFlyTwiddleAccess objects, one for each NTT round.
	pub fn generate(subspace: &BinarySubspace<F>) -> Result<Vec<Self>, Error> {
		let log_domain_size = subspace.dim();
		let s_evals = precompute_subspace_evals(subspace)?
			.into_iter()
			.enumerate()
			.map(|(i, s_evals_i)| Self {
				log_n: log_domain_size - 1 - i,
				offset: F::ZERO,
				s_evals: s_evals_i,
			})
			.collect();
		// The `s_evals` for the $i$th round contains the evaluations of $\hat{W}\_i$ on
		// $\beta_{i+1},\ldots ,\beta_{d-1}$.
		Ok(s_evals)
	}
}

impl<F, SEvals> TwiddleAccess<F> for OnTheFlyTwiddleAccess<F, SEvals>
where
	F: BinaryField,
	SEvals: Deref<Target = [F]>,
{
	#[inline]
	fn log_n(&self) -> usize {
		self.log_n
	}

	fn affine_subspace(&self) -> (BinarySubspace<F>, F) {
		let subspace = BinarySubspace::new_unchecked(
			iter::once(F::ONE)
				.chain(self.s_evals.iter().copied())
				.collect(),
		);
		(subspace, self.offset)
	}

	#[inline]
	fn get(&self, i: usize) -> F {
		self.offset + subset_sum(&self.s_evals, self.log_n, i)
	}

	#[inline]
	fn get_pair(&self, index_bits: usize, i: usize) -> (F, F) {
		let t0 = self.offset + subset_sum(&self.s_evals, index_bits, i);
		(t0, t0 + self.s_evals[index_bits])
	}

	#[inline]
	fn coset(&self, coset_bits: usize, coset: usize) -> impl TwiddleAccess<F> {
		let log_n = self.log_n - coset_bits;
		let offset = subset_sum(&self.s_evals[log_n..], coset_bits, coset);
		OnTheFlyTwiddleAccess {
			log_n,
			offset: self.offset + offset,
			s_evals: &self.s_evals[..log_n],
		}
	}
}

fn subset_sum<F: Field>(values: &[F], n_bits: usize, index: usize) -> F {
	(0..n_bits)
		.filter(|b| (index >> b) & 1 != 0)
		.map(|b| values[b])
		.sum()
}

/// Twiddle access method using a larger table of precomputed constants.
///
/// This implementation precomputes all $2^k$ twiddle factors for a domain of size $2^k$.
#[derive(Debug)]
pub struct PrecomputedTwiddleAccess<F, SEvals = Vec<F>> {
	log_n: usize,
	/// If we are implicitly in NTT round i, then `s_evals` contains the evaluations of
	/// $\hat{W}\_i$ on the entire space $K/U_{i+1}$, where the order is the usual "binary
	/// counting order" in the basis vectors $\beta_{i+1},\ldots ,\beta_{d-1}$.
	///
	/// While $\hat{W}\_i$ is indeed well-defined on $K/U_i$, we have the
	/// normalization $\hat{W}\_{i}(\beta_i)=1$, hence to specify the function we need
	/// only specify it on $K/U_{i+1}$, equivalently, the $\mathbb{F}_2$-span of
	/// $\beta_{i+1},\ldots ,\beta_{d-1}$.
	s_evals: SEvals,
	_marker: PhantomData<F>,
}

impl<F: BinaryField> PrecomputedTwiddleAccess<F> {
	pub fn generate(subspace: &BinarySubspace<F>) -> Result<Vec<Self>, Error> {
		let on_the_fly = OnTheFlyTwiddleAccess::generate(subspace)?;
		Ok(expand_subspace_evals(&on_the_fly))
	}
}

impl<F, SEvals> TwiddleAccess<F> for PrecomputedTwiddleAccess<F, SEvals>
where
	F: BinaryField,
	SEvals: Deref<Target = [F]>,
{
	#[inline]
	fn log_n(&self) -> usize {
		self.log_n
	}

	fn affine_subspace(&self) -> (BinarySubspace<F>, F) {
		let shift = self.s_evals[0];
		let subspace = BinarySubspace::new_unchecked(
			iter::once(F::ONE)
				.chain((0..self.log_n()).map(|i| self.s_evals[1 << i] - shift))
				.collect(),
		);
		(subspace, shift)
	}

	#[inline]
	fn get(&self, i: usize) -> F {
		self.s_evals[i]
	}

	#[inline]
	fn get_pair(&self, index_bits: usize, i: usize) -> (F, F) {
		(self.s_evals[i], self.s_evals[1 << index_bits | i])
	}

	#[inline]
	fn coset(&self, coset_bits: usize, coset: usize) -> impl TwiddleAccess<F> {
		let log_n = self.log_n - coset_bits;
		PrecomputedTwiddleAccess {
			log_n,
			s_evals: &self.s_evals[coset << log_n..(coset + 1) << log_n],
			_marker: PhantomData,
		}
	}
}

/// Precompute the evaluations of the normalized subspace polynomials $\hat{W}_i$ on a basis.
///
/// Let $K/\mathbb{F}_2$ be a finite extension of degree $d$, and let $\beta_0,\ldots ,\beta_{d-1}$
/// be a linear basis, with $\beta_0$ = 1. Let $U_i$ be the $\mathbb{F}_2$-linear span of
/// $\beta_0,\ldots ,\beta_{i-1}$, so $U_0$ is the zero subspace. Let $\hat{W}\_i(X)$ be the
/// normalized subspace polynomial of degree $2^i$ that vanishes on $U_i$ and is $1$ on $\beta_i$.
/// Return a vector whose $i$th entry is a vector of evaluations of $\hat{W}\_i$ at
/// $\beta_{i+1},\ldots ,\beta_{d-1}$.
fn precompute_subspace_evals<F: BinaryField>(
	subspace: &BinarySubspace<F>,
) -> Result<Vec<Vec<F>>, Error> {
	let log_domain_size = subspace.dim();
	if log_domain_size == 0 {
		bail!(Error::DomainTooSmall {
			log_required_domain_size: 1,
		});
	}
	if subspace.basis()[0] != F::ONE {
		bail!(Error::DomainMustIncludeOne);
	}

	let mut s_evals = Vec::with_capacity(log_domain_size);

	// `normalization_consts[i]` = $W\_i(2^i):=  W\_i(\beta_i)$
	let mut normalization_consts = Vec::with_capacity(log_domain_size);
	// $\beta_0 = 1$ and $W\_0(X) = X$, so $W\_0(\beta_0) = \beta_0 = 1$
	normalization_consts.push(F::ONE);
	//`s0_evals` = $(\beta_1,\ldots ,\beta_{d-1}) = (W\_0(\beta_1), \ldots , W\_0(\beta_{d-1}))$
	let s0_evals = subspace.basis()[1..].to_vec();
	s_evals.push(s0_evals);
	// let $W\_i(X)$ be the *unnormalized* subspace polynomial, i.e., $\prod_{u\in U_{i}}(X-u)$.
	// Then $W\_{i+1}(X) = W\_i(X)(W\_i(X)+W\_i(\beta_i))$. This crucially uses the "linearity" of
	// $W\_i(X)$. This fundamental relation allows us to iteratively compute `s_evals` layer by
	// layer.
	for _ in 1..log_domain_size {
		let (norm_const_i, s_i_evals) = {
			let norm_prev = *normalization_consts
				.last()
				.expect("normalization_consts is not empty");
			let s_prev_evals = s_evals.last().expect("s_evals is not empty");
			// `norm_prev` = $W\_{i-1}(\beta_{i-1})$
			// s_prev_evals = $W\_{i-1}(\beta_i),\ldots ,W\_{i-1}(\beta_{d-1})$
			let norm_const_i = subspace_map(s_prev_evals[0], norm_prev);
			let s_i_evals = s_prev_evals
				.iter()
				.skip(1)
				.map(|&s_ij_prev| subspace_map(s_ij_prev, norm_prev))
				.collect::<Vec<_>>();
			// the two calls to the function subspace_map yield the following:
			// `norm_const_i` = $W\_{i}(\beta_i)$; and
			// `s_i_evals` = $W\_{i}(\beta_{i+1}),\ldots ,W\_{i}(\beta_{d-1})$.
			(norm_const_i, s_i_evals)
		};

		normalization_consts.push(norm_const_i);
		s_evals.push(s_i_evals);
	}

	for (norm_const_i, s_evals_i) in normalization_consts.iter().zip(s_evals.iter_mut()) {
		let inv_norm_const = norm_const_i
			.invert()
			.expect("normalization constants are nonzero");
		// replace all terms $W\_{i}(\beta_j)$ with $W\_{i}(\beta_j)/W\_{i}(\beta_i)$
		// to obtain the evaluations of the *normalized* subspace polynomials.
		for s_ij in s_evals_i.iter_mut() {
			*s_ij *= inv_norm_const;
		}
	}

	Ok(s_evals)
}

/// Computes the function $(e,c)\mapsto e^2+ce$.
///
/// This is primarily used to compute $W\_{i+1}(X)$ from $W\_i(X)$ in the binary field setting.
fn subspace_map<F: Field>(elem: F, constant: F) -> F {
	elem.square() + constant * elem
}

/// Given `OnTheFlyTwiddleAccess` instances for each NTT round, returns a vector of
/// `PrecomputedTwiddleAccess` objects, one for each NTT round.
///
/// For each round $i$, the input contains the value of $\hat{W}\_i$ on the basis
/// $\beta_{i+1},\ldots ,\beta_{d-1}$. The ith element of the output contains the evaluations of
/// $\hat{W}\_i$ on the entire space $K/U_{i+1}$, where the order is the usual "binary counting
/// order" in $\beta_{i+1},\ldots ,\beta_{d-1}$. While $\hat{W}\_i$ is well-defined on $K/U_i$, we
/// have the normalization $\hat{W}\_{i}(\beta_i)=1$, hence to specify the function we need only
/// specify it on $K/U_{i+1}$.
pub fn expand_subspace_evals<F, SEvals>(
	on_the_fly: &[OnTheFlyTwiddleAccess<F, SEvals>],
) -> Vec<PrecomputedTwiddleAccess<F>>
where
	F: BinaryField,
	SEvals: Deref<Target = [F]>,
{
	let log_domain_size = on_the_fly.len();
	on_the_fly
		.iter()
		.enumerate()
		.map(|(i, on_the_fly_i)| {
			let s_evals_i = &on_the_fly_i.s_evals;

			let mut expanded = Vec::with_capacity(1 << s_evals_i.len());
			expanded.push(F::ZERO);
			for &eval in s_evals_i.iter() {
				for i in 0..expanded.len() {
					expanded.push(expanded[i] + eval);
				}
			}

			PrecomputedTwiddleAccess {
				log_n: log_domain_size - 1 - i,
				s_evals: expanded,
				_marker: PhantomData,
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField, BinaryField8b, BinaryField16b, BinaryField32b};
	use lazy_static::lazy_static;
	use proptest::prelude::*;

	use super::*;

	lazy_static! {
		// Precomputed and OnTheFlytwiddle access objects for various binary field sizes.
		// We avoided doing the 32B precomputed twiddle access because the tests take too long.
		static ref PRECOMPUTED_TWIDDLE_ACCESS_8B: Vec<PrecomputedTwiddleAccess<BinaryField8b>> =
			PrecomputedTwiddleAccess::<BinaryField8b>::generate(&BinarySubspace::default()).unwrap();

		static ref OTF_TWIDDLE_ACCESS_8B: Vec<OnTheFlyTwiddleAccess<BinaryField8b>> =
			OnTheFlyTwiddleAccess::<BinaryField8b>::generate(&BinarySubspace::default()).unwrap();

		static ref PRECOMPUTED_TWIDDLE_ACCESS_16B: Vec<PrecomputedTwiddleAccess<BinaryField16b>> =
			PrecomputedTwiddleAccess::<BinaryField16b>::generate(&BinarySubspace::default()).unwrap();

		static ref OTF_TWIDDLE_ACCESS_16B: Vec<OnTheFlyTwiddleAccess<BinaryField16b>> =
			OnTheFlyTwiddleAccess::<BinaryField16b>::generate(&BinarySubspace::default()).unwrap();

		static ref OTF_TWIDDLE_ACCESS_32B: Vec<OnTheFlyTwiddleAccess<BinaryField32b>> =
			OnTheFlyTwiddleAccess::<BinaryField32b>::generate(&BinarySubspace::default()).unwrap();
	}

	// Tests that `PrecomputedTwiddleAccess` and `OnTheFlyTwiddleAccess`is linear.
	// (This is more or less by design/construction for `PrecomputedTwiddleAccess`.)
	// More concretely: picks a `layer`, $\ell$, and two valid indices,
	// checks if the claimed equality holds: $\hat{W}_{\ell}(x) + \hat{W}_{\ell}(y) =
	// \hat{W}_{\ell}(x + y).$
	proptest! {
		#[test]
		fn test_linearity_precomputed_8b((x, y, layer) in generate_layer_and_indices(8)) {
			let twiddle_access = &PRECOMPUTED_TWIDDLE_ACCESS_8B[layer];
			test_linearity::<BinaryField8b, _>(twiddle_access, x, y);
		}

		#[test]
		fn test_linearity_precomputed_16b((x, y, layer) in generate_layer_and_indices(16)) {
			let twiddle_access = &PRECOMPUTED_TWIDDLE_ACCESS_16B[layer];
			test_linearity::<BinaryField16b, _>(twiddle_access, x, y);
		}

		#[test]
		fn test_linearity_otf_8b((x, y, layer) in generate_layer_and_indices(8)) {
			let twiddle_access = &OTF_TWIDDLE_ACCESS_8B[layer];
			test_linearity::<BinaryField8b, _>(twiddle_access, x, y);
		}

		#[test]
		fn test_linearity_otf_16b((x, y, layer) in generate_layer_and_indices(16)) {
			let twiddle_access = &OTF_TWIDDLE_ACCESS_16B[layer];
			test_linearity::<BinaryField16b, _>(twiddle_access, x, y);
		}

		#[test]
		fn test_linearity_otf_32b((x, y, layer) in generate_layer_and_indices(32)) {
			let twiddle_access = &OTF_TWIDDLE_ACCESS_32B[layer];
			test_linearity::<BinaryField32b, _>(twiddle_access, x, y);
		}

	}

	// Test compatibility between layers for a `TwiddleAccess` object. More precisely,
	// this checks that the values of $\hat{W}_{\ell}$ and $\hat{W}_{\ell+1}$ are compatible.
	proptest! {
		#[test]
		fn test_compatibility_otf_8b((x, layer) in generate_layer_and_index(8)){
			compatibility_between_layers::<BinaryField8b,_>(layer, &OTF_TWIDDLE_ACCESS_8B, x);
		}

		#[test]
		fn test_compatibility_otf_16b((x, layer) in generate_layer_and_index(16)){
			compatibility_between_layers::<BinaryField16b,_>(layer, &OTF_TWIDDLE_ACCESS_16B, x);
		}

		#[test]
		fn test_compatibility_otf_32b((x, layer) in generate_layer_and_index(32)){
			compatibility_between_layers::<BinaryField32b,_>(layer, &OTF_TWIDDLE_ACCESS_32B, x);
		}

		#[test]
		fn test_compatibility_precomputed_8b((x, layer) in generate_layer_and_index(8)){
			compatibility_between_layers::<BinaryField8b,_>(layer, &PRECOMPUTED_TWIDDLE_ACCESS_8B, x);
		}

		#[test]
		fn test_compatibility_precomputed_16b((x, layer) in generate_layer_and_index(16)){
			compatibility_between_layers::<BinaryField16b,_>(layer, &PRECOMPUTED_TWIDDLE_ACCESS_16B, x);
		}

	}

	prop_compose! {
		/// Given a `max_layer`, which is implicitly assumed to be the logarithm of the field size,
		/// generate a layer (between 0 and `max_layer-2`) of the NTT instance,
		/// such that `layer+1` is a valid layer, and furthermore generate
		/// a valid index $x$ for `layer+1`.
		///
		/// Designed to test for compatibility between layers, hence `layer+1` must also be a valid layer.
		fn generate_layer_and_index
			(max_layer: usize)
			(layer in 0usize..max_layer-1)
			(x in 0usize..(1 << (max_layer-layer-2)), layer in Just(layer))
				-> (usize, usize) {
			(x, layer)
		}
	}

	prop_compose! {
		/// Given a `max_layer`, which is implicitly assumed to be the logarithm of the field size,
		/// generate a layer (between 0 and `max_layer-1`) of the NTT instance a
		/// pair of indices $(x, y)$ that are valid for that layer.
		///
		/// Designed for testing linearity.
		fn generate_layer_and_indices
			(max_layer: usize)
			(layer in 0usize..max_layer)
			(x in 0usize..(1 << (max_layer-layer-1)), y in 0usize..1<<(max_layer-layer-1), layer in Just(layer))
				-> (usize, usize, usize) {
			(x, y, layer)
		}
	}

	/// Given a `TwiddleAccess` object, test linearity, i.e., that:
	/// $\hat{W}\_{\ell}(x) + \hat{W}\_{\ell}(y) = \hat{W}\_{\ell}(x + y)$.
	///
	/// Here, it is important to note that although $x$ and $y$ are `usize`, we consider them
	/// elements of the $F$ via the binary expansion encoding the coefficients of a basis
	/// expansion. Then the expression $x+y$ in $F$ corresponds to the bitwise XOR of the
	/// two `usize` values.
	fn test_linearity<F: BinaryField + std::fmt::Display, T: TwiddleAccess<F>>(
		twiddle_access: &T,
		x: usize,
		y: usize,
	) {
		let first_val = twiddle_access.get(x);
		let second_val = twiddle_access.get(y);
		assert_eq!(first_val + second_val, twiddle_access.get(x ^ y));
	}

	/// Test for compatibility between adjacent layers of a `TwiddleAccess` object.
	///
	/// This checks that the values of $\hat{W}\_{\ell}$ and $\hat{W}\_{\ell+1}$ are compatible.
	/// Set $\tilde{W}\_{\ell+1}(X)=\hat{W}\_{\ell}(X)(\hat{W}\_{\ell}(X)+1)$.
	/// Then $\hat{W}\_{\ell+1}(X)=\tilde{W}\_{\ell+1}(X)/\tilde{W}\_{\ell+1}(\beta_{\ell+1})$.
	/// (The above ensures that $\hat{W}\_{\ell+1}$ has the right properties: vanishes in $U_{\ell}$
	/// and is 1 at $\beta_{\ell+1}$.) This means that knowing $\hat{W}\_{\ell}(x)$ and
	/// $\hat{W}\_{\ell}(\beta_{\ell+1}$, we can compute $\hat{W}\_{\ell+1}(x)$.
	fn compatibility_between_layers<F: BinaryField + std::fmt::Display, T: TwiddleAccess<F>>(
		layer: usize,
		twiddle_access: &[T],
		// `index_next_layer` is a valid index for the layer `layer+1`,
		// i.e., `twiddle_access_next_layer.get(index)` makes sense.
		index_next_layer: usize,
	) {
		let twiddle_access_layer = &twiddle_access[layer];
		let twiddle_access_next_layer = &twiddle_access[layer + 1];
		// `index` corresponds to an element of $F/U_{i+1}$. This corresponds to elements
		// of the space $F/U_i$ whose $\beta_i$ and $\beta_{i+1}$ coordinates are both 0.
		let index = index_next_layer << 1;
		// If index corresponds to an element $x$ in $F$.
		// Claimed value of $\hat{W}_{\ell}(x)$.
		let w_hat_layer_x = twiddle_access_layer.get(index);
		// Claimed value of $\hat{W}_{\ell+1}(x)$.
		let w_hat_next_layer_x = twiddle_access_next_layer.get(index_next_layer);
		// In the below, `beta` refers to $\beta_{\ell+1}$.
		// $\hat{W}_{\ell}(\beta_{\ell+1})$.
		let w_hat_layer_beta = twiddle_access_layer.get(1);
		// `normalizing_factor` is $\hat{W}_{\ell}(\beta) * (\hat{W}_{\ell}(\beta) + 1)$,
		// i.e. $\tilde{W}_{\ell+1}(\beta)$.
		let normalizing_factor = w_hat_layer_beta * w_hat_layer_beta + w_hat_layer_beta;
		assert_eq!(
			w_hat_next_layer_x * normalizing_factor,
			w_hat_layer_x * w_hat_layer_x + w_hat_layer_x
		);
	}
}

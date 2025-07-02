// Copyright 2024-2025 Irreducible Inc.

use binius_field::BinaryField;
use binius_utils::{bail, iter::IterExtensions};

use super::error::Error;

/// An $F_2$-linear subspace of a binary field.
///
/// The subspace is defined by a basis of elements from a binary field. The basis elements are
/// ordered, which implies an ordering on the subspace elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinarySubspace<F: BinaryField> {
	basis: Vec<F>,
}

impl<F: BinaryField> BinarySubspace<F> {
	/// Creates a new subspace from a vector of ordered basis elements.
	///
	/// This constructor does not check that the basis elements are linearly independent.
	pub const fn new_unchecked(basis: Vec<F>) -> Self {
		Self { basis }
	}

	/// Creates a new subspace of this binary subspace with the given dimension.
	///
	/// This creates a new sub-subspace using a prefix of the default $\mathbb{F}_2$ basis elements
	/// of the field.
	///
	/// ## Throws
	///
	/// * `Error::DomainSizeTooLarge` if `dim` is greater than this subspace's dimension.
	pub fn with_dim(dim: usize) -> Result<Self, Error> {
		let basis = (0..dim)
			.map(|i| F::basis_checked(i).map_err(|_| Error::DomainSizeTooLarge))
			.collect::<Result<_, _>>()?;
		Ok(Self { basis })
	}

	/// Creates a new subspace of this binary subspace with reduced dimension.
	///
	/// This creates a new sub-subspace using a prefix of the ordered basis elements.
	///
	/// ## Throws
	///
	/// * `Error::DomainSizeTooLarge` if `dim` is greater than this subspace's dimension.
	pub fn reduce_dim(&self, dim: usize) -> Result<Self, Error> {
		if dim > self.dim() {
			bail!(Error::DomainSizeTooLarge);
		}
		Ok(Self {
			basis: self.basis[..dim].to_vec(),
		})
	}

	/// Creates a new subspace isomorphic to the given one.
	pub fn isomorphic<FIso>(&self) -> BinarySubspace<FIso>
	where
		FIso: BinaryField + From<F>,
	{
		BinarySubspace {
			basis: self.basis.iter().copied().map(Into::into).collect(),
		}
	}

	/// Returns the dimension of the subspace.
	pub fn dim(&self) -> usize {
		self.basis.len()
	}

	/// Returns the slice of ordered basis elements.
	pub fn basis(&self) -> &[F] {
		&self.basis
	}

	pub fn get(&self, index: usize) -> F {
		self.basis
			.iter()
			.take(usize::BITS as usize)
			.enumerate()
			.fold(F::ZERO, |acc, (i, basis_i)| {
				if (index >> i) & 1 != 0 {
					acc + basis_i
				} else {
					acc
				}
			})
	}

	pub fn get_checked(&self, index: usize) -> Result<F, Error> {
		if index >= 1 << self.basis.len() {
			bail!(Error::ArgumentRangeError {
				arg: "index".to_string(),
				range: 0..1 << self.basis.len(),
			});
		}
		Ok(self.get(index))
	}

	/// Returns an iterator over all elements of the subspace in order.
	///
	/// This has a limitation that the iterator only yields the first `2^usize::BITS` elements.
	pub fn iter(&self) -> impl Iterator<Item = F> + '_ {
		let last = if self.basis.len() < usize::BITS as usize {
			(1 << self.basis.len()) - 1
		} else {
			usize::MAX
		};
		(0..=last).map_skippable(|i| self.get(i))
	}
}

impl<F: BinaryField> Default for BinarySubspace<F> {
	fn default() -> Self {
		let basis = (0..F::DEGREE).map(|i| F::basis(i)).collect();
		Self { basis }
	}
}

#[cfg(test)]
mod tests {
	use assert_matches::assert_matches;
	use binius_field::{BinaryField8b, BinaryField128b};

	use super::*;

	#[test]
	fn test_default_binary_subspace_iterates_elements() {
		let subspace = BinarySubspace::<BinaryField8b>::default();
		for i in 0..=255 {
			assert_eq!(subspace.get(i), BinaryField8b::new(i as u8));
		}
	}

	#[test]
	fn test_binary_subspace_range_error() {
		let subspace = BinarySubspace::<BinaryField8b>::default();
		assert_matches!(subspace.get_checked(256), Err(Error::ArgumentRangeError { .. }));
	}

	#[test]
	fn test_default_large_binary_subspace_iterates_elements() {
		let subspace = BinarySubspace::<BinaryField128b>::default();
		for i in 0..=255 {
			assert_eq!(subspace.get(i), BinaryField128b::new(i as u128));
		}
	}

	#[test]
	fn test_default_binary_subspace() {
		let subspace = BinarySubspace::<BinaryField8b>::default();
		assert_eq!(subspace.dim(), 8);
		assert_eq!(subspace.basis().len(), 8);

		assert_eq!(
			subspace.basis(),
			[
				BinaryField8b::new(0b00000001),
				BinaryField8b::new(0b00000010),
				BinaryField8b::new(0b00000100),
				BinaryField8b::new(0b00001000),
				BinaryField8b::new(0b00010000),
				BinaryField8b::new(0b00100000),
				BinaryField8b::new(0b01000000),
				BinaryField8b::new(0b10000000)
			]
		);

		let expected_elements: [u8; 256] = (0..=255).collect::<Vec<_>>().try_into().unwrap();

		for (i, &expected) in expected_elements.iter().enumerate() {
			assert_eq!(subspace.get(i), BinaryField8b::new(expected));
		}
	}

	#[test]
	fn test_with_dim_valid() {
		let subspace = BinarySubspace::<BinaryField8b>::with_dim(3).unwrap();
		assert_eq!(subspace.dim(), 3);
		assert_eq!(subspace.basis().len(), 3);

		assert_eq!(
			subspace.basis(),
			[
				BinaryField8b::new(0b001),
				BinaryField8b::new(0b010),
				BinaryField8b::new(0b100)
			]
		);

		let expected_elements: [u8; 8] = [0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111];

		for (i, &expected) in expected_elements.iter().enumerate() {
			assert_eq!(subspace.get(i), BinaryField8b::new(expected));
		}
	}

	#[test]
	fn test_with_dim_invalid() {
		let result = BinarySubspace::<BinaryField8b>::with_dim(10);
		assert_matches!(result, Err(Error::DomainSizeTooLarge));
	}

	#[test]
	fn test_reduce_dim_valid() {
		let subspace = BinarySubspace::<BinaryField8b>::with_dim(6).unwrap();
		let reduced = subspace.reduce_dim(4).unwrap();
		assert_eq!(reduced.dim(), 4);
		assert_eq!(reduced.basis().len(), 4);

		assert_eq!(
			reduced.basis(),
			[
				BinaryField8b::new(0b0001),
				BinaryField8b::new(0b0010),
				BinaryField8b::new(0b0100),
				BinaryField8b::new(0b1000)
			]
		);

		let expected_elements: [u8; 16] = (0..16).collect::<Vec<_>>().try_into().unwrap();

		for (i, &expected) in expected_elements.iter().enumerate() {
			assert_eq!(reduced.get(i), BinaryField8b::new(expected));
		}
	}

	#[test]
	fn test_reduce_dim_invalid() {
		let subspace = BinarySubspace::<BinaryField8b>::with_dim(4).unwrap();
		let result = subspace.reduce_dim(6);
		assert_matches!(result, Err(Error::DomainSizeTooLarge));
	}

	#[test]
	fn test_isomorphic_conversion() {
		let subspace = BinarySubspace::<BinaryField8b>::with_dim(3).unwrap();
		let iso_subspace: BinarySubspace<BinaryField128b> = subspace.isomorphic();
		assert_eq!(iso_subspace.dim(), 3);
		assert_eq!(iso_subspace.basis().len(), 3);

		assert_eq!(
			iso_subspace.basis(),
			[
				BinaryField128b::from(BinaryField8b::new(0b001)),
				BinaryField128b::from(BinaryField8b::new(0b010)),
				BinaryField128b::from(BinaryField8b::new(0b100))
			]
		);
	}

	#[test]
	fn test_get_checked_valid() {
		let subspace = BinarySubspace::<BinaryField8b>::default();
		for i in 0..256 {
			assert!(subspace.get_checked(i).is_ok());
		}
	}

	#[test]
	fn test_get_checked_invalid() {
		let subspace = BinarySubspace::<BinaryField8b>::default();
		assert_matches!(subspace.get_checked(256), Err(Error::ArgumentRangeError { .. }));
	}

	#[test]
	fn test_iterate_subspace() {
		let subspace = BinarySubspace::<BinaryField8b>::with_dim(3).unwrap();
		let elements: Vec<_> = subspace.iter().collect();
		assert_eq!(elements.len(), 8);

		let expected_elements: [u8; 8] = [0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111];

		for (i, &expected) in expected_elements.iter().enumerate() {
			assert_eq!(elements[i], BinaryField8b::new(expected));
		}
	}
}

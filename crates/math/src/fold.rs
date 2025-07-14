//! Algorithms for matrix multiplications and generalized tensor contractions.

use std::ops::Deref;

use binius_field::{Field, util::inner_product_unchecked};

use super::error::Error;
use crate::field_buffer::FieldBuffer;

/// Computes a linear combination of the columns of a matrix.
///
/// A column-combination of a matrix is a matrix-vector multiplication.
///
/// This implementation is a naive, single-threaded implementation operating on buffers of scalar
/// elements.
///
/// ## Mathematical Definition
///
/// This operation accepts
///
/// * $n \in \mathbb{N}$ (`out.len()`),
/// * $m \in \mathbb{N}$ (`vec.len()`),
/// * $M \in K^{n \times m}$ (`mat`),
/// * $v \in K^m$ (`vec`),
///
/// and computes the vector $Mv$.
///
/// ## Args
///
/// * `mat` - a buffer of `n * m` `F` elements, interpreted as a row-major matrix.
/// * `vec` - a buffer of `m` `F` elements containing the column scalars.
///
/// ## Returns
///
/// The matrix-vector product, as a buffer of `F` elements.
///
/// ## Throws
///
/// * Returns an error if `mat.len()` does not equal `vec.len() * out.len()`.
/// * Returns an error if `mat` is not a subfield of `F`.
pub fn fold_cols<F, DataMat, DataVec>(
	mat: &FieldBuffer<F, DataMat>,
	vec: &FieldBuffer<F, DataVec>,
) -> Result<FieldBuffer<F>, Error>
where
	F: Field,
	DataMat: Deref<Target = [F]>,
	DataVec: Deref<Target = [F]>,
{
	let log_m = vec.log_len();
	let Some(log_n) = mat.log_len().checked_sub(vec.log_len()) else {
		return Err(Error::ArgumentRangeError {
			arg: "vec.log_len()".to_string(),
			range: 0..mat.log_len(),
		});
	};

	let ret_vals = mat
		.chunks(log_m)?
		.map(|row| {
			inner_product_unchecked(row.as_ref().iter().copied(), vec.as_ref().iter().copied())
		})
		.collect::<Box<[_]>>();
	FieldBuffer::new(log_n, ret_vals)
}

/// Computes a linear combination of the rows of a matrix.
///
/// A row-combination of a matrix is a vector-matrix multiplication.
///
/// This implementation is a naive, single-threaded implementation operating on buffers of scalar
/// elements.
///
/// ## Mathematical Definition
///
/// This operation accepts
///
/// * $n \in \mathbb{N}$ (`vec.len()`),
/// * $m \in \mathbb{N}$ (`out.len()`),
/// * $M \in K^{n \times m}$ (`mat`),
/// * $v \in K^m$ (`vec`),
///
/// and computes the vector $v^\top M^\top$.
///
/// ## Args
///
/// * `mat` - a buffer of `n * m` `F` elements, interpreted as a row-major matrix.
/// * `vec` - a buffer of `n` `F` elements containing the row scalars.
///
/// ## Returns
///
/// The vector-matrix product, as a buffer of `F` elements.
///
/// ## Throws
///
/// * Returns an error if `mat.len()` does not equal `vec.len() * out.len()`.
/// * Returns an error if `mat` is not a subfield of `F`.
pub fn fold_rows<F, DataMat, DataVec>(
	mat: &FieldBuffer<F, DataMat>,
	vec: &FieldBuffer<F, DataVec>,
) -> Result<FieldBuffer<F>, Error>
where
	F: Field,
	DataMat: Deref<Target = [F]>,
	DataVec: Deref<Target = [F]>,
{
	let log_n = vec.log_len();
	let Some(log_m) = mat.log_len().checked_sub(vec.log_len()) else {
		return Err(Error::ArgumentRangeError {
			arg: "vec.log_len()".to_string(),
			range: 0..mat.log_len(),
		});
	};

	let mat_vals = mat.as_ref();
	let ret_vals = (0..1 << log_m)
		.map(|col_i| {
			let col = (0..1 << log_n).map(|row_i| mat_vals[(row_i << log_m) + col_i]);
			inner_product_unchecked(col, vec.as_ref().iter().copied())
		})
		.collect::<Box<[_]>>();
	FieldBuffer::new(log_m, ret_vals)
}

#[cfg(test)]
mod tests {
	use std::iter;

	use binius_field::{BinaryField128b as B128, Random};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::test_utils::random_scalars;

	#[test]
	fn test_fold_cols_linear_in_matrix() {
		let mut rng = StdRng::seed_from_u64(0);

		// Matrix dimensions: 2^5 x 2^5 = 32 x 32 = 2^10 elements total
		let log_rows = 5;
		let log_cols = 5;
		let total_elements = 1 << (log_rows + log_cols);

		// Generate two random matrices
		let mat0_values = random_scalars::<B128>(&mut rng, total_elements);
		let mat0 = FieldBuffer::<B128>::from_values(&mat0_values).unwrap();

		let mat1_values = random_scalars::<B128>(&mut rng, total_elements);
		let mat1 = FieldBuffer::<B128>::from_values(&mat1_values).unwrap();

		// Generate random vector
		let vec_values = random_scalars::<B128>(&mut rng, 1 << log_cols);
		let vec = FieldBuffer::<B128>::from_values(&vec_values).unwrap();

		// Generate random scalars
		let scalar0 = B128::random(&mut rng);
		let scalar1 = B128::random(&mut rng);

		// Compute left side: (scalar0 * mat0 + scalar1 * mat1) * vec
		let scaled_mat_values: Vec<B128> = iter::zip(&mat0_values, &mat1_values)
			.map(|(&m0, &m1)| scalar0 * m0 + scalar1 * m1)
			.collect();
		let scaled_mat = FieldBuffer::<B128>::from_values(&scaled_mat_values).unwrap();
		let left_side = fold_cols(&scaled_mat, &vec).unwrap();

		// Compute right side: scalar0 * (mat0 * vec) + scalar1 * (mat1 * vec)
		let mat0_vec = fold_cols(&mat0, &vec).unwrap();
		let mat1_vec = fold_cols(&mat1, &vec).unwrap();
		let right_side_values: Vec<B128> = mat0_vec
			.as_ref()
			.iter()
			.zip(mat1_vec.as_ref().iter())
			.map(|(&m0v, &m1v)| scalar0 * m0v + scalar1 * m1v)
			.collect();
		let right_side = FieldBuffer::<B128>::from_values(&right_side_values).unwrap();

		// Compare results
		assert_eq!(left_side.as_ref(), right_side.as_ref());
	}

	#[test]
	fn test_fold_cols_linear_in_vector() {
		let mut rng = StdRng::seed_from_u64(0);

		// Matrix dimensions: 2^5 x 2^5 = 32 x 32 = 2^10 elements total
		let log_rows = 5;
		let log_cols = 5;
		let total_elements = 1 << (log_rows + log_cols);

		// Generate random matrix
		let mat_values = random_scalars::<B128>(&mut rng, total_elements);
		let mat = FieldBuffer::<B128>::from_values(&mat_values).unwrap();

		// Generate two random vectors
		let vec0_values = random_scalars::<B128>(&mut rng, 1 << log_cols);
		let vec0 = FieldBuffer::<B128>::from_values(&vec0_values).unwrap();

		let vec1_values = random_scalars::<B128>(&mut rng, 1 << log_cols);
		let vec1 = FieldBuffer::<B128>::from_values(&vec1_values).unwrap();

		// Generate random scalars
		let scalar0 = B128::random(&mut rng);
		let scalar1 = B128::random(&mut rng);

		// Compute left side: mat * (scalar0 * vec0 + scalar1 * vec1)
		let scaled_vec_values: Vec<B128> = vec0_values
			.iter()
			.zip(vec1_values.iter())
			.map(|(&v0, &v1)| scalar0 * v0 + scalar1 * v1)
			.collect();
		let scaled_vec = FieldBuffer::<B128>::from_values(&scaled_vec_values).unwrap();
		let left_side = fold_cols(&mat, &scaled_vec).unwrap();

		// Compute right side: scalar0 * (mat * vec0) + scalar1 * (mat * vec1)
		let mat_vec0 = fold_cols(&mat, &vec0).unwrap();
		let mat_vec1 = fold_cols(&mat, &vec1).unwrap();
		let right_side_values: Vec<B128> = mat_vec0
			.as_ref()
			.iter()
			.zip(mat_vec1.as_ref().iter())
			.map(|(&mv0, &mv1)| scalar0 * mv0 + scalar1 * mv1)
			.collect();
		let right_side = FieldBuffer::<B128>::from_values(&right_side_values).unwrap();

		// Compare results
		assert_eq!(left_side.as_ref(), right_side.as_ref());
	}

	#[test]
	fn test_fold_cols_equals_fold_rows_transpose() {
		let mut rng = StdRng::seed_from_u64(0);

		// Matrix dimensions: 2^5 x 2^5 = 32 x 32 = 2^10 elements total
		let log_rows = 5;
		let log_cols = 5;
		let n_rows = 1 << log_rows;
		let n_cols = 1 << log_cols;
		let total_elements = n_rows * n_cols;

		// Generate random matrix
		let mat_values = random_scalars::<B128>(&mut rng, total_elements);
		let mat = FieldBuffer::<B128>::from_values(&mat_values).unwrap();

		// Generate random vector
		let vec_values = random_scalars::<B128>(&mut rng, n_cols);
		let vec = FieldBuffer::<B128>::from_values(&vec_values).unwrap();

		// Compute fold_cols(mat, vec) which gives mat * vec
		let fold_cols_result = fold_cols(&mat, &vec).unwrap();

		// Transpose the matrix: mat_T[j,i] = mat[i,j]
		// Original matrix is row-major: mat[i,j] = mat_values[i * n_cols + j]
		// Transposed matrix is row-major: mat_T[j,i] = mat_T_values[j * n_rows + i]
		let mut mat_t_values = vec![B128::ZERO; total_elements];
		for i in 0..n_rows {
			for j in 0..n_cols {
				let orig_idx = i * n_cols + j;
				let trans_idx = j * n_rows + i;
				mat_t_values[trans_idx] = mat_values[orig_idx];
			}
		}
		let mat_t = FieldBuffer::<B128>::from_values(&mat_t_values).unwrap();

		// Compute fold_rows(mat_T, vec) which gives vec^T * mat^T
		// This should equal mat * vec (same as fold_cols_result)
		let fold_rows_result = fold_rows(&mat_t, &vec).unwrap();

		// Extract values from both results for comparison
		let fold_cols_values: Vec<B128> = (0..fold_cols_result.len())
			.map(|i| fold_cols_result.to_ref().get(i).unwrap())
			.collect();
		let fold_rows_values: Vec<B128> = (0..fold_rows_result.len())
			.map(|i| fold_rows_result.to_ref().get(i).unwrap())
			.collect();

		// Compare results
		assert_eq!(fold_cols_values, fold_rows_values);
	}
}

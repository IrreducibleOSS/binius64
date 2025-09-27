use binius_field::{Field, Random};
use itertools::izip;
use rand::rngs::StdRng;

/// Fold two values: (1-r)*a + r*b
#[inline]
pub fn fold_one<F: Field + Copy>(a: F, b: F, r: F) -> F {
	(F::ONE - r) * a + r * b
}

/// Generic affine-system check over any field F implementing binius_field::Field.
///
/// Math background (vector-valued affine maps over a field):
/// - A function f: F^n -> F^m is affine iff there exists a linear map A and a vector b
///   such that f(x) = A x + b.
///
/// Verification: 2-point affine identity
///     f((1-r)*x + r*y) = (1-r)*f(x) + r*f(y)
///
/// Proof that affine functions satisfy this identity:
/// If f(x) = Ax + b, then:
///   LHS: f((1-r)*x + r*y) = A((1-r)*x + r*y) + b
///                         = (1-r)Ax + rAy + b
///   
///   RHS: (1-r)*f(x) + r*f(y) = (1-r)*(Ax + b) + r*(Ay + b)
///                             = (1-r)Ax + (1-r)b + rAy + rb
///                             = (1-r)Ax + rAy + ((1-r) + r)b
///                             = (1-r)Ax + rAy + b
///
/// Therefore LHS = RHS for all affine functions f.
///
/// Soundness: Why non-affine functions fail with high probability
/// If f is not affine, then for most pairs (x, y), define:
///   g(r) = f((1-r)x + ry) - (1-r)f(x) - rf(y)
///
/// Since f is not affine, g(r) is a non-zero polynomial in r for most (x, y).
/// By the Schwartz-Zippel lemma, for a random r ∈ F:
///   Pr[g(r) = 0] ≤ deg(g) / |F|
///
/// We're assuming deg(g) << |F|, so the probability of
/// accidentally passing is negligible (roughly 1/|F| for large finite fields).
///
/// Therefore: affine functions always pass, non-affine functions fail whp.
pub fn test_affinity<F, Map>(rng: &mut StdRng, dim: usize, f: Map)
where
	F: Field + Random + Copy + core::fmt::Debug + PartialEq,
	Map: Fn(&[F]) -> Vec<F>,
{
	// Random points and scalar
	let x: Vec<F> = (0..dim).map(|_| F::random(&mut *rng)).collect();
	let y: Vec<F> = (0..dim).map(|_| F::random(&mut *rng)).collect();
	let r: F = F::random(&mut *rng);

	let left = {
		let comb: Vec<F> = izip!(x.iter(), y.iter())
			.map(|(a, b)| fold_one(*a, *b, r))
			.collect();
		f(&comb)
	};
	let right = {
		izip!(f(&x), f(&y))
			.map(|(a, b)| fold_one(a, b, r))
			.collect::<Vec<_>>()
	};
	assert_eq!(left, right, "2-point affine identity failed");
}

// =============================
// Generic matrix rank routines
// =============================

#[derive(Debug, Clone, PartialEq, Eq)]
struct Matrix<F: Field + Copy> {
	m: usize,
	n: usize,
	elements: Vec<F>, // row-major
}

impl<F: Field + Copy> Matrix<F> {
	fn new(m: usize, n: usize, elements: Vec<F>) -> Result<Self, String> {
		if elements.len() != m * n {
			return Err(format!(
				"Elements length {} does not match matrix dimensions {}x{}",
				elements.len(),
				m,
				n
			));
		}
		Ok(Self { m, n, elements })
	}

	#[inline]
	fn get(&self, i: usize, j: usize) -> F {
		assert!(i < self.m && j < self.n);
		self.elements[i * self.n + j]
	}

	#[inline]
	fn set(&mut self, i: usize, j: usize, value: F) {
		assert!(i < self.m && j < self.n);
		self.elements[i * self.n + j] = value;
	}

	#[inline]
	fn swap_rows(&mut self, i0: usize, i1: usize) {
		if i0 == i1 {
			return;
		}
		for j in 0..self.n {
			let tmp = self.get(i0, j);
			self.set(i0, j, self.get(i1, j));
			self.set(i1, j, tmp);
		}
	}

	#[inline]
	fn scale_row(&mut self, row: usize, scalar: F) {
		for j in 0..self.n {
			let cur = self.get(row, j);
			self.set(row, j, cur * scalar);
		}
	}

	#[inline]
	fn sub_scaled_row(&mut self, target: usize, src: usize, scalar: F) {
		for j in 0..self.n {
			let t = self.get(target, j);
			let s = self.get(src, j);
			self.set(target, j, t - s * scalar);
		}
	}

	/// Gaussian elimination rank over a field.
	fn rank(&mut self) -> usize {
		let mut rank = 0;
		for col in 0..self.n {
			// Find pivot with non-zero entry in this column at or below `rank`
			let mut pivot_row: Option<usize> = None;
			for row in rank..self.m {
				let e = self.get(row, col);
				// e == 0 iff e == e - e
				if e != (e - e) {
					pivot_row = Some(row);
					break;
				}
			}
			if let Some(p) = pivot_row {
				if p != rank {
					self.swap_rows(rank, p);
				}
				// Normalize pivot row
				let pivot = self.get(rank, col);
				let inv = pivot.invert().expect("pivot element is non-zero");
				self.scale_row(rank, inv);
				// Eliminate other rows in this column
				for r in 0..self.m {
					if r == rank {
						continue;
					}
					let entry = self.get(r, col);
					if entry != (entry - entry) {
						self.sub_scaled_row(r, rank, entry);
					}
				}
				rank += 1;
			}
		}
		rank
	}
}

/// Compute rank from rows for any field F.
pub fn compute_matrix_rank_from_rows<F: Field + Copy + PartialEq>(rows: &[Vec<F>]) -> usize {
	if rows.is_empty() {
		return 0;
	}
	let n_cols = rows[0].len();
	if n_cols == 0 {
		return 0;
	}
	for (i, row) in rows.iter().enumerate() {
		assert_eq!(row.len(), n_cols, "Row {i} has length {} (expected {n_cols})", row.len());
	}
	let mut elements = Vec::with_capacity(rows.len() * n_cols);
	for row in rows {
		elements.extend_from_slice(row);
	}
	let mut mat = Matrix::<F>::new(rows.len(), n_cols, elements).expect("consistent dims");
	mat.rank()
}

/// Compute rank from columns for any field F.
pub fn compute_matrix_rank_from_cols<F: Field + Copy + PartialEq>(cols: &[Vec<F>]) -> usize {
	if cols.is_empty() {
		return 0;
	}
	let n_rows = cols[0].len();
	if n_rows == 0 {
		return 0;
	}
	for (i, col) in cols.iter().enumerate() {
		assert_eq!(col.len(), n_rows, "Column {i} has length {} (expected {n_rows})", col.len());
	}
	// Transpose columns -> rows
	let mut elements = Vec::with_capacity(n_rows * cols.len());
	for r in 0..n_rows {
		for col in cols {
			elements.push(col[r]);
		}
	}
	let mut mat = Matrix::<F>::new(n_rows, cols.len(), elements).expect("consistent dims");
	mat.rank()
}

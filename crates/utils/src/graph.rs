// Copyright 2024-2025 Irreducible Inc.

use std::cmp::Ordering;

/// Finds connected components using a Kruskal-like approach.
/// Each input slice of usizes represents a set of nodes that form a complete subgraph
/// (i.e., all of them are connected).
///
/// Returns a vector where each index corresponds to a graph node index and the value is the
/// identifier of the connected component (the minimal node in that component).
///
/// ```
/// use binius_utils::graph::connected_components;
/// assert_eq!(connected_components::<&[&Vec<usize>]>(&[]), vec![]);
/// assert_eq!(connected_components(&[&vec![0], &vec![1]]), vec![0, 1]);
/// assert_eq!(connected_components(&[&vec![0, 1], &vec![1, 2], &vec![2, 3], &vec![4]]), vec![0, 0, 0, 0, 4]);
/// assert_eq!(
///     connected_components(&[&vec![0, 1, 2], &vec![5, 6, 7, 8], &vec![9], &vec![2, 3, 9]]),
///     vec![0, 0, 0, 0, 4, 5, 5, 5, 5, 0]
/// );
/// ```
pub fn connected_components<T: AsRef<[impl AsRef<[usize]>]>>(data: T) -> Vec<usize> {
	let data = data.as_ref();
	if data.is_empty() {
		return vec![];
	}

	// Determine the maximum node ID
	let max_id = *data
		.iter()
		.flat_map(|ids| ids.as_ref().iter())
		.max()
		.unwrap_or(&0);

	let n = max_id + 1;
	let mut uf = UnionFind::new(n);

	// Convert input sets into edges. For each chunk, we connect all nodes together.
	// To avoid adding a large number of redundant edges (fully connecting each subset),
	// we can simply connect each node in the subset to the minimum node in that subset.
	// This still ensures they all become part of one connected component.
	for ids in data {
		let ids = ids.as_ref();
		if ids.len() > 1 {
			let &base = ids.iter().min().unwrap();
			for &node in ids {
				if node != base {
					uf.union(base, node);
				}
			}
		}
	}

	// After union-find is complete, each node can be mapped to the minimum element
	// of its component.
	let mut result = vec![0; n];
	for (i, res) in result.iter_mut().enumerate() {
		let root = uf.find(i);
		// Use the stored minimum element for the root
		*res = uf.min_element[root];
	}

	result
}

struct UnionFind {
	parent: Vec<usize>,
	rank: Vec<usize>,
	min_element: Vec<usize>,
}

impl UnionFind {
	fn new(n: usize) -> Self {
		Self {
			parent: (0..n).collect(),
			rank: vec![0; n],
			min_element: (0..n).collect(),
		}
	}

	fn find(&mut self, x: usize) -> usize {
		if self.parent[x] != x {
			self.parent[x] = self.find(self.parent[x]);
		}
		self.parent[x]
	}

	fn union(&mut self, x: usize, y: usize) {
		let rx = self.find(x);
		let ry = self.find(y);

		if rx != ry {
			// Union by rank, but also maintain the minimal element in the representative
			let min_element = self.min_element[rx].min(self.min_element[ry]);
			match self.rank[rx].cmp(&self.rank[ry]) {
				Ordering::Less => {
					self.parent[rx] = ry;
					self.min_element[ry] = min_element;
				}
				Ordering::Greater => {
					self.parent[ry] = rx;
					self.min_element[rx] = min_element;
				}
				Ordering::Equal => {
					self.parent[ry] = rx;
					self.min_element[rx] = min_element;
					self.rank[rx] += 1;
				}
			}
		}
	}
}

/// Statistics about the fusion optimization pass
#[derive(Debug, Clone, Default)]
pub struct Stats {
	/// Number of AND constraints before fusion
	pub and_constraints_before: usize,
	/// Number of AND constraints after fusion
	pub and_constraints_after: usize,
	/// Number of producers identified
	pub producers_found: usize,
	/// Number of producers actually fused
	pub producers_fused: usize,
}

impl Stats {
	/// Get the reduction in AND constraints
	pub fn and_constraints_reduced(&self) -> usize {
		self.and_constraints_before
			.saturating_sub(self.and_constraints_after)
	}

	/// Get the reduction ratio for AND constraints (0.0 = no reduction, 1.0 = all removed)
	pub fn and_reduction_ratio(&self) -> f64 {
		if self.and_constraints_before == 0 {
			0.0
		} else {
			self.and_constraints_reduced() as f64 / self.and_constraints_before as f64
		}
	}

	/// Get total constraints before
	pub fn total_before(&self) -> usize {
		self.and_constraints_before
	}

	/// Get total constraints after
	pub fn total_after(&self) -> usize {
		self.and_constraints_after
	}

	/// Get the reduction ratio for total constraints
	pub fn total_reduction_ratio(&self) -> f64 {
		let before = self.total_before();
		if before == 0 {
			0.0
		} else {
			(before - self.total_after()) as f64 / before as f64
		}
	}
}

impl std::fmt::Display for Stats {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Calculate power-of-two sizes
		let and_before_po2 = self.and_constraints_before.next_power_of_two();
		let and_after_po2 = self.and_constraints_after.next_power_of_two();
		let and_before_log2 = and_before_po2.trailing_zeros();
		let and_after_log2 = and_after_po2.trailing_zeros();

		writeln!(f, "Gate Fusion Statistics:")?;
		writeln!(f, "  Producers found:  {}", self.producers_found)?;
		writeln!(f, "  Producers fused:  {}", self.producers_fused)?;
		writeln!(
			f,
			"  AND constraints:  {} -> {} (reduced by {} = {:.1}%)",
			self.and_constraints_before,
			self.and_constraints_after,
			self.and_constraints_reduced(),
			self.and_reduction_ratio() * 100.0
		)?;
		writeln!(
			f,
			"  AND po2 size:     {} -> {} (2^{} -> 2^{})",
			and_before_po2, and_after_po2, and_before_log2, and_after_log2
		)?;
		write!(
			f,
			"  Total:            {} -> {} (reduced by {} = {:.1}%)",
			self.total_before(),
			self.total_after(),
			self.total_before() - self.total_after(),
			self.total_reduction_ratio() * 100.0
		)
	}
}

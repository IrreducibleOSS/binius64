use std::{
	collections::HashMap,
	time::{Duration, Instant},
};

/// Simple timing collector that measures specific operations manually.
/// This avoids interfering with the existing tracing subscriber setup.
#[derive(Debug, Default)]
pub struct SimpleTimer {
	start_times: HashMap<String, Instant>,
	timings: HashMap<String, Duration>,
}

impl SimpleTimer {
	pub fn new() -> Self {
		Self::default()
	}

	/// Start timing an operation
	pub fn start(&mut self, name: &str) {
		self.start_times.insert(name.to_string(), Instant::now());
	}

	/// End timing an operation and record the duration
	pub fn end(&mut self, name: &str) {
		if let Some(start_time) = self.start_times.remove(name) {
			let duration = start_time.elapsed();
			self.timings.insert(name.to_string(), duration);
		}
	}

	/// Time a closure and return its result
	pub fn time<F, R>(&mut self, name: &str, f: F) -> R
	where
		F: FnOnce() -> R,
	{
		self.start(name);
		let result = f();
		self.end(name);
		result
	}

	/// Get the collected timings
	pub fn get_timings(&self) -> &HashMap<String, Duration> {
		&self.timings
	}

	/// Consume the timer and return the timings
	pub fn into_timings(self) -> HashMap<String, Duration> {
		self.timings
	}
}

/// Convenience function to manually time operations without interfering with tracing.
///
/// This approach manually times each major operation and returns the measurements
/// without disrupting the existing tracing subscriber setup.
///
/// The function passed to this should manually time its operations using the provided timer.
pub fn collect_timings_with<F, R>(f: F) -> Result<(R, HashMap<String, Duration>), anyhow::Error>
where
	F: FnOnce(&mut SimpleTimer) -> Result<R, anyhow::Error>,
{
	let mut timer = SimpleTimer::new();
	let result = f(&mut timer)?;
	Ok((result, timer.into_timings()))
}

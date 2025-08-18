//! Operand manipulation utilities for gate fusion.

use std::collections::HashMap;

use binius_core::{
	ValueIndex,
	constraint_system::{Operand, ShiftVariant, ShiftedValueIndex},
};

/// Canonicalized term for deduplication
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct CanonTerm {
	pub value_index: u32,
	pub shift_variant: u8, // 0=Sll, 1=Slr, 2=Sar
	pub amount: u8,
}

impl From<ShiftedValueIndex> for CanonTerm {
	fn from(svi: ShiftedValueIndex) -> Self {
		CanonTerm {
			value_index: svi.value_index.0,
			shift_variant: match svi.shift_variant {
				ShiftVariant::Sll => 0,
				ShiftVariant::Slr => 1,
				ShiftVariant::Sar => 2,
			},
			amount: svi.amount as u8,
		}
	}
}

/// Canonicalize an operand by sorting and XOR-canceling duplicate terms.
pub fn canonicalize_operand(operand: &Operand) -> Operand {
	// Build parity map for XOR cancellation
	let mut term_counts: HashMap<CanonTerm, usize> = HashMap::new();
	for term in operand.iter() {
		let canon_term = CanonTerm::from(*term);
		*term_counts.entry(canon_term).or_insert(0) += 1;
	}

	// Keep only terms that appear an odd number of times.
	let mut terms: Vec<_> = term_counts
		.into_iter()
		.filter(|(_, count)| count % 2 == 1)
		.map(|(term, _)| term)
		.collect();

	// Sort for deterministic output
	terms.sort();

	// Convert back to ShiftedValueIndex
	terms
		.into_iter()
		.map(|term| ShiftedValueIndex {
			value_index: ValueIndex(term.value_index),
			shift_variant: match term.shift_variant {
				0 => ShiftVariant::Sll,
				1 => ShiftVariant::Slr,
				2 => ShiftVariant::Sar,
				_ => unreachable!(),
			},
			amount: term.amount as usize,
		})
		.collect()
}

/// Count the number of unique terms after XOR cancellation.
pub fn count_unique_terms(terms: &[ShiftedValueIndex]) -> usize {
	let mut term_counts: HashMap<CanonTerm, usize> = HashMap::new();
	for term in terms {
		let canon_term = CanonTerm::from(*term);
		*term_counts.entry(canon_term).or_insert(0) += 1;
	}

	term_counts
		.values()
		.filter(|&&count| count % 2 == 1)
		.count()
}

#[cfg(test)]
pub(super) fn make_operand(terms: Vec<(u32, ShiftVariant, usize)>) -> Operand {
	terms
		.into_iter()
		.map(|(idx, variant, amount)| ShiftedValueIndex {
			value_index: ValueIndex(idx),
			shift_variant: variant,
			amount,
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_canonicalize_operand_basic() {
		// Test XOR cancellation: a ^ a = 0
		let op = make_operand(vec![
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
		]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 1);
		assert_eq!(canonicalized[0].value_index.0, 2);

		// Test sorting
		let op = make_operand(vec![
			(3, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
		]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 3);
		assert_eq!(canonicalized[0].value_index.0, 1);
		assert_eq!(canonicalized[1].value_index.0, 2);
		assert_eq!(canonicalized[2].value_index.0, 3);
	}

	#[test]
	fn test_canonicalize_empty_operand() {
		// Empty operand should remain empty
		let op = make_operand(vec![]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 0);
	}

	#[test]
	fn test_canonicalize_complete_cancellation() {
		// All terms cancel out (even number of each)
		let op = make_operand(vec![
			(1, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
		]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 0);
	}

	#[test]
	fn test_canonicalize_odd_occurrences() {
		// Terms appearing odd number of times survive
		let op = make_operand(vec![
			(1, ShiftVariant::Sll, 0), // appears 3 times -> survives
			(1, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0), // appears 5 times -> survives
			(2, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0), // appears 4 times -> cancels
			(3, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
		]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 2);
		assert_eq!(canonicalized[0].value_index.0, 1);
		assert_eq!(canonicalized[1].value_index.0, 2);
	}

	#[test]
	fn test_canonicalize_with_shifts() {
		// Different shift amounts/types are different terms
		let op = make_operand(vec![
			(1, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 5),  // Different amount
			(1, ShiftVariant::Slr, 0),  // Different shift type
			(1, ShiftVariant::Sar, 0),  // Different shift type
			(1, ShiftVariant::Sll, 5),  // Duplicate - cancels with above
			(1, ShiftVariant::Sll, 10), // Another different amount
		]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 4);

		// Check sorting order: by value_index, then shift_variant, then amount
		assert_eq!(canonicalized[0].value_index.0, 1);
		assert!(matches!(canonicalized[0].shift_variant, ShiftVariant::Sll));
		assert_eq!(canonicalized[0].amount, 0);

		assert_eq!(canonicalized[1].value_index.0, 1);
		assert!(matches!(canonicalized[1].shift_variant, ShiftVariant::Sll));
		assert_eq!(canonicalized[1].amount, 10);

		assert_eq!(canonicalized[2].value_index.0, 1);
		assert!(matches!(canonicalized[2].shift_variant, ShiftVariant::Slr));
		assert_eq!(canonicalized[2].amount, 0);

		assert_eq!(canonicalized[3].value_index.0, 1);
		assert!(matches!(canonicalized[3].shift_variant, ShiftVariant::Sar));
		assert_eq!(canonicalized[3].amount, 0);
	}

	#[test]
	fn test_canonicalize_complex_sorting() {
		// Test complex sorting with multiple values, shifts, and amounts
		let op = make_operand(vec![
			(3, ShiftVariant::Sar, 10),
			(1, ShiftVariant::Slr, 5),
			(2, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 10),
			(3, ShiftVariant::Sll, 5),
			(2, ShiftVariant::Slr, 0),
			(1, ShiftVariant::Sll, 5),
			(3, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sar, 0),
		]);

		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 9);

		// Verify sorting order
		let expected = [
			(1, ShiftVariant::Sll, 5),
			(1, ShiftVariant::Sll, 10),
			(1, ShiftVariant::Slr, 5),
			(2, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Slr, 0),
			(2, ShiftVariant::Sar, 0),
			(3, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 5),
			(3, ShiftVariant::Sar, 10),
		];

		for (i, (idx, variant, amount)) in expected.iter().enumerate() {
			assert_eq!(canonicalized[i].value_index.0, *idx);
			match variant {
				ShiftVariant::Sll => {
					assert!(matches!(canonicalized[i].shift_variant, ShiftVariant::Sll))
				}
				ShiftVariant::Slr => {
					assert!(matches!(canonicalized[i].shift_variant, ShiftVariant::Slr))
				}
				ShiftVariant::Sar => {
					assert!(matches!(canonicalized[i].shift_variant, ShiftVariant::Sar))
				}
			}
			assert_eq!(canonicalized[i].amount, *amount);
		}
	}

	#[test]
	fn test_canonicalize_large_operand() {
		// Test with many terms to ensure performance and correctness at scale
		let mut terms = Vec::new();

		// Add 100 unique terms
		for i in 0..100 {
			terms.push((i, ShiftVariant::Sll, 0));
		}

		// Add duplicates for some terms (these will cancel)
		for i in 0..20 {
			terms.push((i, ShiftVariant::Sll, 0));
		}

		// Add some terms three times (these will survive)
		for i in 10..15 {
			terms.push((i, ShiftVariant::Sll, 0));
			terms.push((i, ShiftVariant::Sll, 0));
		}

		let op = make_operand(terms);
		let canonicalized = canonicalize_operand(&op);

		// Terms 0-9: appear twice (cancel)
		// Terms 10-14: appear 4 times (cancel)
		// Terms 15-19: appear twice (cancel)
		// Terms 20-99: appear once (survive)
		assert_eq!(canonicalized.len(), 80);

		// First surviving term should be 20
		assert_eq!(canonicalized[0].value_index.0, 20);
		// Last surviving term should be 99
		assert_eq!(canonicalized[79].value_index.0, 99);
	}

	#[test]
	fn test_canonicalize_mixed_shift_amounts() {
		// Test all valid shift amounts (0-63) with cancellation
		let mut terms = Vec::new();

		// Add terms with various shift amounts
		for amount in 0..64 {
			terms.push((1, ShiftVariant::Sll, amount));
			if amount % 2 == 0 {
				// Even amounts: add twice (will cancel)
				terms.push((1, ShiftVariant::Sll, amount));
			}
		}

		let op = make_operand(terms);
		let canonicalized = canonicalize_operand(&op);

		// Only odd shift amounts should survive (32 terms)
		assert_eq!(canonicalized.len(), 32);

		// Verify they're sorted by amount and all odd
		for (i, term) in canonicalized.iter().enumerate() {
			assert_eq!(term.value_index.0, 1);
			assert!(matches!(term.shift_variant, ShiftVariant::Sll));
			assert_eq!(term.amount, i * 2 + 1);
		}
	}

	#[test]
	fn test_canonicalize_preserves_single_term() {
		// Single term should be preserved as-is
		let op = make_operand(vec![(42, ShiftVariant::Slr, 17)]);
		let canonicalized = canonicalize_operand(&op);
		assert_eq!(canonicalized.len(), 1);
		assert_eq!(canonicalized[0].value_index.0, 42);
		assert!(matches!(canonicalized[0].shift_variant, ShiftVariant::Slr));
		assert_eq!(canonicalized[0].amount, 17);
	}

	#[test]
	fn test_canonicalize_idempotent() {
		// Canonicalizing twice should give the same result
		let op = make_operand(vec![
			(3, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(4, ShiftVariant::Sll, 0),
		]);

		let canonicalized_once = canonicalize_operand(&op);
		let canonicalized_twice = canonicalize_operand(&canonicalized_once);

		assert_eq!(canonicalized_once.len(), canonicalized_twice.len());
		for (t1, t2) in canonicalized_once.iter().zip(canonicalized_twice.iter()) {
			assert_eq!(t1.value_index, t2.value_index);
			// Check shift variants match
			match (&t1.shift_variant, &t2.shift_variant) {
				(ShiftVariant::Sll, ShiftVariant::Sll) => {}
				(ShiftVariant::Slr, ShiftVariant::Slr) => {}
				(ShiftVariant::Sar, ShiftVariant::Sar) => {}
				_ => panic!("Shift variants don't match"),
			}
			assert_eq!(t1.amount, t2.amount);
		}
	}

	#[test]
	fn test_count_unique_terms() {
		// Test with no cancellation
		let terms = make_operand(vec![
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
		]);
		assert_eq!(count_unique_terms(&terms), 3);

		// Test with full cancellation
		let terms = make_operand(vec![(1, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0)]);
		assert_eq!(count_unique_terms(&terms), 0);

		// Test with partial cancellation
		let terms = make_operand(vec![
			(1, ShiftVariant::Sll, 0),
			(2, ShiftVariant::Sll, 0),
			(1, ShiftVariant::Sll, 0),
			(3, ShiftVariant::Sll, 0),
		]);
		assert_eq!(count_unique_terms(&terms), 2);
	}
}

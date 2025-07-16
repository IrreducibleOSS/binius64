use binius_field::Field;
use rayon::prelude::*;
use binius_math::{Error, FieldBuffer};

pub fn mle_to_field_buffer<F: Field>(mle: BigFieldMultilinear<F>) -> Result<FieldBuffer<F>, Error> {
    FieldBuffer::from_values(&mle.packed_evals)
}

pub fn field_buffer_to_mle<F: Field>(buf: FieldBuffer<F>) -> Result<BigFieldMultilinear<F>, Error> {
    let mut values = vec![];
    for i in 0..buf.len() {
        values.push(buf.get(i).unwrap());
    }
    Ok(BigFieldMultilinear {
        n_vars: buf.log_len(),
        packed_evals: values,
    })
}


#[derive(Debug, Clone, PartialEq)]
pub struct BigFieldMultilinear<F: Field> {
    pub n_vars: usize,
    pub packed_evals: Vec<F>,
}

impl<F: Field> BigFieldMultilinear<F> {
    pub fn fold_high_to_low(self: &mut Self, challenge: F) {
        let n = 1 << self.n_vars;
        let n_half = n >> 1;

        // fold high to low
        let (low, high) = self.packed_evals.split_at_mut(n_half);
        low.par_iter_mut()
            .zip(high.par_iter())
            .for_each(|(elm, high_elm)| {
                *elm += challenge * (*high_elm - *elm);
            });

        self.packed_evals.truncate(n_half);
        self.n_vars -= 1;
    }

    pub fn fold_low_to_high(self: &mut Self, challenge: F) {
        let n = 1 << self.n_vars;
        let n_half = n >> 1;

        for j in 0..n_half {
            let (low_idx, high_idx) = (2 * j, 2 * j + 1);
            let even = self.packed_evals[low_idx];
            let odd = self.packed_evals[high_idx];

            self.packed_evals[j] = even + challenge * (odd - even);
        }

        // remove last 1 << n-1 elements from each multilinear
        self.packed_evals.truncate(n_half);
        self.n_vars -= 1;
    }

    // Partially evaluate multilinear from low to high variables
    pub fn partial_eval_low_to_high(&self, challenges: &Vec<F>) -> Vec<F> {
        let mut result = self.clone();

        for challenge in challenges {
            result.fold_low_to_high(*challenge);
        }
        result.packed_evals
    }

    // Partially evaluate multilinear from high to low variables
    pub fn partial_eval_high_to_low(&self, challenges: &Vec<F>) -> Vec<F> {
        let mut result = self.clone();

        for challenge in challenges {
            result.fold_high_to_low(*challenge);
        }
        result.packed_evals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::BinaryField128b;

    #[test]
    fn test_fold() {
        type F = BinaryField128b;

        let log_n = 3;
        let n = 1 << log_n;

        let challenges = (0..log_n).map(|i| F::from(i as u128)).collect::<Vec<_>>();

        let mut mle = BigFieldMultilinear {
            n_vars: 3,
            packed_evals: (0..n).map(|i| F::from(i as u128)).collect(),
        };

        for i in 0..log_n {
            let prev_mle = mle.clone();

            mle.fold_high_to_low(challenges[i]);

            for j in 0..(1 << mle.n_vars) {
                assert_eq!(
                    mle.packed_evals[j],
                    (F::ONE - challenges[i]) * prev_mle.packed_evals[j]
                        + challenges[i] * (prev_mle.packed_evals[j + (1 << mle.n_vars)])
                );
            }
        }
    }

    #[test]
    fn mle_to_field_buffer_round_trip() {
        type F = BinaryField128b;

        let log_n = 5;

        let multilinear = BigFieldMultilinear {
            n_vars: log_n,
            packed_evals: (0..1 << log_n).map(|i| F::from(i as u128)).collect(),
        };

        let field_buffer = mle_to_field_buffer(multilinear.clone()).unwrap();

        let mle = field_buffer_to_mle(field_buffer).unwrap();

        assert_eq!(multilinear, mle);
    }
}

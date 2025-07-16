use binius_field::{AESTowerField128b, ExtensionField, Field, PackedField};
use binius_math::{FieldBuffer, multilinear::eq::tensor_prod_eq_ind};
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

use super::big_field_multilinear::BigFieldMultilinear;

pub fn eq_ind_mle<F: Field>(zerocheck_challenges: &[F]) -> FieldBuffer<F>
{
    let mut mle = FieldBuffer::<F>::zeros( zerocheck_challenges.len());
    let _ = mle.set(0, F::ONE);
    let _ = tensor_prod_eq_ind(0, &mut mle, &zerocheck_challenges);
    mle
}

pub fn eq_ind<F: Field, BF>(zerocheck_challenges: &[F]) -> BigFieldMultilinear<BF>
where
    BF: ExtensionField<F>,
{
    let mut mle = bytemuck::zeroed_vec(1 << zerocheck_challenges.len());

    let _span = tracing::debug_span!("eq ind").entered();

    mle[0] = BF::ONE;
    for (curr_log_len, challenge) in zerocheck_challenges.iter().enumerate() {
        let _span = tracing::debug_span!("compute eq_ind for curr log len").entered();

        let (mle_lower, mle_upper) = mle.split_at_mut(1 << curr_log_len);

        mle_lower
            .par_iter_mut()
            .zip(mle_upper.par_iter_mut())
            .for_each(|(low, up)| {
                let multiplied = *low * *challenge;
                *up = multiplied;
                *low -= multiplied;
            });
    }

    BigFieldMultilinear {
        n_vars: zerocheck_challenges.len(),
        packed_evals: mle,
    }
}

pub fn eval_eq<F: Field>(zerocheck_challenges: &[F], eval_point: &[F]) -> F {
    zerocheck_challenges
        .into_iter()
        .zip(eval_point.into_iter())
        .map(|(a, b)| F::ONE + a + b)
        .product()
}

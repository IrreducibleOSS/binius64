use binius_field::{ Field};
use binius_math::{FieldBuffer, multilinear::eq::tensor_prod_eq_ind};

pub fn eq_ind_mle<F: Field>(zerocheck_challenges: &[F]) -> FieldBuffer<F>
{
    let mut mle = FieldBuffer::<F>::zeros( zerocheck_challenges.len());
    let _ = mle.set(0, F::ONE);
    let _ = tensor_prod_eq_ind(0, &mut mle, zerocheck_challenges);
    mle
}

pub fn eval_eq<F: Field>(zerocheck_challenges: &[F], eval_point: &[F]) -> F {
    zerocheck_challenges
        .iter()
        .zip(eval_point)
        .map(|(a, b)| F::ONE + a + b)
        .product()
}

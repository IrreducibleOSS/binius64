use crate::{ring_switch::tensor_algebra::TensorAlgebra};
use binius_field::{ExtensionField, Field, PackedExtension};

// Compute inner product of two MLEs with eq evaluation_pointindicator
pub fn compute_mle_eq_sum<BigField: Field>(
    mle_values: &[BigField],
    eq_values: &[BigField],
) -> BigField {
    mle_values.iter().zip(eq_values).map(|(m, e)| *m * *e).sum()
}

pub fn large_field_mle_to_small_field_mle<
    SmallField: Field,
    BigField: Field + ExtensionField<SmallField>,
>(
    large_field_mle: &[BigField],
) -> Vec<SmallField> {
    large_field_mle
        .iter()
        .flat_map(|elm| ExtensionField::<SmallField>::iter_bases(elm))
        .collect()
}

pub fn lift_small_to_large_field<
    SmallField: Field,
    BigField: Field + ExtensionField<SmallField>,
>(
    small_field_elms: &[SmallField],
) -> Vec<BigField> {
    small_field_elms
        .iter()
        .map(|&elm| BigField::from(elm))
        .collect()
}

pub fn construct_s_hat_u<
    SmallField: Field,
    BigField: Field + ExtensionField<SmallField> + PackedExtension<SmallField>,
>(
    s_hat_v: Vec<BigField>,
) -> Vec<BigField> {
    <TensorAlgebra<SmallField, BigField>>::new(s_hat_v)
        .transpose()
        .elems
}

pub fn compute_expected_sumcheck_claim<
    SmallField: Field,
    BigField: Field + ExtensionField<SmallField> + PackedExtension<SmallField>,
>(
    s_hat_u: &[BigField],
    eq_r_double_prime: &[BigField],
) -> BigField {
    compute_mle_eq_sum(s_hat_u, eq_r_double_prime)
}

// given 4 lagrange basis coefficients for a univariate polynomial, compute
// lagrange basis polynomials and evaluate at x the resulting polynomial
pub fn evaluate_round_polynomial_at<BigField: Field>(
    x: BigField,
    round_msg: Vec<BigField>,
) -> BigField {
    let _span = tracing::debug_span!("evaluate round polynomial").entered();

    let (x_0, y_0) = (BigField::ZERO, round_msg[0]);
    let (x_1, y_1) = (BigField::ONE, round_msg[1]);
    let y_leading_coeff = round_msg[2];

    // lagrange basis polynomials
    let l_0 = (x - x_1) * (x_0 - x_1).invert().unwrap();
    let l_1 = (x - x_0) * (x_1 - x_0).invert().unwrap();
    let poly_with_leading_coeff = (x - x_0) * (x - x_1);

    l_0 * y_0 + l_1 * y_1 + poly_with_leading_coeff * y_leading_coeff
}

pub fn verify_sumcheck_round<BigField: Field>(
    round_sum_claim: BigField,
    expected_round_claim: BigField,
    round_msg: Vec<BigField>,
    sumcheck_challenge: BigField,
) -> BigField {
    let _span = tracing::debug_span!("verify round").entered();

    // first two coefficients of round message should match the sum claim
    // these are the evaluations of the univariate polynomial at 0, 1 and
    // (even/odd sum of boolean hypercube evals)
    assert_eq!(round_msg[0] + round_msg[1], round_sum_claim);

    // When the verifier receives the round message, it represents the coefficients
    // of the current univariate, partially specialized composition polynomial. By
    // evaluating this polynomial at the challenge, we determine what the honest
    // prover will claim as the sum for the next round. This is because the when
    // we fold the challenge into the multilinear, it is the same as partially
    // specializing the current composition polynomial w/ the challenge point.
    assert_eq!(expected_round_claim, round_sum_claim);

    // compute expected next round claim
    evaluate_round_polynomial_at(sumcheck_challenge, round_msg)
}

pub fn fri_fold_arities_to_is_commit_round(fri_fold_arities: &[usize], num_basefold_rounds: usize)->Vec<bool>{
    let mut result = vec![false; num_basefold_rounds];
    let mut result_idx = 0;
    for arity in fri_fold_arities{
        result_idx += arity;
        result[result_idx-1] = true;
    }

    result
}
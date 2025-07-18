use binius_field::{ExtensionField, Field, PackedExtension};

pub const KAPPA: usize = 7;

pub fn compute_mle_eq_sum<BigField: Field>(
	mle_values: &[BigField],
	eq_values: &[BigField],
) -> BigField {
	mle_values.iter().zip(eq_values).map(|(m, e)| *m * *e).sum()
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
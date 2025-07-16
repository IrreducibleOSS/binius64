use binius_field::Field;

pub trait SumcheckProver<F: Field> {
	fn fold(&mut self, challenge: F);

	fn round_message(&self) -> Vec<F>;

	fn final_eval_claims(self) -> Vec<F>;
}

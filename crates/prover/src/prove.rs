use super::error::Error;
use binius_field::{BinaryField, ExtensionField};
use binius_frontend::constraint_system::{ConstraintSystem, ValueVec};
use binius_transcript::{ProverTranscript, fiat_shamir::Challenger};
use binius_verifier::{Params, fields::B64};

pub fn prove<F, Challenger_>(
	params: &Params,
	cs: &ConstraintSystem,
	witness: ValueVec,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: BinaryField + ExtensionField<B64>,
	Challenger_: Challenger,
{
	let _ = (params, cs, witness, transcript);
	Ok(())
}

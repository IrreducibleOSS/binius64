use binius_field::{BinaryField, ExtensionField};
use binius_transcript::{ProverTranscript, fiat_shamir::Challenger};
use binius_verifier::{Params, fields::B64};
use monbijou::{constraint_system::ConstraintSystem, word::Word};
use monbijou::constraint_system::ValueVec;
use super::error::Error;

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
	Ok(())
}

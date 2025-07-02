use binius_field::{BinaryField, ExtensionField};
use binius_frontend::constraint_system::{ConstraintSystem, ValueVec};
use binius_transcript::{ProverTranscript, fiat_shamir::Challenger};
use binius_verifier::{Params, fields::B64};

use super::error::Error;

pub fn prove<F, Challenger_>(
	_params: &Params,
	_cs: &ConstraintSystem,
	_witness: ValueVec,
	_transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: BinaryField + ExtensionField<B64>,
	Challenger_: Challenger,
{
	Ok(())
}

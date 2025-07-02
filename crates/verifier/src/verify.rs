use binius_field::{BinaryField, ExtensionField};
use binius_frontend::{constraint_system::ConstraintSystem, word::Word};
use binius_transcript::{VerifierTranscript, fiat_shamir::Challenger};

use super::{error::Error, fields::B64};

#[derive(Debug, Clone)]
pub struct Params {}

pub fn verify<F, Challenger_>(
	_params: &Params,
	_cs: &ConstraintSystem,
	_inout: &[Word],
	_transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: BinaryField + ExtensionField<B64>,
	Challenger_: Challenger,
{
	let _ = (params, cs, inout, transcript);
	Ok(())
}

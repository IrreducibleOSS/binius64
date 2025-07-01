use binius_field::{BinaryField, ExtensionField};
use binius_transcript::{VerifierTranscript, fiat_shamir::Challenger};
use monbijou::{constraint_system::ConstraintSystem, word::Word};

use super::{error::Error, fields::B64};

#[derive(Debug, Clone)]
pub struct Params {}

pub fn verify<F, Challenger_>(
	params: &Params,
	cs: &ConstraintSystem,
	inout: &[Word],
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: BinaryField + ExtensionField<B64>,
	Challenger_: Challenger,
{
	Ok(())
}

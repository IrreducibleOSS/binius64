use binius_field::{AESTowerField8b, Field};

#[derive(Clone)]
pub struct SubfieldIsomorphismLookup<F>(Vec<F>);

impl<F: Field> SubfieldIsomorphismLookup<F> {
	pub fn new<FIntermediate>() -> Self
	where
		F: From<FIntermediate>,
		FIntermediate: Field + From<AESTowerField8b>,
	{
		let mut lookup_table = vec![];
		for i in 0..=255 {
			lookup_table.push(FIntermediate::from(AESTowerField8b::from(i)).into());
		}

		Self(lookup_table)
	}

	pub fn lookup_8b_value(&self, value: AESTowerField8b) -> F {
		self.0[Into::<u8>::into(value) as usize]
	}
}

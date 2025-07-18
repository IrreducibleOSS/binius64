use binius_field::Field;
use binius_math::FieldBuffer;

use crate::error::Error;

#[derive(Debug)]
pub struct BigFieldMultilinear<F: Field> {
    pub n_vars: usize,
    pub packed_evals: Vec<F>,
}

pub fn mle_to_field_buffer<F: Field>(mle: &BigFieldMultilinear<F>) -> Result<FieldBuffer<F>, Error> {
    Ok(FieldBuffer::from_values(&mle.packed_evals).unwrap())
}

pub fn field_buffer_to_mle<F: Field>(buf: FieldBuffer<F>) -> Result<BigFieldMultilinear<F>, Error> {
    let mut values = vec![];
    for i in 0..buf.len() {
        values.push(buf.get(i).unwrap());
    }
    Ok(BigFieldMultilinear {
        n_vars: buf.log_len(),
        packed_evals: values,
    })
}
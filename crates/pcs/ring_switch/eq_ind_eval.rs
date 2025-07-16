use std::iter;

use binius_field::{BinaryField1b, BinaryField128b, Field};

use super::tensor_algebra::TensorAlgebra;

type BF = BinaryField128b;

pub fn eval_rs_eq(z_vals: &[BF], query: &[BF], expanded_row_batch_query: &[BF]) -> BF {
    let tensor_eval = iter::zip(z_vals, query).fold(
        <TensorAlgebra<BinaryField1b, BF>>::from_vertical(BF::ONE),
        |eval, (&vert_i, &hztl_i)| {
            // This formula is specific to characteristic 2 fields
            // Here we know that $h v + (1 - h) (1 - v) = 1 + h + v$.
            let vert_scaled = eval.clone().scale_vertical(vert_i);

            // println!("vert scaled: {:?}", vert_scaled);
            let hztl_scaled = eval.clone().scale_horizontal(hztl_i);
            // println!("hztl scaled: {:?}", hztl_scaled);

            eval + &vert_scaled + &hztl_scaled
        },
    );

    tensor_eval.fold_vertical(expanded_row_batch_query)
}

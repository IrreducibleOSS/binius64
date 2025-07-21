use binius_field::{
    AESTowerField8b, BinaryField128bPolyval, PackedBinaryField128x1b, PackedField, Random, AESTowerField128b,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itertools::Itertools;
use binius_prover::protocols::sumcheck::{
	and_reduction::{
		fold_lookups::precompute_fold_lookup,
		one_bit_multivariate::OneBitMultivariate,
		sumcheck_prover::{AndReductionMultilinearSumcheckProver, FoldDirection},
		sumcheck_round_message::univariate_round_message,
		univariate::{
			delta::delta_poly,
			ntt_lookup::{precompute_lookup, NTTLookup, ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
			subfield_isomorphism::SubfieldIsomorphismLookup,
			univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly},
		},
	}, common::SumcheckProver,
};
use rand::{SeedableRng, rngs::StdRng};
use binius_math::{multilinear::eq::eq_ind_partial_eval, FieldBuffer};
use binius_prover::protocols::sumcheck::and_reduction::zerocheck_prover::OblongZerocheckProver;
use binius_prover::protocols::sumcheck::and_reduction::sumcheck_prover::multilinear_sumcheck;


fn random_mlv(log_num_rows: usize, num_polys: usize) -> Vec<OneBitMultivariate> {
    let mut rng = StdRng::from_seed([0; 32]);

    let mut vec = Vec::with_capacity(num_polys);
    for _ in 0..num_polys {
        vec.push(
            OneBitMultivariate {
                log_num_rows,
                packed_evals: (0..1 << log_num_rows).map(|_| PackedBinaryField128x1b::random(&mut rng)).collect(),
            }
        );
    }

    vec
}

fn setup() -> (usize, Vec<BinaryField128bPolyval>, [AESTowerField8b; 3], OneBitMultivariate, OneBitMultivariate, OneBitMultivariate, NTTLookup, SubfieldIsomorphismLookup<BinaryField128bPolyval>) {
    let log_num_rows = 24;
    let mut rng = StdRng::from_seed([0; 32]);

    let big_field_zerocheck_challenges =
        vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

    let small_field_zerocheck_challenges = [
        AESTowerField8b::new(2),
        AESTowerField8b::new(4),
        AESTowerField8b::new(16),
    ];

    let random_mlvs = random_mlv(log_num_rows, 3);
    let (first_mlv, second_mlv, third_mlv) = (random_mlvs[0].clone(), random_mlvs[1].clone(), random_mlvs[2].clone());

    let onto_domain: Vec<_> = (64..128).map(AESTowerField8b::new).collect();
    let iso_lookup: SubfieldIsomorphismLookup<BinaryField128bPolyval> = SubfieldIsomorphismLookup::new::<AESTowerField128b>();
    let ntt_lookup = precompute_lookup(&onto_domain);

    (log_num_rows, big_field_zerocheck_challenges, small_field_zerocheck_challenges, first_mlv, second_mlv, third_mlv, ntt_lookup, iso_lookup)
}


fn bench(c: &mut Criterion) {
    let log_num_rows = 24;
    let mut rng = StdRng::from_seed([0; 32]);
    let big_field_zerocheck_challenges =
        vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];
    let small_field_zerocheck_challenges = [
        AESTowerField8b::new(2),
        AESTowerField8b::new(4),
        AESTowerField8b::new(16),
    ];
    let first_mlv = OneBitMultivariate {
        log_num_rows,
        packed_evals: (0..1 << log_num_rows)
            .map(|_| PackedBinaryField128x1b::random(&mut rng))
            .collect(),
    };

    let second_mlv = OneBitMultivariate {
        log_num_rows,
        packed_evals: (0..1 << log_num_rows)
            .map(|_| PackedBinaryField128x1b::random(&mut rng))
            .collect(),
    };

    let third_mlv = OneBitMultivariate {
        log_num_rows,
        packed_evals: (0..1 << log_num_rows)
            .map(|i| first_mlv.packed_evals[i] * second_mlv.packed_evals[i])
            .collect(),
    };

    let onto_domain: Vec<_> = (64..128).map(AESTowerField8b::new).collect();

    let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

    let ntt_lookup = precompute_lookup(&onto_domain);

    let mut group = c.benchmark_group("evaluate");
    group.throughput(Throughput::Elements(1 << log_num_rows));
    group.bench_function("univariate_round 2^24", |bench| {
        bench.iter(|| {
            let eq_ind_mle: FieldBuffer<BinaryField128bPolyval> = eq_ind_partial_eval(&big_field_zerocheck_challenges[1..]);

            let urm = univariate_round_message(
                &first_mlv,
                &second_mlv,
                &third_mlv,
                &eq_ind_mle,
                &ntt_lookup,
                &small_field_zerocheck_challenges,
                big_field_zerocheck_challenges[0],
                &iso_lookup,
            );

            let fold_lookup = precompute_fold_lookup(BinaryField128bPolyval::new(123), &iso_lookup);

            (
                urm,
                first_mlv.fold(&fold_lookup),
                second_mlv.fold(&fold_lookup),
                third_mlv.fold(&fold_lookup),
            )
        });
    });

    group.bench_function("full zerocheck 2^24", |bench| {
        bench.iter(|| {
            let eq_ind_only_big: FieldBuffer<BinaryField128bPolyval> = eq_ind_partial_eval(&big_field_zerocheck_challenges[1..]);

            let urm = univariate_round_message(
                &first_mlv,
                &second_mlv,
                &third_mlv,
                &eq_ind_only_big,
                &ntt_lookup,
                &small_field_zerocheck_challenges,
                big_field_zerocheck_challenges[0],
                &iso_lookup,
            );

            let first_sumcheck_challenge = BinaryField128bPolyval::new(123);

            let fold_lookup = precompute_fold_lookup(first_sumcheck_challenge, &iso_lookup);

            let eq_ind_div_by = delta_poly(big_field_zerocheck_challenges[0], 6, &iso_lookup)
                .evaluate_at_challenge(first_sumcheck_challenge);

            let next_round_claim = urm.evaluate_at_challenge(first_sumcheck_challenge)
                * eq_ind_div_by.invert_or_zero();

            let upcasted_small_field_challenges: Vec<_> = small_field_zerocheck_challenges
                .into_iter()
                .map(|i| iso_lookup.lookup_8b_value(i))
                .collect();

            let polyval_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
                .iter()
                .chain(big_field_zerocheck_challenges[1..].iter())
                .copied()
                .collect();

            let proving_polys = vec![
                first_mlv.fold(&fold_lookup),
                second_mlv.fold(&fold_lookup),
                third_mlv.fold(&fold_lookup),
            ];

            let prover = AndReductionMultilinearSumcheckProver::new(
                proving_polys,
                polyval_zerocheck_challenges,
                next_round_claim,
                24 - SKIPPED_VARS,
                FoldDirection::LowToHigh,
            );

            multilinear_sumcheck(prover);
        });
    });
}

criterion_main!(univariate_round);
criterion_group!(univariate_round, bench);
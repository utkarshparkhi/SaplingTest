use crate::group_hash;
use crate::note::NoteValue;
use crate::pedersen_crh;
use crate::pedersen_crh::Window;
use ark_crypto_primitives::commitment::pedersen;
use ark_crypto_primitives::commitment::pedersen::Window as pdWindow;
use ark_crypto_primitives::commitment::CommitmentScheme;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381::Fq;
use ark_ed_on_bls12_381::Fr;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{thread_rng, Rng};
use ark_std::Zero;
const X: [u8; 32] = [
    98, 100, 227, 168, 52, 59, 20, 165, 218, 236, 177, 255, 6, 157, 145, 240, 44, 236, 59, 243,
    161, 154, 64, 161, 140, 42, 199, 158, 138, 159, 235, 38,
];
const Y: [u8; 32] = [
    231, 232, 93, 224, 247, 249, 122, 70, 210, 73, 161, 245, 234, 81, 223, 80, 204, 72, 73, 15,
    132, 1, 201, 222, 122, 42, 223, 24, 7, 209, 182, 84,
];
#[derive(Clone)]
pub struct Commitment {
    pub params: pedersen::Parameters<ark_ed_on_bls12_381::EdwardsProjective>,
}
impl Commitment {
    pub fn setup() -> Self {
        let mut rng = thread_rng();
        let mut params =
            pedersen::Commitment::<ark_ed_on_bls12_381::EdwardsProjective, Window>::setup(&mut rng)
                .unwrap();
        let randomness_generator = EdwardsAffine::new_unchecked(
            Fq::from_le_bytes_mod_order(&X),
            Fq::from_le_bytes_mod_order(&Y),
        );
        params.randomness_generator = vec![randomness_generator.into_group()];
        let v: Vec<EdwardsProjective> = pedersen_crh::get_pedersen_generators();
        let mut generators: Vec<Vec<EdwardsProjective>> = vec![];
        for g in v.iter() {
            let mut nv: Vec<EdwardsProjective> = vec![];
            let mut base = EdwardsProjective::zero();
            for _ in 0..Window::NUM_WINDOWS {
                nv.push(base);
                base += g;
            }
            generators.push(nv)
        }
        params.generators = generators;
        Self { params }
    }
}
#[derive(Clone, Debug)]
pub struct ValueCommitTrapdoor(pub ark_ed_on_bls12_381::Fr);
impl ValueCommitTrapdoor {
    pub fn random() -> Self {
        let mut rng = thread_rng();
        let mut a: [u8; 64] = [0; 64];
        rng.fill(&mut a);
        Self(Fr::from_le_bytes_mod_order(&a))
    }
}

pub fn homomorphic_pedersen_commitment(val: NoteValue, rcv: &ValueCommitTrapdoor) -> EdwardsAffine {
    let v_sap = group_hash::calc_v_sapling();
    let r_sap = group_hash::calc_r_sapling();
    let v = Fr::from(val.0);
    (v_sap.mul_bigint(v.0) + r_sap.mul_bigint(rcv.0 .0)).into_affine()
}
pub fn mixing_pedersen_hash(note_comm: EdwardsAffine, x: Fr) -> EdwardsAffine {
    println!("pos fr{:?}", x.0.to_bytes_le());
    let j_sap = group_hash::calc_pedersen_hash();
    (note_comm + j_sap.mul_bigint(x.0)).into_affine()
}
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::pedersen_crh::Window;
    use ark_crypto_primitives::commitment::pedersen::{Commitment as pdCommit, Randomness};
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_ec::AffineRepr;
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381::Fr;
    use ark_ff::Field;
    use ark_ff::PrimeField;
    use ark_std::One;
    #[test]
    pub fn comm_test() {
        let c = Commitment::setup();
        let r = Randomness::<ark_ed_on_bls12_381::EdwardsProjective>(Fr::one());

        let cm = pdCommit::<ark_ed_on_bls12_381::EdwardsProjective, Window>::commit(
            &c.params, b"Helloa", &r,
        );
        println!("com {:?}", cm.unwrap().is_on_curve());

        let y = [
            Y[0].to_le_bytes(),
            Y[1].to_le_bytes(),
            Y[2].to_le_bytes(),
            Y[3].to_le_bytes(),
        ]
        .concat();

        println!("{:?}", y);
    }
    #[test]
    pub fn test_homo() {
        let rcm = ValueCommitTrapdoor::random();
        let cm_1 = homomorphic_pedersen_commitment(NoteValue(1), &rcm);
        let cm_2 = homomorphic_pedersen_commitment(NoteValue(2), &rcm);
        let cm_3 = homomorphic_pedersen_commitment(
            NoteValue(3),
            &ValueCommitTrapdoor(rcm.clone().0 * Fr::from(2)),
        );
        assert_eq!((cm_1 + cm_2), cm_3);
    }
}

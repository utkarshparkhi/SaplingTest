use crate::pedersen_crh;
use crate::pedersen_crh::Window;
use ark_crypto_primitives::commitment::{pedersen, CommitmentScheme};
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::EdwardsAffine;
use ark_ed_on_bls12_381::Fq;
use ark_ff::PrimeField;
const X: [u8; 32] = [
    98, 100, 227, 168, 52, 59, 20, 165, 218, 236, 177, 255, 6, 157, 145, 240, 44, 236, 59, 243,
    161, 154, 64, 161, 140, 42, 199, 158, 138, 159, 235, 38,
];
const Y: [u8; 32] = [
    231, 232, 93, 224, 247, 249, 122, 70, 210, 73, 161, 245, 234, 81, 223, 80, 204, 72, 73, 15,
    132, 1, 201, 222, 122, 42, 223, 24, 7, 209, 182, 84,
];

use ark_std::rand::thread_rng;
pub struct Commitment {
    params: pedersen::Parameters<ark_ed_on_bls12_381::EdwardsProjective>,
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
        params.generators = pedersen_crh::get_pedersen_generators();
        Self { params }
    }
}
#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    pub fn comm_test() {
        let y = [
            Y[0].to_le_bytes(),
            Y[1].to_le_bytes(),
            Y[2].to_le_bytes(),
            Y[3].to_le_bytes(),
        ]
        .concat();
        println!("{:?}", y);
    }
}

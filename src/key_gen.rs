use crate::signing_key::SigningKey;
use crate::PRF::prf_expand::PrfExpand;
use ark_ec::Group;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ff::{BigInt, BigInteger};

pub struct SpendAuthorizationKey(pub EdwardsProjective);

impl From<[u8; 64]> for SpendAuthorizationKey {
    fn from(value: [u8; 64]) -> Self {
        let bits: Vec<bool> = value
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();

        let big_int: BigInt<8> = BigInt::from_bits_le(&bits);
        Self(EdwardsProjective::generator().mul_bigint(big_int))
    }
}

impl SpendAuthorizationKey {
    pub fn new(sk: SigningKey) -> Self {
        let prf = PrfExpand::calc_ask(sk);
        SpendAuthorizationKey::from(prf)
    }
}

pub struct ProofAuthorizationKey(pub EdwardsProjective);
impl ProofAuthorizationKey {
    pub fn new(sk: SigningKey) -> Self {
        let prf = PrfExpand::calc_nsk(sk);
        ProofAuthorizationKey(SpendAuthorizationKey::from(prf).0)
    }
}
#[cfg(test)]
mod tests {
    use ark_std::rand;

    use crate::signing_key::SigningKey;

    use super::SpendAuthorizationKey;
    #[test]
    pub fn test_rand_sk() {
        let mut rng = rand::thread_rng();
        let sk: SigningKey = &[
            0x18, 0xe2, 0x8d, 0xea, 0x5c, 0x11, 0x81, 0x7a, 0xee, 0xb2, 0x1a, 0x19, 0x98, 0x1d,
            0x28, 0x36, 0x8e, 0xc4, 0x38, 0xaf, 0xc2, 0x5a, 0x8d, 0xb9, 0x4e, 0xbe, 0x08, 0xd7,
            0xa0, 0x28, 0x8e, 0x09,
        ];
        let ask = SpendAuthorizationKey::new(sk);
        println!("{:?}", ask.0.into())
    }
}

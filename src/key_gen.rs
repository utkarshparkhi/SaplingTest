use crate::group_hash;
use crate::signing_key::SigningKey;
use crate::PRF::prf_expand::{Crh, PrfExpand};
use ark_crypto_primitives::signature::schnorr::{self, Parameters};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use ark_ff::{BigInteger, BigInteger256, PrimeField};
use ark_std::ops::Mul;
use blake2::Blake2b512;
use rand::thread_rng;
pub type SecretKey = schnorr::SecretKey<EdwardsProjective>;

pub type OutgoingViewKey = [u8; 32];
#[derive(Debug)]
pub struct PublicKey(schnorr::PublicKey<EdwardsProjective>);
pub struct Keychain<'a> {
    pub sk: SigningKey<'a>,
    pub ask: SecretKey,
    pub nsk: SecretKey,
    pub ovk: OutgoingViewKey,
    pub ivk: SecretKey,
    pub nk: PublicKey,
    pub parameters: schnorr::Parameters<EdwardsProjective, Blake2b512>,
    pub ak: PublicKey,
}
impl PublicKey {
    pub fn to_repr_j(&self) -> [u8; 32] {
        let mut rep: BigInteger256 = self.0.y.into();
        let rep1: BigInteger256 = BigInteger256::from(self.0.x);
        let mut rep1: BigInteger256 = (rep1.is_odd() as u8).into();
        rep1.muln(255);
        rep.add_with_carry(&rep1);
        let mut ret = [0u8; 32];
        ret.copy_from_slice(&rep.to_bytes_le()[..32]);
        ret
    }
}
impl<'a> From<SigningKey<'a>> for Keychain<'a> {
    fn from(sk: SigningKey<'a>) -> Self {
        let ask: SecretKey =
            schnorr::SecretKey(Fr::from_le_bytes_mod_order(&PrfExpand::calc_ask(sk)));
        let nsk = schnorr::SecretKey(Fr::from_le_bytes_mod_order(&PrfExpand::calc_nsk(sk)));
        let mut rng = thread_rng();
        let mut parameters: Parameters<EdwardsProjective, Blake2b512> =
            schnorr::Schnorr::<EdwardsProjective, Blake2b512>::setup(&mut rng).unwrap();
        parameters.generator = group_hash::group_hash_spend_auth();
        let ak: PublicKey = PublicKey(parameters.generator.mul(ask.0).into());
        let nk: PublicKey = PublicKey(group_hash::group_hash_h_sapling().mul(nsk.0).into());
        let mut ovk: [u8; 32] = [0; 32];
        ovk.copy_from_slice(&PrfExpand::calc_ovk(sk)[..32]);
        let ivk = schnorr::SecretKey(Crh::calc(&ak.to_repr_j(), &nk.to_repr_j()));
        println!("ak_repr : {:?}", ak.to_repr_j());
        println!("nk_repr : {:?}", nk.to_repr_j());

        Keychain {
            sk,
            ask,
            nsk,
            ovk,
            ivk,
            nk,
            parameters,
            ak,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::signing_key::SigningKey;
    use ark_ff::{BigInteger, PrimeField};

    use super::Keychain;
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];
    const EASK: [u8; 32] = [
        14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210, 17,
        50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
    ];
    const EIVK: [u8; 32] = [
        162, 159, 59, 178, 16, 189, 223, 176, 99, 86, 247, 67, 215, 146, 154, 112, 191, 254, 50,
        78, 104, 214, 15, 66, 181, 235, 78, 158, 91, 167, 240, 2,
    ];
    #[test]
    pub fn test_kc_from_sk() {
        let sk: SigningKey = SK;
        let kc = Keychain::from(sk);
        let eask = EASK;
        println!("ask: {:?}", kc.ask);
        println!("nsk: {:?}", kc.nsk);
        println!("ovk: {:?}", kc.ovk);
        println!("ak: {:?}", kc.ak);
        println!("nk: {:?}", kc.nk);
        println!("ivk: {:?}", kc.ivk.0.into_bigint().to_bytes_le());
        println!("params: {:?}", kc.parameters);
        assert_eq!(kc.ask.0.into_bigint().to_bytes_le(), eask);

        assert_eq!(EIVK.to_vec(), kc.ivk.0.into_bigint().to_bytes_le());
    }
}

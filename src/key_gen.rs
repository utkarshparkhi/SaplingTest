use crate::group_hash;
use crate::signing_key::SigningKey;
use crate::PRF::prf_expand::PrfExpand;
use ark_crypto_primitives::signature::schnorr::{self, Parameters};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use ark_ff::PrimeField;
use ark_std::ops::Mul;
use blake2::Blake2b512;
use rand::thread_rng;
#[derive(Debug)]
pub struct SpendAuthorizationKey(pub Fr);

impl From<[u8; 64]> for SpendAuthorizationKey {
    fn from(value: [u8; 64]) -> Self {
        SpendAuthorizationKey(Fr::from_le_bytes_mod_order(&value))
    }
}

impl SpendAuthorizationKey {
    pub fn new(sk: SigningKey) -> Self {
        let prf = PrfExpand::calc_ask(sk);
        SpendAuthorizationKey::from(prf)
    }
}
#[derive(Debug)]
pub struct ProofAuthorizationKey(pub Fr);
impl ProofAuthorizationKey {
    pub fn new(sk: SigningKey) -> Self {
        let prf = PrfExpand::calc_nsk(sk);
        ProofAuthorizationKey(SpendAuthorizationKey::from(prf).0)
    }
}
pub type OutgoingViewKey = [u8; 32];
pub type AuthorizingKey = schnorr::PublicKey<EdwardsProjective>;
pub struct Keychain<'a> {
    pub sk: SigningKey<'a>,
    pub ask: SpendAuthorizationKey,
    pub nsk: ProofAuthorizationKey,
    pub ovk: OutgoingViewKey,
    pub parameters: schnorr::Parameters<EdwardsProjective, Blake2b512>,
    pub ak: AuthorizingKey,
}
impl<'a> From<SigningKey<'a>> for Keychain<'a> {
    fn from(sk: SigningKey<'a>) -> Self {
        let ask = SpendAuthorizationKey::new(sk);

        let mut rng = thread_rng();
        let mut params: Parameters<EdwardsProjective, Blake2b512> =
            schnorr::Schnorr::<EdwardsProjective, Blake2b512>::setup(&mut rng).unwrap();
        params.generator = group_hash::group_hash_spend_auth();
        let ak = params.generator.mul(ask.0).into();

        let mut ovk: [u8; 32] = [0; 32];
        ovk.copy_from_slice(&PrfExpand::calc_ovk(sk)[..32]);
        Keychain {
            sk,
            ask,
            nsk: ProofAuthorizationKey::new(sk),
            ovk,
            parameters: params,
            ak,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::signing_key::SigningKey;
    use ark_ff::{BigInteger, PrimeField};

    use super::{Keychain, SpendAuthorizationKey};
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];
    const EASK: [u8; 32] = [
        14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210, 17,
        50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
    ];

    #[test]
    pub fn test_from_prf() {
        let prf: [u8; 64] = [
            235, 147, 48, 48, 145, 176, 19, 191, 157, 67, 99, 224, 147, 110, 233, 123, 161, 28,
            130, 200, 111, 155, 179, 72, 124, 120, 211, 74, 195, 195, 52, 93, 210, 151, 20, 125,
            87, 188, 32, 181, 117, 245, 141, 227, 249, 95, 139, 11, 184, 132, 143, 136, 188, 145,
            198, 129, 154, 165, 83, 196, 155, 42, 106, 26,
        ];
        let ask = SpendAuthorizationKey::from(prf);

        let eask = EASK;
        assert_eq!(ask.0.into_bigint().to_bytes_le(), eask)
    }
    #[test]
    pub fn test_from_sk() {
        let sk: SigningKey = SK;
        let ask = SpendAuthorizationKey::new(sk);

        let eask = EASK;
        assert_eq!(ask.0.into_bigint().to_bytes_le(), eask)
    }
    #[test]
    pub fn test_kc_from_sk() {
        let sk: SigningKey = SK;
        let kc = Keychain::from(sk);
        let eask = EASK;
        println!("ask: {:?}", kc.ask);
        println!("nsk: {:?}", kc.nsk);
        println!("ovk: {:?}", kc.ovk);
        println!("ak: {:?}", kc.ak);
        println!("params: {:?}", kc.parameters);
        assert_eq!(kc.ask.0.into_bigint().to_bytes_le(), eask)
    }
}

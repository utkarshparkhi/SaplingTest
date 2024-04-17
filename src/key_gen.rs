use crate::signing_key::SigningKey;
use crate::PRF::prf_expand::PrfExpand;
use ark_crypto_primitives::signature::schnorr::{self, Schnorr};
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use ark_ff::PrimeField;
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

pub struct ProofAuthorizationKey(pub Fr);
impl ProofAuthorizationKey {
    pub fn new(sk: SigningKey) -> Self {
        let prf = PrfExpand::calc_nsk(sk);
        ProofAuthorizationKey(SpendAuthorizationKey::from(prf).0)
    }
}
pub type OutgoingViewKey = [u8;32];
pub type AuthorizingKey = schnorr::PublicKey<EdwardsProjective>;
pub struct Keychain<'a>{
    sk: SigningKey<'a>,
    ask: SpendAuthorizationKey,
    nsk: ProofAuthorizationKey,
    ovk: OutgoingViewKey,
}

impl<'a> From<SigningKey<'a>> for Keychain<'a> {
    fn from(sk: SigningKey<'a>) -> Self {
    Keychain {
        sk,
            ask: SpendAuthorizationKey::new(sk),
            nsk: ProofAuthorizationKey::new(sk),
            ovk: [0;32],
        }
    }
}
#[cfg(test)]
mod tests{
    use crate::signing_key::SigningKey;
    use ark_ff::{BigInteger, PrimeField};

    use super::SpendAuthorizationKey;
    #[test]
    pub fn test_from_prf() {
        let prf: [u8; 64] = [
            235, 147, 48, 48, 145, 176, 19, 191, 157, 67, 99, 224, 147, 110, 233, 123, 161, 28,
            130, 200, 111, 155, 179, 72, 124, 120, 211, 74, 195, 195, 52, 93, 210, 151, 20, 125,
            87, 188, 32, 181, 117, 245, 141, 227, 249, 95, 139, 11, 184, 132, 143, 136, 188, 145,
            198, 129, 154, 165, 83, 196, 155, 42, 106, 26,
        ];
        let ask = SpendAuthorizationKey::from(prf);

        let eask = [
            14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210,
            17, 50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
        ];
        assert_eq!(ask.0.into_bigint().to_bytes_le(), eask)
    }
    #[test]
    pub fn test_from_sk() {
        let sk: SigningKey = &[
            24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56,
            175, 194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
        ];
        let ask = SpendAuthorizationKey::new(sk);

        let eask = [
            14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210,
            17, 50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
        ];
        assert_eq!(ask.0.into_bigint().to_bytes_le(), eask)
    }
}

use crate::signing_key::SigningKey;
use blake2b_simd::Params;
const EXPAND_SEED: &[u8] = b"Zcash_ExpandSeed";
pub struct PrfExpand {}
impl PrfExpand {
    fn calc(sk: SigningKey, t: &u8) -> [u8; 64] {
        let mut h = Params::new()
            .hash_length(64)
            .personal(EXPAND_SEED)
            .to_state();
        h.update(sk);
        h.update(&[*t]);
        *h.finalize().as_array()
    }
    pub fn calc_ask(sk: SigningKey) -> [u8; 64] {
        Self::calc(sk, &0u8)
    }
    pub fn calc_nsk(sk: SigningKey) -> [u8; 64] {
        Self::calc(sk, &1u8)
    }
}

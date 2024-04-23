use crate::signing_key::SigningKey;
use ark_ed_on_bls12_381::Fr;
use ark_ff::PrimeField;
use blake2b_simd::Params;
use blake2s_simd::Params as b2sParams;
const EXPAND_SEED: &[u8] = b"Zcash_ExpandSeed";
const IVK: &[u8] = b"Zcashivk";
pub struct PrfExpand {}
impl PrfExpand {
    fn calc(sk: SigningKey, t: &[u8]) -> [u8; 64] {
        let mut h = Params::new()
            .hash_length(64)
            .personal(EXPAND_SEED)
            .to_state();
        h.update(sk);
        h.update(t);
        *h.finalize().as_array()
    }
    pub fn calc_ask(sk: SigningKey) -> [u8; 64] {
        Self::calc(sk, &[0u8])
    }
    pub fn calc_nsk(sk: SigningKey) -> [u8; 64] {
        Self::calc(sk, &[1u8])
    }
    pub fn calc_ovk(sk: SigningKey) -> [u8; 64] {
        Self::calc(sk, &[2u8])
    }
    pub fn calc_default_diversified(sk: SigningKey, i: u8) -> [u8; 11] {
        let mut t = [0u8; 11];
        t.copy_from_slice(&Self::calc(sk, &[3, i])[..11]);
        t
    }
}
pub struct Crh {}
impl Crh {
    pub fn calc(ak: &[u8], nk: &[u8]) -> Fr {
        let h = b2sParams::new()
            .hash_length(32)
            .personal(IVK)
            .to_state()
            .update(ak)
            .update(nk)
            .finalize();
        println!("crh_raw: {:?}", h.as_bytes());
        let mut h: [u8; 32] = h.as_bytes().try_into().expect("Wrong Size");
        h[31] &= 0b0000_0111;
        Fr::from_le_bytes_mod_order(&h)
    }
}

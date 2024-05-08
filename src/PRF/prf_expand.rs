use crate::{signing_key::SigningKey, PRF::poseidon_config};
use ark_crypto_primitives::crh::poseidon;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::prf::blake2s::Blake2sWithParameterBlock;
use ark_ed_on_bls12_381::Fr;
use ark_ff::PrimeField;
use blake2::digest::Digest;
use blake2::Blake2s256 as Blake2s;
use blake2b_simd::Params;
use blake2s_simd::Params as b2sParams;
const EXPAND_SEED: &[u8] = b"Zcash_ExpandSeed";
pub const IVK: &[u8] = b"Zcashivk";
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
        // let mut pers: [u8; 8] = [0; 8];
        //
        // pers[..IVK.len()].copy_from_slice(IVK);
        let b2sp = Blake2sWithParameterBlock {
            output_size: 32,
            key_size: 0,
            personalization: [0; 8],
            salt: [0; 8],
        };
        // let ak = Fr::from_le_bytes_mod_order(ak);
        // let nk = Fr::from_le_bytes_mod_order(nk);
        let mut inp: Vec<u8> = vec![];
        inp.extend(ak);
        inp.extend(nk);
        println!("hash input: {:?}", inp);
        // let mut h = b2sp.evaluate(inp.as_ref());
        let mut b2s = Blake2s::new();
        b2s.update(&inp);
        let mut h = [0; 32];
        h.copy_from_slice(&b2s.finalize());
        // let h: Fr =
        //     poseidon::CRH::<Fr>::evaluate(&poseidon_config::poseidon_parameters(), vec![ak, nk])
        //         .expect("hash failed");
        // let mut h: [u8; 32] = b2sParams::new()
        //     .hash_length(32)
        //     .personal(IVK)
        //     .to_state()
        //     .update(ak)
        //     .update(nk)
        //     .finalize()
        //     .as_bytes()
        //     .try_into()
        //     .expect("failed");
        h[31] &= 0b0000_0111;
        Fr::from_le_bytes_mod_order(&h)
    }
}

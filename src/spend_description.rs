use crate::commitment::{mixing_pedersen_hash, Commitment};
use crate::key_gen::{PublicKey, Signature};
use crate::PRF::prf_expand::Crh;
use ark_ed_on_bls12_381::EdwardsAffine;
use ark_ed_on_bls12_381::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
#[derive(Clone)]
pub struct Nullifier(pub [u8; 32]);
impl Nullifier {
    pub fn new(note_commitment: EdwardsAffine, pos: u64, nk: EdwardsAffine) -> Self {
        let rho = mixing_pedersen_hash(
            note_commitment,
            Fr::from_le_bytes_mod_order(&pos.to_le_bytes()),
        );
        let mut nk_repr = [0_u8; 32];
        let mut rho_repr = [0_u8; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&nk, nk_repr.as_mut()).unwrap();
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&rho, rho_repr.as_mut())
            .unwrap();
        println!("rho_repr: {:?}", rho_repr);
        println!("nk_repr: {:?}", nk_repr);
        Self(Crh::find_nullifier(&nk_repr, &rho_repr))
    }
}
pub struct SpendDescription {
    cv: Commitment,
    anchor: ark_ed_on_bls12_381::Fr,
    nf: Nullifier,
    rk: PublicKey,
    spend_proof: u64,
    sig: Signature,
}

use crate::commitment::Commitment;
use crate::key_gen::{PublicKey, Signature};
pub struct Nullifier(pub [u8; 32]);
pub struct SpendDescription {
    cv: Commitment,
    anchor: ark_bls12_381::Fr,
    nf: Nullifier,
    rk: PublicKey,
    spend_proof: u64,
    sig: Signature,
}

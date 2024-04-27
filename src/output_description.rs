use crate::commitment::Commitment;
use crate::key_gen::{PublicKey, Signature};
pub struct Nullifier(pub [u8; 32]);
pub struct SpendDescription {
    cv: Commitment,
    cmu: [u8; 64],
    epk: PublicKey,
    enc_cipher: [u8; 32],
    dec_cipher: [u8; 32],
    output_proof: u64,
}

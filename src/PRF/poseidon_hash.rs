use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::CRHScheme;
pub type MerkleTreeHash = CRH<ark_bls12_381::Fr>;

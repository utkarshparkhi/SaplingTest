use ark_ec::AffineRepr;

use ark_ed_on_bls12_381::EdwardsAffine;
use blake2s_simd::Params;
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";
pub const SPEND_AUTH_GEN: &[u8] = b"Zcash_G_";
pub const DIVERSIFY_HASH: &[u8] = b"Zcash_gd";
pub const ZCASH_H: &[u8] = b"Zcash_H_";
pub const ZCASH_PEDERSEN_GENERATORS: &[u8] = b"Zcash_PH";
pub fn group_hash(tag: &[u8], personal: &[u8]) -> Option<EdwardsAffine> {
    let h = Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state()
        .update(GH_FIRST_BLOCK)
        .update(tag)
        .finalize();
    println!("Here : {:?} {:?} {:?}", tag, personal, h.as_array());
    let p: Option<EdwardsAffine> = EdwardsAffine::from_random_bytes(h.as_array());
    p.map(|p| {
        if !p.is_zero() {
            let mut p = p.clear_cofactor();
            //p.x = -p.x;
            //
            Some(p)
        } else {
            None
        }
    })?
}
pub fn calc_group_hash(tag: &[u8], personal: &[u8]) -> EdwardsAffine {
    let mut tag = tag.to_vec();
    let i = tag.len();
    tag.push(0);
    loop {
        let gh = group_hash(&tag, personal);
        tag[i] += 1;
        assert_ne!(tag[0], u8::max_value());
        if let Some(gh) = gh {
            println!("FOUND: {:?} ,{:?}", i, gh);
            return gh;
        }
    }
}
pub fn group_hash_spend_auth() -> EdwardsAffine {
    calc_group_hash(&[], SPEND_AUTH_GEN)
}
pub fn group_hash_h_sapling() -> EdwardsAffine {
    calc_group_hash(&[], ZCASH_H)
}
pub fn diversify_hash(d: &[u8]) -> Option<EdwardsAffine> {
    group_hash(d, DIVERSIFY_HASH)
}
pub fn pedersen_generator(i: &[u8]) -> EdwardsAffine {
    calc_group_hash(i, ZCASH_PEDERSEN_GENERATORS)
}
#[cfg(test)]
pub mod test {
    use super::*;
    use ark_ed_on_bls12_381::Fq;
    use ark_ff::Field;

    #[test]
    pub fn test_simple() {
        let fq1: [u64; 4] = [
            0x47bf_4692_0a95_a753,
            0xd5b9_a7d3_ef8e_2827,
            0xd418_a7ff_2675_3b6a,
            0x0926_d4f3_2059_c712,
        ];
        let fq2: [u64; 4] = [
            0x3056_32ad_aaf2_b530,
            0x6d65_674d_cedb_ddbc,
            0x53bb_37d0_c21c_fd05,
            0x57a1_019e_6de9_b675,
        ];
        let mut fq1n: [u8; 32] = [0; 32];
        fq1n.copy_from_slice(
            &([
                fq1[0].to_le_bytes(),
                fq1[1].to_le_bytes(),
                fq1[2].to_le_bytes(),
                fq1[3].to_le_bytes(),
            ]
            .concat()),
        );
        let mut fq2n: [u8; 32] = [0; 32];
        fq2n.copy_from_slice(
            &([
                fq2[0].to_le_bytes(),
                fq2[1].to_le_bytes(),
                fq2[2].to_le_bytes(),
                fq2[3].to_le_bytes(),
            ]
            .concat()),
        );
        let mut proof_generation_key_generator: EdwardsAffine = EdwardsAffine::new(
            Fq::from_random_bytes(&fq1n).unwrap(),
            Fq::from_random_bytes(&fq2n).unwrap(),
        );
        proof_generation_key_generator.x = -proof_generation_key_generator.x;
        assert_eq!(group_hash_spend_auth(), proof_generation_key_generator)
    }
}

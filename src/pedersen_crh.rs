use ark_crypto_primitives::crh::pedersen;

use ark_ed_on_bls12_381::EdwardsProjective;

use crate::group_hash;
#[derive(Clone)]
pub struct Window;
impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 63;
}

pub fn get_pedersen_generators() -> Vec<Vec<ark_ed_on_bls12_381::EdwardsProjective>> {
    let mut vc: Vec<EdwardsProjective> = vec![];
    for i in 0..6 {
        let eda = group_hash::pedersen_generator(&(i as u32).to_le_bytes());
        let edpt = EdwardsProjective::from(eda);

        vc.push(edpt);
    }
    vec![vc]
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_ed_on_bls12_381::Fq;
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;
    const GENERATORS_X: [[u64; 4]; 6] = [
        [
            0x194e_4292_6f66_1b51_u64,
            0x2f0c_718f_6f0f_badd_u64,
            0xb5ea_25de_7ec0_e378_u64,
            0x73c0_16a4_2ded_9578_u64,
        ],
        [
            0xb981_9dc8_2d90_607e,
            0xa361_ee3f_d48f_df77,
            0x52a3_5a8c_1908_dd87,
            0x15a3_6d1f_0f39_0d88,
        ],
        [
            0x76d6_f7c2_b67f_c475,
            0xbae8_e5c4_6641_ae5c,
            0xeb69_ae39_f5c8_4210,
            0x6643_21a5_8246_e2f6,
        ],
        [
            0x4c76_7804_c1c4_a2cc,
            0x7d02_d50e_654b_87f2,
            0xedc5_f4a9_cff2_9fd5,
            0x323a_6548_ce9d_9876,
        ],
        [
            0x4680_9430_657f_82d1,
            0xefd5_9313_05f2_f0bf,
            0x89b6_4b4e_0336_2796,
            0x3bd2_6660_00b5_4796,
        ],
        [
            0xcb3c_0232_58d3_2079,
            0x1d9e_5ca2_1135_ff6f,
            0xda04_9746_d76d_3ee5,
            0x6344_7b2b_a31b_b28a,
        ],
    ];
    const GENERATORS_Y: [[u64; 4]; 6] = [
        [
            0x77bf_abd4_3224_3cca,
            0xf947_2e8b_c04e_4632,
            0x79c9_166b_837e_dc5e,
            0x289e_87a2_d352_1b57,
        ],
        [
            0x7b0d_c53c_4ebf_1891,
            0x1f3a_beeb_98fa_d3e8,
            0xf789_1142_c001_d925,
            0x015d_8c7f_5b43_fe33,
        ],
        [
            0x80ed_502c_9793_d457,
            0x8bb2_2a7f_1784_b498,
            0xe000_a46c_8e8c_e853,
            0x362e_1500_d24e_ee9e,
        ],
        [
            0x8471_4bec_a335_70e9,
            0x5103_afa1_a11f_6a85,
            0x9107_0acb_d8d9_47b7,
            0x2f7e_e40c_4b56_cad8,
        ],
        [
            0x9996_8299_c365_8aef,
            0xb3b9_d809_5859_d14c,
            0x3978_3238_1406_c9e5,
            0x494b_c521_03ab_9d0a,
        ],
        [
            0x4360_8211_9f8d_629a,
            0xa802_00d2_c66b_13a7,
            0x64cd_b107_0a13_6a28,
            0x64ec_4689_e8bf_b6e5,
        ],
    ];
    #[test]
    pub fn crh_test() {
        let v = get_pedersen_generators();
        let ev: EdwardsProjective = EdwardsProjective::from(EdwardsAffine::new_unchecked(
            Fq::from_le_bytes_mod_order(
                &[
                    GENERATORS_X[0][0].to_le_bytes(),
                    GENERATORS_X[0][1].to_le_bytes(),
                    GENERATORS_X[0][2].to_le_bytes(),
                    GENERATORS_X[0][3].to_le_bytes(),
                ]
                .concat(),
            ),
            Fq::from_le_bytes_mod_order(
                &[
                    GENERATORS_Y[0][0].to_le_bytes(),
                    GENERATORS_Y[0][1].to_le_bytes(),
                    GENERATORS_Y[0][2].to_le_bytes(),
                    GENERATORS_Y[0][3].to_le_bytes(),
                ]
                .concat(),
            ),
        ));
        let mut vbytes: [u8; 32] = [0; 32];
        let mut evbytes: [u8; 32] = [0; 32];
        v[0][0].serialize_compressed(&mut vbytes[..]).unwrap();
        ev.serialize_compressed(&mut evbytes[..]).unwrap();
        println!("v :{:?}", v[0][0]);
        println!("vb : {:?}", vbytes);
        println!("ev : {:?}", ev);
        println!("evb : {:?}", evbytes);
        assert_eq!(ev, v[0][0]);
    }
}

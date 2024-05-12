use crate::commitment::{Commitment, ValueCommitTrapdoor};
use crate::group_hash;
use crate::key_gen::{Params, PublicKey};
use crate::note::NoteValue;
use crate::pedersen_crh::Window;
use crate::spend_description::Nullifier;
use crate::PRF::poseidon_config::poseidon_parameters;
use ark_crypto_primitives::commitment::pedersen::constraints::{
    CommGadget, ParametersVar as pdcmParamVar, RandomnessVar as pdcmRandVar,
};
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::commitment::CommitmentGadget;
use ark_crypto_primitives::crh::constraints::TwoToOneCRHSchemeGadget;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_crypto_primitives::prf::constraints::PRFGadget;
use ark_crypto_primitives::signature::schnorr::constraints::SchnorrRandomizePkGadget;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::signature::SigRandomizePkGadget;
use ark_crypto_primitives::signature::*;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsAffine, Fr};
use ark_ff::BigInteger;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::ToBytesGadget;
use ark_r1cs_std::{prelude::*, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
pub type ConstraintF = ark_bls12_381::Fr;
pub fn to_repr(affine: EdwardsVar, cs: Namespace<ConstraintF>) -> Vec<UInt8<ConstraintF>> {
    let mut tmp: Vec<_> = vec![];

    let x: Vec<Boolean<ConstraintF>> =
        <FpVar<_> as ToBitsGadget<_>>::to_bits_le(&affine.x).unwrap();

    let mut y = <FpVar<_> as ToBitsGadget<_>>::to_bits_le(&affine.y).unwrap();
    let msb = &x[x.len() - 1];
    y.push(msb.clone());
    let mut tmp1 = vec![];
    for i in 1..y.len() + 1 {
        tmp1.push(y[i - 1].clone());
        if (i as i32) % 8 == 0 {
            let ui = UInt8::from_bits_le(&tmp1);
            tmp1.clear();
            tmp.push(ui)
        }
    }
    tmp
}
#[derive(Clone)]
pub struct Spend<'a> {
    //pub val: NoteValue,
    //pub vc_randomness: Fr,
    pub ak: Option<EdwardsAffine>,
    pub sig_params: Params,
    pub randomness: &'a [Option<u8>],
    pub randomized_ak: Option<EdwardsAffine>,
    pub nsk: &'a [Option<u8>],
    pub nk: Option<EdwardsAffine>,
    pub val_cm_old: Option<EdwardsProjective>,
    pub note_val: Option<NoteValue>,
    pub rcv_old: Option<ValueCommitTrapdoor>,
    pub cm_params: Option<Commitment>,
    pub crh_rand: Option<Randomness<EdwardsProjective>>,

    pub note_com: EdwardsAffine,
    pub ivk: Option<Fr>,
    pub gd: Option<EdwardsAffine>,
    pub pk_d: Option<EdwardsAffine>,
    pub nf_old: Option<Nullifier>,
    pub pos: Option<u64>,
    pub root: Option<ConstraintF>,
    pub auth_path: Vec<Option<(ConstraintF, bool)>>,
}
impl ConstraintSynthesizer<ConstraintF> for Spend<'_> {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> ark_relations::r1cs::Result<()> {
        //ensure ak is not low order
        let ak = <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "ak"), || {
            self.ak.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // // let tmp = ak.double()?;
        // // let tmp = tmp.double()?;
        // // let tmp = tmp.double()?;
        // //
        // ak.enforce_equal(&ak)?;
        // //Spend Authority check
        // {
        //     let params_var =
        //         schnorr::constraints::ParametersVar::<EdwardsProjective, EdwardsVar>::new_constant(
        //             ark_relations::ns!(cs, "sig params"),
        //             self.sig_params,
        //         )?;
        //     let pk_var: schnorr::constraints::PublicKeyVar<EdwardsProjective, EdwardsVar>;
        //     if let Some(pk) = self.ak {
        //         pk_var = schnorr::constraints::PublicKeyVar::new_witness(
        //             ark_relations::ns!(cs, "pk_ak"),
        //             || Ok(pk),
        //         )?
        //     } else {
        //         pk_var = schnorr::constraints::PublicKeyVar::new_witness(
        //             ark_relations::ns!(cs, "pk_ak"),
        //             || {
        //                 Result::<EdwardsAffine, SynthesisError>::Err(
        //                     SynthesisError::AssignmentMissing,
        //                 )
        //             },
        //         )?
        //     }
        //
        //     let rand = UInt8::<ConstraintF>::new_witness_vec(
        //         ark_relations::ns!(cs, "random"),
        //         self.randomness,
        //     )?;
        //     let computed_rand_pk =
        //     <SchnorrRandomizePkGadget<EdwardsProjective, EdwardsVar> as SigRandomizePkGadget<
        //         Schnorr<EdwardsProjective, Blake2b512>,
        //         ConstraintF,
        //     >>::randomize(&params_var, &pk_var, &rand)?;
        //     let randomized_ak: schnorr::constraints::PublicKeyVar<EdwardsProjective, EdwardsVar> =
        //         schnorr::constraints::PublicKeyVar::new_input(
        //             ark_relations::ns!(cs, "orig rand pk"),
        //             || self.randomized_ak.ok_or(SynthesisError::AssignmentMissing),
        //         )?;
        //     computed_rand_pk.enforce_equal(&randomized_ak)?;
        // }
        // //calculate nk
        // let nk;
        // {
        //     let proof_generator = <EdwardsVar as AllocVar<_, _>>::new_constant(
        //         ark_relations::ns!(cs, "proof generator"),
        //         group_hash::group_hash_h_sapling(),
        //     )?;
        //
        //     let nsk = UInt8::new_witness_vec(ark_relations::ns!(cs, "nsk"), &self.nsk);
        //     let nsk = nsk
        //         .iter()
        //         .flat_map(|b| b.to_bits_le().unwrap())
        //         .collect::<Vec<_>>();
        //     nk = proof_generator.scalar_mul_le(nsk.iter())?;
        //     let claimed_nk = <EdwardsVar as AllocVar<_, _>>::new_input(
        //         ark_relations::ns!(cs, "claimed nk"),
        //         || self.nk.ok_or(SynthesisError::AssignmentMissing),
        //     )?;
        //     nk.enforce_equal(&claimed_nk)?;
        // }
        // //value_commitment
        // {
        //     let v_sap_raw = group_hash::calc_v_sapling();
        //     let r_sap_raw = group_hash::calc_r_sapling();
        //     let v_sap: EdwardsVar = <EdwardsVar as AllocVar<_, _>>::new_constant(
        //         ark_relations::ns!(cs, "v_sap"),
        //         v_sap_raw,
        //     )?;
        //     let r_sap = <EdwardsVar as AllocVar<_, _>>::new_constant(
        //         ark_relations::ns!(cs, "r_sap"),
        //         r_sap_raw,
        //     )?;
        //     let note_value;
        //     if let Some(v) = self.note_val.clone() {
        //         note_value = UInt8::new_witness_vec(
        //             ark_relations::ns!(cs, "note_value"),
        //             &Fr::from(v.0).0.to_bytes_le(),
        //         )?;
        //     } else {
        //         note_value = UInt8::new_witness_vec(ark_relations::ns!(cs, "note_value"), &[None])?;
        //     }
        //     let note_value_bits = note_value
        //         .iter()
        //         .flat_map(|b| b.to_bits_le().unwrap())
        //         .collect::<Vec<_>>();
        //     let rcv;
        //     if let Some(v) = self.rcv_old {
        //         rcv = UInt8::new_witness_vec(ark_relations::ns!(cs, "rcv"), &v.0 .0.to_bytes_le());
        //     } else {
        //         rcv = UInt8::new_witness_vec(ark_relations::ns!(cs, "rcv"), &[None]);
        //     }
        //     let rcv_bits = rcv
        //         .iter()
        //         .flat_map(|b| b.to_bits_le().unwrap())
        //         .collect::<Vec<_>>();
        //     let computed_val_cm = &v_sap.scalar_mul_le(note_value_bits.iter())?
        //         + &r_sap.scalar_mul_le(rcv_bits.iter())?;
        //     let old_val_cm = <EdwardsVar as AllocVar<_, _>>::new_input(
        //         ark_relations::ns!(cs, "old_val_cm"),
        //         || self.val_cm_old.ok_or(SynthesisError::AssignmentMissing),
        //     )?;
        //     computed_val_cm.enforce_equal(&old_val_cm)?;
        // }
        // //IVK
        // let nk_repr: Vec<_> = to_repr(nk, ark_relations::ns!(cs, "nk_repr"));
        // let g_d: EdwardsVar;
        // let pk_d: EdwardsVar;
        // {
        //     let ak_repr = to_repr(ak, ark_relations::ns!(cs, "ak_repr"));
        //     //
        //     let mut ivk = Blake2sGadget::evaluate(&ak_repr, &nk_repr)?;
        //     let mut x = ivk.0.value()?[31];
        //     x &= 0b00000111;
        //     let x = UInt8::new_witness(ark_relations::ns!(cs, "truncate"), || Ok(x))?;
        //     ivk.0.pop();
        //     ivk.0.push(x);
        //
        //     g_d =
        //         <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "g_d"), || {
        //             Ok(self.gd.unwrap())
        //         })?;
        //     let ivk_bits = ivk
        //         .0
        //         .iter()
        //         .flat_map(|b| b.to_bits_le().unwrap())
        //         .collect::<Vec<_>>();
        //     pk_d = g_d.scalar_mul_le(ivk_bits.iter())?;
        //     let claimed_pk_d = <EdwardsVar as AllocVar<_, _>>::new_input(
        //         ark_relations::ns!(cs, "claimed pk"),
        //         || self.pk_d.ok_or(SynthesisError::AssignmentMissing),
        //     )?;
        //     pk_d.enforce_equal(&claimed_pk_d)?;
        // }
        // //note commitment
        // let comm: EdwardsVar;
        // {
        //     let g_d_repr = to_repr(g_d.clone(), ark_relations::ns!(cs, "g_d to_repr"));
        //     let pk_d_repr = to_repr(pk_d, ark_relations::ns!(cs, "pk_d to_repr"));
        //
        //     let v_old;
        //     if let Some(v) = self.note_val {
        //         v_old = UInt8::new_witness_vec(
        //             ark_relations::ns!(cs, "note_value"),
        //             &v.0.to_le_bytes(),
        //         )?;
        //     } else {
        //         v_old = UInt8::new_witness_vec(ark_relations::ns!(cs, "note_value"), &[None])?;
        //     }
        //     let mut note_com_inp = vec![];
        //     note_com_inp.extend(g_d_repr);
        //     note_com_inp.extend(pk_d_repr);
        //     note_com_inp.extend(v_old);
        //     let pdcm_params: pdcmParamVar<EdwardsProjective, EdwardsVar> =
        //         <pdcmParamVar<_, _> as AllocVar<_, _>>::new_constant(
        //             ark_relations::ns!(cs, "crh params"),
        //             self.cm_params.unwrap().params,
        //         )?;
        //     let pdcm_randomness =
        //         pdcmRandVar::new_witness(ark_relations::ns!(cs, "crh randomness"), || {
        //             Ok(self.crh_rand.unwrap())
        //         })?;
        //     comm = CommGadget::<EdwardsProjective, EdwardsVar, Window>::commit(
        //         &pdcm_params,
        //         &note_com_inp,
        //         &pdcm_randomness,
        //     )?;
        //
        //     let claimed_comm = <EdwardsVar as AllocVar<_, _>>::new_constant(
        //         ark_relations::ns!(cs, "claimed note com"),
        //         self.note_com,
        //     )?;
        //     // println!("comm : {:?}", comm.value()?);
        //     // println!("claimed comm : {:?}", claimed_comm.value()?);
        //     comm.enforce_equal(&claimed_comm)?;
        // }
        // //Nullifier
        // {
        //     let j_sap = <EdwardsVar as AllocVar<_, _>>::new_constant(
        //         ark_relations::ns!(cs, "J_sap"),
        //         group_hash::calc_pedersen_hash(),
        //     )?;
        //     let pos;
        //     if let Some(p) = self.pos {
        //         pos = UInt8::new_witness_vec(
        //             ark_relations::ns!(cs, "pos"),
        //             &Fr::from(p).0.to_bytes_le(),
        //         )?;
        //     } else {
        //         pos = UInt8::new_witness_vec(ark_relations::ns!(cs, "pos"), &[None])?;
        //     }
        //     let pos_bits = pos
        //         .iter()
        //         .flat_map(|b| b.to_bits_le().unwrap())
        //         .collect::<Vec<_>>();
        //     let rho = comm.clone() + j_sap.scalar_mul_le(pos_bits.iter())?;
        //     let rho_repr = to_repr(rho, ark_relations::ns!(cs, "repr of rho"));
        //     let nf = Blake2sGadget::evaluate(&nk_repr, &rho_repr)?;
        //     let nf_old =
        //         UInt8::new_witness_vec(ark_relations::ns!(cs, "nf_old"), &self.nf_old.unwrap().0)?;
        //
        //     nf.0.enforce_equal(&nf_old)?;
        // }
        // //Merkle Path
        // let posiedon_hash_params = CRHParametersVar::new_constant(
        //     ark_relations::ns!(cs, "poseidon hash var"),
        //     poseidon_parameters(),
        // )?;
        // let mut curr_node: FpVar<ConstraintF> = comm.clone().y;
        // for (i, val) in self.auth_path.iter().enumerate() {
        //     let pos_bit;
        //     let sibling;
        //     if let Some((sib, p)) = val {
        //         pos_bit =
        //             Boolean::new_witness(ark_relations::ns!(cs, "flip the 2 children"), || Ok(p))?;
        //         sibling = FpVar::new_witness(ark_relations::ns!(cs, "sibling"), || Ok(sib))?;
        //     } else {
        //         pos_bit =
        //             Boolean::new_witness(ark_relations::ns!(cs, "flip the 2 children"), || {
        //                 Result::<bool, SynthesisError>::Err(SynthesisError::AssignmentMissing)
        //             })?;
        //         sibling = FpVar::new_witness(ark_relations::ns!(cs, "sibling"), || {
        //             Result::<ConstraintF, SynthesisError>::Err(SynthesisError::AssignmentMissing)
        //         })?;
        //     }
        //     let (lef, rig);
        //     rig = <FpVar<_> as CondSelectGadget<_>>::conditionally_select(
        //         &pos_bit, &curr_node, &sibling,
        //     )?;
        //     lef = <FpVar<_> as CondSelectGadget<_>>::conditionally_select(
        //         &pos_bit, &sibling, &curr_node,
        //     )?;
        //     curr_node = <TwoToOneCRHGadget<_> as TwoToOneCRHSchemeGadget<_, _>>::evaluate(
        //         &posiedon_hash_params,
        //         &lef,
        //         &rig,
        //     )?
        // }
        // let claimed_root =
        //     FpVar::new_input(ark_relations::ns!(cs, "commitment tree root"), || {
        //         self.root.ok_or(SynthesisError::AssignmentMissing)
        //     })?;
        // curr_node.enforce_equal(&claimed_root)?;
        Ok(())
    }
}
pub struct Output {
    pub cv_new: Option<EdwardsAffine>,
    pub note_com_new: Option<EdwardsAffine>,
    pub epk: Option<EdwardsAffine>,
    pub g_d: Option<EdwardsAffine>,
    pub pk_d: Option<EdwardsAffine>,
    pub v_new: Option<NoteValue>,
    pub rcv_new: Option<ValueCommitTrapdoor>,
    pub rcm_new: Option<Randomness<EdwardsProjective>>,
    pub esk: Option<Fr>,
    pub note_com_params: Commitment,
}
impl ConstraintSynthesizer<ConstraintF> for Output {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> ark_relations::r1cs::Result<()> {
        //Note Commitment
        let g_d =
            <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "gd"), || {
                self.g_d.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let pk_d =
            <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "pk_d"), || {
                self.pk_d.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let note_value;
        let v_new;

        if let Some(v_n) = self.v_new {
            v_new = UInt8::new_witness_vec(ark_relations::ns!(cs, "v_new"), &v_n.0.to_le_bytes())?;
            note_value = UInt8::new_witness_vec(
                ark_relations::ns!(cs, "note_value"),
                &Fr::from(v_n.0).0.to_bytes_le(),
            )?;
        } else {
            v_new = UInt8::new_witness_vec(ark_relations::ns!(cs, "v_new"), &[None])?;
            note_value = UInt8::new_witness_vec(ark_relations::ns!(cs, "note_value"), &[None])?;
        }
        let g_d_repr = to_repr(g_d.clone(), ark_relations::ns!(cs, "g_d to_repr"));
        let pk_d_repr = to_repr(pk_d, ark_relations::ns!(cs, "pk_d to_repr"));
        let mut note_com_inp = vec![];
        note_com_inp.extend(g_d_repr);
        note_com_inp.extend(pk_d_repr);
        note_com_inp.extend(v_new);
        let pdcm_params: pdcmParamVar<EdwardsProjective, EdwardsVar> =
            pdcmParamVar::<EdwardsProjective, EdwardsVar>::new_constant(
                ark_relations::ns!(cs, "note_com_params"),
                self.note_com_params.params,
            )?;
        let rcm_new = pdcmRandVar::new_witness(ark_relations::ns!(cs, "rcm_new"), || {
            self.rcm_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let note_com = CommGadget::<EdwardsProjective, EdwardsVar, Window>::commit(
            &pdcm_params,
            &note_com_inp,
            &rcm_new,
        )?;

        //first input note commitment
        let claimed_note_com = <EdwardsVar as AllocVar<_, _>>::new_input(
            ark_relations::ns!(cs, "claimed note com"),
            || self.note_com_new.ok_or(SynthesisError::AssignmentMissing),
        )?;
        note_com.enforce_equal(&claimed_note_com)?;
        //value commitment
        let v_sap_raw = group_hash::calc_v_sapling();
        let r_sap_raw = group_hash::calc_r_sapling();
        let v_sap: EdwardsVar = <EdwardsVar as AllocVar<_, _>>::new_constant(
            ark_relations::ns!(cs, "v_sap"),
            v_sap_raw,
        )?;
        let r_sap = <EdwardsVar as AllocVar<_, _>>::new_constant(
            ark_relations::ns!(cs, "r_sap"),
            r_sap_raw,
        )?;
        let note_value_bits = note_value
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let rcv;
        if let Some(rc) = self.rcv_new {
            rcv = UInt8::new_witness_vec(ark_relations::ns!(cs, "rcv"), &rc.0 .0.to_bytes_le());
        } else {
            rcv = UInt8::new_witness_vec(ark_relations::ns!(cs, "rcv"), &[None]);
        }
        let rcv_bits = rcv
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let computed_val_cm = &v_sap.scalar_mul_le(note_value_bits.iter())?
            + &r_sap.scalar_mul_le(rcv_bits.iter())?;
        //second public input value commitment
        let cv_new =
            <EdwardsVar as AllocVar<_, _>>::new_input(ark_relations::ns!(cs, "cv_new"), || {
                self.cv_new.ok_or(SynthesisError::AssignmentMissing)
            })?;
        computed_val_cm.enforce_equal(&cv_new)?;

        let esk;
        if let Some(es) = self.esk {
            esk = UInt8::new_witness_vec(ark_relations::ns!(cs, "esk"), &es.0.to_bytes_le())?;
        } else {
            esk = UInt8::new_witness_vec(ark_relations::ns!(cs, "esk"), &[None])?;
        }
        //third public input epk
        let epk = <EdwardsVar as AllocVar<_, _>>::new_input(ark_relations::ns!(cs, "epk"), || {
            self.epk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let esk_bits = esk
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let computed_epk = g_d.scalar_mul_le(esk_bits.iter())?;
        epk.enforce_equal(&computed_epk)?;
        let temp = g_d.double()?;
        let temp = temp.double()?;
        let temp = temp.double()?;
        temp.x.enforce_not_equal(&FpVar::<ConstraintF>::zero())?;
        Ok(())
    }
}
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::commitment::homomorphic_pedersen_commitment;
    use crate::spend_description::Nullifier;
    use crate::SigningKey;
    use crate::PRF::poseidon_config;
    use crate::{group_hash::group_hash_h_sapling, key_gen::Keychain};
    use ark_crypto_primitives::commitment::{
        pedersen::{Commitment as pdCommit, Randomness as pdRand},
        CommitmentScheme,
    };
    use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
    use ark_crypto_primitives::crh::TwoToOneCRHScheme;
    use ark_ec::AffineRepr;
    use ark_ff::fields::Field;
    use ark_ff::{BigInteger, BigInteger128, BigInteger256, UniformRand};
    use ark_groth16::prepare_verifying_key;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use ark_std::One;
    use rand::thread_rng;
    use tracing_subscriber::layer::SubscriberExt;
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];

    #[test]
    pub fn test_ak_not_small_order() {
        let kc = Keychain::from(SK);
        let (_d, g_d, pk_d) = kc.get_diversified_transmission_address();
        let randmized_pk = kc.get_randomized_ak();
        let proof_gen_key = group_hash_h_sapling();
        let note_val = NoteValue(2);
        let rcv = ValueCommitTrapdoor::random();
        let val_commitment = homomorphic_pedersen_commitment(note_val.clone(), &rcv).into_group();
        let comm = Commitment::setup();
        let crh_rand = pdRand::<EdwardsProjective>(Fr::one());
        let mut kc_key = vec![];
        kc_key.extend(kc.ak.to_repr_j());
        kc_key.extend(kc.nk.to_repr_j());
        let mut note_com_inp = vec![];
        let mut g_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&g_d, &mut g_d_repr[..])
            .expect("failed");

        let mut pk_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&pk_d.0, &mut pk_d_repr[..])
            .expect("failed");
        let v_repr = note_val.0.to_le_bytes();
        note_com_inp.extend(g_d_repr);
        note_com_inp.extend(pk_d_repr);
        note_com_inp.extend(v_repr);
        let note_com = pdCommit::<EdwardsProjective, Window>::commit(
            &comm.params.clone(),
            &note_com_inp,
            &crh_rand,
        )
        .expect("asdf");
        let mut ivk: [u8; 32] = [0; 32];
        ivk.copy_from_slice(&kc.ivk.0 .0.to_bytes_le());
        let mut pos: u64 = 1000;
        let mut merkle_path: Vec<Option<(ark_bls12_381::Fr, bool)>> = vec![];
        let mut root_till_now: ark_bls12_381::Fr = note_com.y;
        let mut rng = thread_rng();
        let p = pos.clone();
        for _ in 0..32 {
            let (lef, rig);
            if pos % 2 == 1 {
                lef = ark_bls12_381::Fr::rand(&mut rng);

                rig = root_till_now;
                merkle_path.push(Some((lef, true)));
            } else {
                rig = ark_bls12_381::Fr::rand(&mut rng);
                lef = root_till_now;
                merkle_path.push(Some((rig, false)));
            }
            root_till_now = <TwoToOneCRH<_> as TwoToOneCRHScheme>::evaluate(
                &poseidon_config::poseidon_parameters(),
                lef,
                rig,
            )
            .expect("hash failed");
            pos = pos / 2;
        }
        let nf = Nullifier::new(note_com, p, kc.nk.0);
        let a = &randmized_pk.0 .0.to_bytes_le();
        let mut oa = vec![];
        for i in randmized_pk.0 .0.to_bytes_le() {
            oa.push(Some(i))
        }
        let mut nsk = vec![];
        for i in kc.nsk.0 .0.to_bytes_le() {
            nsk.push(Some(i));
        }
        let spend = Spend {
            auth_path: merkle_path,
            root: Some(root_till_now),
            ak: Some(kc.ak.clone().0),
            randomized_ak: Some(randmized_pk.1 .0),
            randomness: &oa,
            sig_params: kc.parameters.clone(),
            nsk: &nsk,
            nk: Some(kc.nk.0),
            note_val: Some(note_val.clone()),
            rcv_old: Some(rcv.clone()),
            val_cm_old: Some(val_commitment.into()),
            cm_params: Some(comm.clone()),
            crh_rand: Some(crh_rand),
            note_com: note_com,
            ivk: Some(kc.ivk.0),
            gd: Some(g_d),
            pk_d: Some(pk_d.0),
            nf_old: Some(nf),
            pos: Some(p),
        };
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        spend.generate_constraints(cs.clone()).unwrap();

        let result = cs.is_satisfied().unwrap();
        println!("total constraints : {:?}", cs.num_constraints());
        println!("result {:?}", result);
        if !result {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(result);
        //let mut layer = ConstraintLayer::default();
        //layer.mode = OnlyConstraints;
        //let subscriber = tracing_subscriber::Registry::default().with(layer);

        //let cs = ConstraintSystem::new_ref();
        //spend.generate_constraints(cs.clone()).unwrap();
        //let result = cs.is_satisfied().unwrap();
        //if !result {
        //    println!("{:?}", cs.which_is_unsatisfied());
        //}
        //assert!(result);
    }
    #[test]
    pub fn test_output_circuit() {
        let kc = Keychain::from(SK);
        let value = NoteValue(10);
        let rcv = ValueCommitTrapdoor::random();
        let cv_new = homomorphic_pedersen_commitment(value.clone(), &rcv);
        let (d, g_d, pk_d) = kc.get_diversified_transmission_address();

        let cm_params = Commitment::setup();
        let rcm = pdRand::<EdwardsProjective>(Fr::from(46));
        let mut note_com_inp = vec![];
        let mut g_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&g_d, &mut g_d_repr[..])
            .expect("failed");

        let mut pk_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&pk_d.0, &mut pk_d_repr[..])
            .expect("failed");
        let v_repr = value.0.to_le_bytes();
        note_com_inp.extend(g_d_repr);
        note_com_inp.extend(pk_d_repr);
        note_com_inp.extend(v_repr);
        let note_comm =
            pdCommit::<EdwardsProjective, Window>::commit(&cm_params.params, &note_com_inp, &rcm)
                .expect("failed");
        let esk = Fr::from(5345345);
        let epk = g_d.mul_bigint(esk.0);
        let output = Output {
            cv_new: Some(cv_new),
            note_com_new: Some(note_comm),
            epk: Some(epk.into()),
            g_d: Some(g_d),
            pk_d: Some(pk_d.0),
            v_new: Some(value),
            rcv_new: Some(rcv),
            rcm_new: Some(rcm),
            esk: Some(esk),
            note_com_params: cm_params,
        };
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        output.generate_constraints(cs.clone()).unwrap();

        let result = cs.is_satisfied().unwrap();
        println!("result {:?}", result);
        if !result {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        println!("num constraints: {:?}", cs.num_constraints());
        assert!(result);
    }
}

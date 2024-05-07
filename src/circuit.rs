use crate::commitment::ValueCommitTrapdoor;
use crate::group_hash;
use crate::key_gen::{Params, PublicKey};
use crate::note::NoteValue;
use ark_crypto_primitives::signature::schnorr::constraints::SchnorrRandomizePkGadget;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::signature::SigRandomizePkGadget;
use ark_crypto_primitives::signature::*;
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsAffine, Fr};
use ark_ff::BigInteger;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use blake2::Blake2b512;
pub type ConstraintF = ark_bls12_381::Fr;
#[derive(Clone)]
pub struct Spend<'a> {
    //pub val: NoteValue,
    //pub vc_randomness: Fr,
    pub ak: PublicKey,
    pub sig_params: Params,
    pub randomness: &'a [u8],
    pub randomized_ak: PublicKey,
    pub proof_generation_key: EdwardsAffine,
    pub nsk: Fr,
    pub nk: EdwardsAffine,
    pub val_cm_old: EdwardsAffine,
    pub note_val: NoteValue,
    pub rcv_old: ValueCommitTrapdoor,
}
impl ConstraintSynthesizer<ConstraintF> for Spend<'_> {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> ark_relations::r1cs::Result<()> {
        //let spend_auth_gen: AffineVar<JubjubConfig, FpVar<Fq>> =
        //    AffineVar::<EdwardsConfig, FpVar<Fq>>::new_constant(
        //        ark_relations::ns!(cs, "spend auth gen"),
        //        group_hash::group_hash_spend_auth().into_group(),
        //    )?;
        //ensure ak is not low order
        let ak = EdwardsVar::new_witness(ark_relations::ns!(cs, "ak"), || Ok(self.ak.0))?;
        let tmp = ak.double()?;
        let tmp = tmp.double()?;
        let tmp = tmp.double()?;
        tmp.x.enforce_not_equal(&FpVar::<ConstraintF>::zero())?;
        let params_var =
            schnorr::constraints::ParametersVar::<EdwardsProjective, EdwardsVar>::new_constant(
                ark_relations::ns!(cs, "sig params"),
                self.sig_params,
            )?;
        let pk_var: schnorr::constraints::PublicKeyVar<EdwardsProjective, EdwardsVar> =
            schnorr::constraints::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "pk_ak"),
                || Ok(self.ak.0),
            )?;
        let rand = UInt8::<ConstraintF>::new_witness_vec(
            ark_relations::ns!(cs, "random"),
            self.randomness,
        )?;
        let computed_rand_pk =
            <SchnorrRandomizePkGadget<EdwardsProjective, EdwardsVar> as SigRandomizePkGadget<
                Schnorr<EdwardsProjective, Blake2b512>,
                ConstraintF,
            >>::randomize(&params_var, &pk_var, &rand)?;
        let randomized_ak: schnorr::constraints::PublicKeyVar<EdwardsProjective, EdwardsVar> =
            schnorr::constraints::PublicKeyVar::new_input(
                ark_relations::ns!(cs, "orig rand pk"),
                || Ok(self.randomized_ak.0),
            )?;
        computed_rand_pk.enforce_equal(&randomized_ak)?;
        let nk;
        {
            let proof_generator = <EdwardsVar as AllocVar<_, _>>::new_constant(
                ark_relations::ns!(cs, "proof generator"),
                group_hash::group_hash_h_sapling(),
            )?;

            let nsk =
                UInt8::new_witness_vec(ark_relations::ns!(cs, "nsk"), &self.nsk.0.to_bytes_le());
            let nsk = nsk
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>();
            nk = proof_generator.scalar_mul_le(nsk.iter())?;
        }
        let claimed_nk = <EdwardsVar as AllocVar<_, _>>::new_input(
            ark_relations::ns!(cs, "claimed nk"),
            || Ok(self.nk),
        )?;
        nk.enforce_equal(&claimed_nk)?;
        let v_sap = group_hash::calc_v_sapling().into_group();
        let r_sap = group_hash::calc_r_sapling().into_group();
        let v_sap =
            <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "v_sap"), || {
                Ok(v_sap)
            })?;
        let r_sap =
            <EdwardsVar as AllocVar<_, _>>::new_witness(ark_relations::ns!(cs, "r_sap"), || {
                Ok(r_sap)
            })?;
        let note_value = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "note value"),
            &self.note_val.0.to_le_bytes(),
        )?;
        let not_value_bits = note_value
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let rcv = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "rcv"),
            &self.rcv_old.0 .0.to_bytes_le(),
        )?;
        let rcv_bits = rcv
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let mut computed_val_cm: EdwardsVar = v_sap.scalar_mul_le(not_value_bits.iter())?;
        computed_val_cm += r_sap.scalar_mul_le(rcv_bits.iter())?;
        let old_val_cm = <EdwardsVar as AllocVar<_, _>>::new_input(
            ark_relations::ns!(cs, "old_val_cm"),
            || Ok(self.val_cm_old),
        )?;
        computed_val_cm.y.enforce_equal(&old_val_cm.y)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::commitment::homomorphic_pedersen_commitment;
    use crate::SigningKey;
    use crate::{group_hash::group_hash_h_sapling, key_gen::Keychain};
    use ark_ff::BigInteger;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use tracing_subscriber::layer::SubscriberExt;
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];

    #[test]
    pub fn test_ak_not_small_order() {
        let kc = Keychain::from(SK);
        let randmized_pk = kc.get_randomized_ak();
        println!("rand,pk: {:?}", randmized_pk);
        let proof_gen_key = group_hash_h_sapling();
        let note_val = NoteValue(2);
        let rcv = ValueCommitTrapdoor::random();
        let val_commitment = homomorphic_pedersen_commitment(note_val.clone(), &rcv);
        let spend = Spend {
            ak: kc.ak.clone(),
            randomized_ak: randmized_pk.1,
            randomness: &randmized_pk.0 .0.to_bytes_le(),
            sig_params: kc.parameters.clone(),
            proof_generation_key: proof_gen_key,
            nsk: kc.nsk.0,
            nk: kc.nk.0,
            note_val: note_val.clone(),
            rcv_old: rcv.clone(),
            val_cm_old: val_commitment,
        };
        println!("note_val : {:?}", note_val);
        println!("rcv : {:?}", rcv);
        println!("val_com : {:?}", val_commitment);
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        spend.generate_constraints(cs.clone()).unwrap();
        let result = cs.is_satisfied().unwrap();
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
}

use crate::key_gen::{Params, PublicKey, Signature};
use ark_crypto_primitives::signature::schnorr::constraints::SchnorrRandomizePkGadget;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::signature::SigRandomizePkGadget;
use ark_crypto_primitives::signature::*;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsAffine, Fq, Fr};
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
            schnorr::constraints::PublicKeyVar::new_witness(ark_relations::ns!(cs, "pk"), || {
                Ok(self.ak.0)
            })?;
        let rand = UInt8::<ConstraintF>::new_witness_vec(
            ark_relations::ns!(cs, "random"),
            self.randomness,
        )?;
        let computed_rand_pk =
            <SchnorrRandomizePkGadget<EdwardsProjective, EdwardsVar> as SigRandomizePkGadget<
                Schnorr<EdwardsProjective, Blake2b512>,
                ConstraintF,
            >>::randomize(&params_var, &pk_var, &rand)?;
        //SchnorrRandomizePkGadget::<EdwardsProjective, EdwardsVar>::randomize(, public_key, randomness)
        //let alpha = FpVar::new_witness(ark_relations::ns!(cs, "alpha"), || Ok(self.alpha))?;
        //let alpha_bits = alpha.to_bits_le()?;
        //spend_generator.scalar_mul_le(alpha_bits.iter());
        let randomized_ak: schnorr::constraints::PublicKeyVar<EdwardsProjective, EdwardsVar> =
            schnorr::constraints::PublicKeyVar::new_input(
                ark_relations::ns!(cs, "orig rand pk"),
                || Ok(self.randomized_ak.0),
            )?;
        computed_rand_pk.enforce_equal(&randomized_ak)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::key_gen::Keychain;
    use crate::SigningKey;
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
        let spend = Spend {
            ak: kc.ak.clone(),
            randomized_ak: randmized_pk.1,
            randomness: randmized_pk.0.as_ref(),
            sig_params: kc.parameters.clone(),
        };
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        spend.generate_constraints(cs.clone()).unwrap();
        let result = cs.is_satisfied().unwrap();
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

use crate::key_gen::{Keychain, PublicKey};
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::EdwardsAffine;
#[derive(Debug)]
pub struct PaymentAddress {
    diversifier: [u8; 11],
    pk_d: PublicKey,
}
impl<'a> From<Keychain<'a>> for PaymentAddress {
    fn from(value: Keychain) -> Self {
        let (d, pk_d) = value.get_diversified_transmission_address();
        Self {
            diversifier: d,
            pk_d,
        }
    }
}
impl From<[u8; 43]> for PaymentAddress {
    fn from(value: [u8; 43]) -> Self {
        let mut d: [u8; 11] = [0; 11];
        d.copy_from_slice(&value[..11]);
        let mut pk_db: [u8; 32] = [0; 32];
        pk_db.copy_from_slice(&value[11..]);
        let pk_d: PublicKey = PublicKey(EdwardsAffine::from_random_bytes(&pk_db).unwrap());
        Self {
            diversifier: d,
            pk_d,
        }
    }
}
impl PaymentAddress {
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes: [u8; 43] = [0; 43];
        bytes[..11].copy_from_slice(&self.diversifier);
        bytes[11..].copy_from_slice(&self.pk_d.to_repr_j());
        bytes
    }
}
#[cfg(test)]
mod tests {
    use crate::signing_key::SigningKey;

    use super::{Keychain, PaymentAddress};
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];
    const EASK: [u8; 32] = [
        14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210, 17,
        50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
    ];
    const EIVK: [u8; 32] = [
        162, 159, 59, 178, 16, 189, 223, 176, 99, 86, 247, 67, 215, 146, 154, 112, 191, 254, 50,
        78, 104, 214, 15, 66, 181, 235, 78, 158, 91, 167, 240, 2,
    ];
    #[test]
    pub fn test_to_fro_pa() {
        let kc: Keychain = Keychain::from(SK);
        let pa: PaymentAddress = PaymentAddress::from(kc);
        let pa_b = pa.to_bytes();
        println!("{:?}", pa);
        println!("{:?}", pa_b);
        let pa_bc = PaymentAddress::from(pa_b);
        assert_eq!(pa_b, pa_bc.to_bytes());
    }
}

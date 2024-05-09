pub mod PRF;
pub mod address;
pub mod commitment;
pub mod group_hash;
pub mod key_gen;
pub mod note;
pub mod output_description;
pub mod pedersen_crh;
pub mod signing_key;
pub mod spend_description;
pub mod utils;
use ark_std::rand;
pub mod circuit;
use rand::Rng;

use crate::signing_key::SigningKey;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "gen" {
        let mut rng = rand::thread_rng();
        let mut sk_raw: [u8; 32] = [0u8; 32];
        rng.fill(&mut sk_raw);
        let sk: SigningKey = &sk_raw;

        let kc = key_gen::Keychain::from(sk);
        println!("ask: {:?}", kc.ask);
        println!("nsk: {:?}", kc.nsk);
        println!("ovk: {:?}", kc.ovk);
        println!("ak: {:?}", kc.ak);
        println!("params: {:?}", kc.parameters);
    }
}

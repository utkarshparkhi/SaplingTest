pub mod PRF;
pub mod key_gen;
pub mod signing_key;
use ark_std::rand;
use rand::Rng;

use crate::signing_key::SigningKey;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "gen" {
        let mut rng = rand::thread_rng();
        let mut sk_raw: [u8; 32] = [0u8; 32];
        rng.fill(&mut sk_raw);
        let sk: SigningKey = &sk_raw;

        let ask = key_gen::SpendAuthorizationKey::new(sk);
        println!("Sk={:?}", sk);
        println!("ask={:?}", ask.0);
    }
    println!("Hello, world!");
}

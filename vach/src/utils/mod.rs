use ed25519_dalek as esdalek;
use rand::rngs::OsRng;

/// Use this function to easily generate a [Keypair](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.Keypair.html) using `OsRng`
#[inline(always)]
pub fn gen_keypair() -> esdalek::Keypair {
	esdalek::Keypair::generate(&mut OsRng)
}

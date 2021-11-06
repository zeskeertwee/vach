use ed25519_dalek as esdalek;
use rand::rngs::OsRng;
use std::{
	io::Read,
};
use anyhow;

/// Use this function to easily generate a [Keypair](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.Keypair.html) using `OsRng`
#[inline(always)]
pub fn gen_keypair() -> esdalek::Keypair {
	esdalek::Keypair::generate(&mut OsRng)
}

/// Use this to read and parse a `Keypair` from a `io::Read` handle
pub fn read_keypair<R: Read>(mut handle: R) -> anyhow::Result<esdalek::Keypair> {
	let mut keypair_bytes = [0; crate::KEYPAIR_LENGTH];
	handle.read_exact(&mut keypair_bytes)?;
	Ok(esdalek::Keypair::from_bytes(&keypair_bytes)?)
}
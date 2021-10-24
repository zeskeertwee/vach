use chacha20stream as c20stream;
use ed25519_dalek as esdalek;
use rand::rngs::OsRng;
use std::{io::{Read, Write}, convert::TryInto};
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

pub(crate) fn transform_key(public_key: &esdalek::PublicKey) -> anyhow::Result<c20stream::Key> {
	let bytes = &public_key.to_bytes() as &[u8];
	Ok(c20stream::Key::from_bytes(bytes.try_into()?))
}

pub(crate) fn transform_iv(magic: &[u8; 5]) -> anyhow::Result<c20stream::IV> {
	let mut iv_bytes = vec![0; 7];
	iv_bytes.write_all(magic)?;
	let iv_bytes: [u8; 12] = iv_bytes.as_slice().try_into()?;
	Ok(c20stream::IV::from_bytes(iv_bytes))
}
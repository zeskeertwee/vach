use ed25519_dalek as esdalek;
use rand::rngs::OsRng;
use std::{io::Read};

use crate::global::{error::InternalError, result::InternalResult};

/// Use this function to easily generate a [Keypair](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.Keypair.html) using `OsRng`
#[inline(always)]
pub fn gen_keypair() -> esdalek::Keypair {
	esdalek::Keypair::generate(&mut OsRng)
}

/// Use this to read and parse a `Keypair` from a read stream
/// ### Errors
///  - If the data can't be parsed into a keypair
pub fn read_keypair<R: Read>(mut handle: R) -> InternalResult<esdalek::Keypair> {
	let mut keypair_bytes = [0; crate::KEYPAIR_LENGTH];
	handle.read_exact(&mut keypair_bytes)?;
	Ok(match esdalek::Keypair::from_bytes(&keypair_bytes) {
		Ok(kep) => kep,
		Err(err) => return Err(InternalError::ParseError(err.to_string())),
	})
}

/// Read and parse a public key from a read stream
///
/// ### Errors
///  - If parsing of the public key fails
///  - `io` errors
pub fn read_public_key<T: Read>(mut handle: T) -> InternalResult<esdalek::PublicKey> {
	let mut keypair_bytes = [0; crate::PUBLIC_KEY_LENGTH];

	handle.read_exact(&mut keypair_bytes)?;

	match esdalek::PublicKey::from_bytes(&keypair_bytes) {
		Ok(pk) => Ok(pk),
		Err(err) => Err(InternalError::ValidationError(err.to_string())),
	}
}
/// Read and parse a secret key from a read stream
///
/// ### Errors
///  - If parsing of the secret key fails
///  - `io` errors
pub fn read_secret_key<T: Read>(mut handle: T) -> InternalResult<esdalek::SecretKey> {
	let mut secret_bytes = [0; crate::SECRET_KEY_LENGTH];

	handle.read_exact(&mut secret_bytes)?;

	match esdalek::SecretKey::from_bytes(&secret_bytes) {
		Ok(sk) => Ok(sk),
		Err(err) => Err(InternalError::ValidationError(err.to_string())),
	}
}

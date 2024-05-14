#![cfg(feature = "crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "crypto")))]

use {
	rand::rngs::OsRng,
	crate::{crypto, global::error::*},
	std::io::Read,
};

use rand::RngCore;

// A favour
#[cfg(feature = "compression")]
pub use super::global::compressor::Compressor;

/// Use this function to easily generate a [Keypair](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.Keypair.html) using `OsRng`
#[inline(always)]
pub fn gen_keypair() -> crypto::SigningKey {
	let mut bytes = [0u8; 32];
	(&mut OsRng).fill_bytes(&mut bytes);
	crypto::SigningKey::from_bytes(&bytes)
}

/// Use this to read and parse a `Keypair` from a read stream
/// ### Errors
///  - If the data can't be parsed into a keypair
pub fn read_keypair<R: Read>(mut handle: R) -> InternalResult<crypto::SigningKey> {
	let mut keypair_bytes = [0; crate::SECRET_KEY_LENGTH + crate::PUBLIC_KEY_LENGTH];
	handle.read_exact(&mut keypair_bytes)?;
	crypto::SigningKey::from_keypair_bytes(&keypair_bytes).map_err(|err| InternalError::ParseError(err.to_string()))
}

/// Read and parse a public key from a read stream
///
/// ### Errors
///  - If parsing of the public key fails
///  - `io` errors
pub fn read_public_key<T: Read>(mut handle: T) -> InternalResult<crypto::VerifyingKey> {
	let mut keypair_bytes = [0; crate::PUBLIC_KEY_LENGTH];
	handle.read_exact(&mut keypair_bytes)?;
	crypto::VerifyingKey::from_bytes(&keypair_bytes).map_err(|err| InternalError::ParseError(err.to_string()))
}
/// Read and parse a secret key from a read stream
///
/// ### Errors
///  - If parsing of the secret key fails
///  - `io` errors
pub fn read_secret_key<T: Read>(mut handle: T) -> InternalResult<crypto::SigningKey> {
	let mut secret_bytes = [0; crate::SECRET_KEY_LENGTH];
	handle.read_exact(&mut secret_bytes)?;
	Ok(crypto::SigningKey::from_bytes(&secret_bytes))
}

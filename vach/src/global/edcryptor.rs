use std::fmt;

use ed25519_dalek::PublicKey;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::{Aes256Gcm, Key, Nonce};

// Encryption - Decryption, A convenient wrapper around aes encryption and decryption
#[derive(Clone)]
pub(crate) struct Encryptor {
	cipher: Aes256Gcm,
	nonce: Nonce<U12>,
}

impl fmt::Debug for Encryptor {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "[Vach::Encryptor] cipher: Aes256Gcm, nonce: Nonce",)
	}
}

impl Encryptor {
	pub(crate) fn new(pk: &PublicKey, magic: [u8; 5]) -> Encryptor {
		// Build encryption key
		let bytes = &pk.to_bytes();

		// Build Nonce
		let key = Key::from_slice(bytes);
		let mut v = [178, 5, 239, 228, 165, 44, 169].to_vec();
		v.extend_from_slice(&magic);

		Encryptor {
			cipher: Aes256Gcm::new(key),
			nonce: *Nonce::from_slice(v.as_slice()),
		}
	}

	// The meat and the mass of this struct
	pub(crate) fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
		let res = match self.cipher.encrypt(&self.nonce, data.as_ref()) {
			Ok(data) => data,
			Err(err) => return Err(err.to_string()),
		};
		Ok(res)
	}

	pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
		let res = match self.cipher.decrypt(&self.nonce, data.as_ref()) {
			Ok(data) => data,
			Err(err) => return Err(err.to_string()),
		};
		Ok(res)
	}
}

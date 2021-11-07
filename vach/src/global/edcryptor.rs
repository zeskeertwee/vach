use std::fmt;

use ed25519_dalek::PublicKey;

use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};

// Encryption - Decryption, A convenience wrapper around aes encryption and decryption
pub(crate) struct EDCryptor {
	cipher: Aes256GcmSiv,
	nonce: Nonce,
}

impl fmt::Debug for EDCryptor {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let nonce = self.nonce.to_ascii_lowercase();
		write!(
			f,
			"[Vach::EDCryptor] cipher: Aes256GcmSiv, nonce: {}",
			String::from_utf8_lossy(nonce.as_slice())
		)
	}
}

impl EDCryptor {
	pub(crate) fn new(pk: &PublicKey, magic: [u8; 5]) -> EDCryptor {
		// Build encryption key
		let bytes = &pk.to_bytes();

		// Build Nonce
		let key = Key::from_slice(bytes);
		let mut v = [178, 5, 239, 228, 165, 44, 169].to_vec();
		v.extend_from_slice(&magic);

		EDCryptor {
			cipher: Aes256GcmSiv::new(key),
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

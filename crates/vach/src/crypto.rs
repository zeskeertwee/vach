#![cfg(feature = "crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
use std::fmt;

use aes_gcm::aead::{Aead, AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::global::error::{InternalError, InternalResult};

/// Encryption - Decryption, A convenient wrapper around [`aes`](aes_gcm) encryption and decryption
pub(crate) struct Encryptor {
	cipher: Aes256Gcm,
}

impl fmt::Debug for Encryptor {
	fn fmt(
		&self,
		f: &mut fmt::Formatter<'_>,
	) -> fmt::Result {
		f.debug_struct("Encryptor").field("cipher", &"<Aes256Gcm>").finish()
	}
}

impl Encryptor {
	pub(crate) fn new(vk: &VerifyingKey) -> Encryptor {
		Encryptor {
			cipher: Aes256Gcm::new_from_slice(vk.as_bytes()).unwrap(),
		}
	}

	pub(crate) fn encrypt(
		&self,
		data: &[u8],
	) -> InternalResult<(Vec<u8>, [u8; crate::NONCE_LENGTH])> {
		let nonce = Aes256Gcm::generate_nonce(OsRng);

		self.cipher.encrypt(&nonce, data).map_err(InternalError::CryptoError).map(|res| (res, *nonce.as_array().unwrap()))
	}

	pub(crate) fn decrypt(
		&self,
		data: &[u8],
		nonce: &[u8; crate::NONCE_LENGTH],
	) -> InternalResult<Vec<u8>> {
		let nonce = aes_gcm::Nonce::from_slice(nonce);
		self.cipher.decrypt(nonce, data).map_err(InternalError::CryptoError)
	}
}

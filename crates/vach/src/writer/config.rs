#[cfg(feature = "multithreaded")]
use std::num::NonZeroUsize;

use crate::global::flags::Flags;
#[cfg(feature = "crypto")]
use crate::crypto;

/// Settings for [`dump`](crate::writer::dump)
#[derive(Debug, Clone)]
pub struct BuilderConfig {
	/// Number of threads to spawn during `Builder::dump`, defaults to 4
	#[cfg(feature = "multithreaded")]
	pub num_threads: NonZeroUsize,
	/// Flags to be written into the `Header` section of the archive.
	pub flags: Flags,
	/// An optional private key. If one is provided, then the archive will have signatures.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub signing_key: Option<crypto::SigningKey>,
}

// Helper functions
impl BuilderConfig {
	/// Setter for the `keypair` field
	#[cfg(feature = "crypto")]
	pub fn keypair(mut self, keypair: crypto::SigningKey) -> Self {
		self.signing_key = Some(keypair);
		self
	}

	///```
	/// use vach::prelude::{Flags, BuilderConfig};
	///
	/// let config = BuilderConfig::default().flags(Flags::empty());
	///```
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}

	/// Read and parse a keypair from a stream of bytes
	#[cfg(feature = "crypto")]
	pub fn load_keypair<T: std::io::Read>(&mut self, handle: T) -> crate::global::error::InternalResult {
		crate::crypto_utils::read_keypair(handle).map(|kp| self.signing_key = Some(kp))
	}
}

impl<'a> Default for BuilderConfig {
	fn default() -> BuilderConfig {
		BuilderConfig {
			#[cfg(feature = "multithreaded")]
			num_threads: unsafe { NonZeroUsize::new_unchecked(4) },
			flags: Flags::default(),
			#[cfg(feature = "crypto")]
			signing_key: None,
		}
	}
}

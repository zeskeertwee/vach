#[cfg(feature = "crypto")]
use crate::crypto;
use crate::global::flags::Flags;

/// Settings for [`dump`](crate::writer::dump)
#[derive(Debug, Clone)]
pub struct BuilderConfig {
	/// Number of threads to spawn during `Builder::dump`. Set to 1 (default) to disable multithreading.
	pub num_threads: usize,
	/// Singleton flags to be written into the `Header` section of the archive.
	pub flags: Flags,
	/// An optional private key. If one is provided, then the archive will have signatures.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub signing_key: Option<crypto::SigningKey>,
}

// Helper functions
impl BuilderConfig {
	/// Setter for the [`num_threads`](BuilderConfig::num_threads) field
	pub fn threads(
		mut self,
		num_threads: usize,
	) -> Self {
		self.num_threads = num_threads;
		self
	}

	/// Setter for the [`keypair`](BuilderConfig::keypair) field
	#[cfg(feature = "crypto")]
	pub fn keypair(
		mut self,
		keypair: crypto::SigningKey,
	) -> Self {
		self.signing_key = Some(keypair);
		self
	}

	/// Setter for the [`flags`](BuilderConfig::flags) field
	pub fn flags(
		mut self,
		flags: Flags,
	) -> Self {
		self.flags = flags;
		self
	}

	/// Read and parse a keypair from a stream of bytes
	#[cfg(feature = "crypto")]
	pub fn load_keypair<T: std::io::Read>(
		&mut self,
		handle: T,
	) -> crate::global::error::InternalResult {
		crate::crypto_utils::read_keypair(handle).map(|kp| self.signing_key = Some(kp))
	}
}

impl Default for BuilderConfig {
	fn default() -> BuilderConfig {
		BuilderConfig {
			num_threads: 1,
			flags: Flags::default(),
			#[cfg(feature = "crypto")]
			signing_key: None,
		}
	}
}

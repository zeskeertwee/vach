#[cfg(feature = "multithreaded")]
use std::num::NonZeroUsize;

use crate::global::{flags::Flags, reg_entry::RegistryEntry};
#[cfg(feature = "crypto")]
use crate::crypto;

/// Allows for the customization of valid `vach` archives during their construction.
/// Such as custom `MAGIC`, custom `Header` flags and signing by providing a keypair.
pub struct BuilderConfig<'a> {
	/// Number of threads to spawn during `Builder::dump`, defaults to 4
	#[cfg(feature = "multithreaded")]
	pub num_threads: NonZeroUsize,
	/// Used to write a unique magic sequence into the archive.
	pub magic: [u8; crate::MAGIC_LENGTH],
	/// Flags to be written into the `Header` section of the archive.
	pub flags: Flags,
	/// An optional private key. If one is provided, then the archive will have signatures.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub signing_key: Option<crypto::SigningKey>,
	/// An optional callback that is called every time a [Leaf](crate::builder::Leaf) finishes processing.
	/// The callback get passed to it: a reference to the leaf and the generated registry entry. Use the RegEntry to get info on how the data was integrated for the given [`Leaf`].
	/// > **To avoid** the `implementation of "FnOnce" is not general enough` error consider adding types to the closure's parameters, as this is a type inference error. Rust somehow cannot infer enough information, [link](https://www.reddit.com/r/rust/comments/ntqu68/implementation_of_fnonce_is_not_general_enough/).
	/// Usage:
	/// ```
	/// use vach::prelude::{RegistryEntry, BuilderConfig, Leaf};
	///
	/// let builder_config = BuilderConfig::default();
	/// fn callback(reg_entry: &RegistryEntry, data: &[u8]) {
	///   println!("Processed Entry: {:?}. First Bytes: {:?}", reg_entry, &data[0..1])
	/// }
	///
	/// builder_config.callback(&mut callback);
	/// ```
	pub progress_callback: Option<&'a mut dyn FnMut(&RegistryEntry, &[u8])>,
}

impl<'a> std::fmt::Debug for BuilderConfig<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut f = f.debug_struct("BuilderConfig");

		f.field("magic", &self.magic);
		f.field("flags", &self.flags);
		f.field(
			"progress_callback",
			if self.progress_callback.is_some() {
				&"Some(&dyn Fn(id: &str, reg_entry: &RegistryEntry))"
			} else {
				&"None"
			},
		);

		#[cfg(feature = "crypto")]
		f.field("keypair", &self.signing_key);

		f.finish()
	}
}

// Helper functions
impl<'a> BuilderConfig<'a> {
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

	///```
	/// use vach::prelude::BuilderConfig;
	/// let config = BuilderConfig::default().magic(*b"DbAfh");
	///```
	pub fn magic(mut self, magic: [u8; 5]) -> BuilderConfig<'a> {
		self.magic = magic;
		self
	}

	///```
	/// use vach::prelude::{BuilderConfig, RegistryEntry, Leaf};
	///
	/// let mut callback = |entry: &RegistryEntry, _data: &[u8]| { println!("Number of bytes written: {}", entry.offset) };
	/// let config = BuilderConfig::default().callback(&mut callback);
	///```
	pub fn callback(mut self, callback: &'a mut dyn FnMut(&RegistryEntry, &[u8])) -> BuilderConfig<'a> {
		self.progress_callback = Some(callback);
		self
	}

	/// Read and parse a keypair from a stream of bytes
	#[cfg(feature = "crypto")]
	pub fn load_keypair<T: std::io::Read>(&mut self, handle: T) -> crate::global::error::InternalResult {
		crate::crypto_utils::read_keypair(handle).map(|kp| self.signing_key = Some(kp))
	}
}

impl<'a> Default for BuilderConfig<'a> {
	fn default() -> BuilderConfig<'a> {
		BuilderConfig {
			#[cfg(feature = "multithreaded")]
			num_threads: unsafe { NonZeroUsize::new_unchecked(4) },
			flags: Flags::default(),
			magic: *crate::DEFAULT_MAGIC,
			progress_callback: None,
			#[cfg(feature = "crypto")]
			signing_key: None,
		}
	}
}

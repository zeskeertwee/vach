use crate::global::{flags::Flags, result::InternalResult, reg_entry::RegistryEntry};
use std::io;
use ed25519_dalek as esdalek;
use std::fmt::Debug;

/// Allows for the customization of valid `vach` archives during their construction.
/// Such as custom `MAGIC`, custom `Header` flags and signing by providing a keypair.
pub struct BuilderConfig<'a> {
	/// Used to write a unique magic sequence into the write target.
	pub magic: [u8; crate::MAGIC_LENGTH],
	/// Flags to be written into the `Header` section of the write target.
	pub flags: Flags,
	/// An optional keypair. If a key is provided, then the write target will have signatures for tamper verification.
	pub keypair: Option<esdalek::Keypair>,
	/// An optional callback that is called every time a [Leaf](crate::builder::Leaf) finishes processing.
	/// The callback get passed to it: the leaf's id, the number of bytes written and the generated registry entry. Respectively.
	/// > **To avoid** the `implementation of "FnOnce" is not general enough` error consider adding types to the closure's parameters, as this is a type inference error. Rust somehow cannot infer enough information, [link](https://www.reddit.com/r/rust/comments/ntqu68/implementation_of_fnonce_is_not_general_enough/).
	///
	/// Usage:
	/// ```ignore
	/// let builder_config = BuilderConfig::new()
	/// ```
	pub progress_callback: Option<&'a dyn Fn(&str, usize, &RegistryEntry)>
}

impl<'a> Debug for BuilderConfig<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("BuilderConfig")
			.field("magic", &self.magic)
			.field("flags", &self.flags)
			.field("keypair", &self.keypair)
			.field(
				"progress_callback",
				if self.progress_callback.is_some() {
					&"dyn Fn(id: &str, glob_size: usize, reg_entry: &RegistryEntry)"
				} else {
					&"None"
				},
			)
			.finish()
	}
}

impl<'a> BuilderConfig<'a> {
	// Helper functions
	/// Setter for the `keypair` field
	pub fn keypair(mut self, keypair: esdalek::Keypair) -> Self {
		self.keypair = Some(keypair);
		self
	}
	/// Setter for the `flags` field
	///```
	/// use vach::prelude::{Flags, BuilderConfig};
	///
	/// let config = BuilderConfig::default().flags(Flags::empty());
	///```
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}

	/// Setter for the `magic` field
	///```
	/// use vach::prelude::BuilderConfig;
	/// let config = BuilderConfig::default().magic(*b"DbAfh");
	///```
	pub fn magic(mut self, magic: [u8; 5]) -> BuilderConfig<'a> {
		self.magic = magic;
		self
	}

	/// Setter for the `progress_callback` field
	///```
	/// use vach::prelude::{BuilderConfig, RegistryEntry};
	///
	/// let callback = |_: &str, byte_len: usize, _: &RegistryEntry| { println!("Number of bytes written: {}", byte_len) };
	/// let config = BuilderConfig::default().callback(&callback);
	///```
	pub fn callback(
		mut self, callback: &'a dyn Fn(&str, usize, &RegistryEntry),
	) -> BuilderConfig<'a> {
		self.progress_callback = Some(callback);
		self
	}

	// Keypair helpers
	/// Parses and stores a keypair from a source.
	/// ### Errors
	/// If the call to `::utils::read_keypair()` fails to parse the data from the handle
	pub fn load_keypair<T: io::Read>(&mut self, handle: T) -> InternalResult<()> {
		self.keypair = Some(crate::utils::read_keypair(handle)?);
		Ok(())
	}
}

impl<'a> Default for BuilderConfig<'a> {
	fn default() -> BuilderConfig<'a> {
		BuilderConfig {
			flags: Flags::default(),
			keypair: None,
			magic: *crate::DEFAULT_MAGIC,
			progress_callback: None
		}
	}
}

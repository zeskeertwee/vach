use crate::global::{flags::Flags, result::InternalResult};
use std::io;
use ed25519_dalek as esdalek;

/// Allows for the customization of valid `vach` archives during their construction.
/// Such as custom `MAGIC`, custom `Header` flags and signing by providing a keypair.
#[derive(Debug)]
pub struct BuilderConfig {
	/// Used to write a unique magic sequence into the write target.
	pub magic: [u8; crate::MAGIC_LENGTH],
	/// Flags to be written into the `Header` section of the write target.
	pub flags: Flags,
	/// An optional keypair. If a key is provided, then the write target will have signatures for tamper verification.
	pub keypair: Option<esdalek::Keypair>,
}

impl BuilderConfig {
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
	pub fn magic(mut self, magic: [u8; 5]) -> BuilderConfig {
		self.magic = magic;
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

impl Default for BuilderConfig {
	fn default() -> BuilderConfig {
		BuilderConfig {
			flags: Flags::default(),
			keypair: None,
			magic: *crate::DEFAULT_MAGIC,
		}
	}
}

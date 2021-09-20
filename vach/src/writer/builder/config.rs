use crate::global::types::Flags;
use std::io;
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct BuilderConfig {
	pub magic: [u8; crate::MAGIC_LENGTH],
	pub flags: Flags,
	pub keypair: Option<esdalek::Keypair>,
}

impl BuilderConfig {
	// Helper functions
	pub fn keypair(mut self, keypair: esdalek::Keypair) -> Self {
		self.keypair = Some(keypair);
		self
	}
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}
	pub fn magic(mut self, magic: [u8; 5]) -> BuilderConfig {
		self.magic = magic;
		self
	}

	// Keypair helpers
	pub fn load_keypair<T: io::Read>(&mut self, handle: T) -> anyhow::Result<()> {
		self.keypair = Some(crate::utils::read_keypair(handle)?);
		Ok(())
	}
}

impl Default for BuilderConfig {
	fn default() -> BuilderConfig {
		BuilderConfig {
			flags: Flags::default(),
			keypair: None,
			magic: *crate::DEFAULT_MAGIC
		}
	}
}

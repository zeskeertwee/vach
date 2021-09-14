use anyhow;
use super::resource::Resource;
use crate::global::{
	header::{Header, HeaderConfig},
	registry::{Registry, RegistryEntry},
};
use std::{
	io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
	str,
};
use ed25519_dalek as esdalek;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct Archive<T> {
	header: Header,
	registry: Registry,
	handle: T,
	key: Option<esdalek::PublicKey>,
}

impl Archive<Cursor<Vec<u8>>> {
	pub fn empty() -> Archive<Cursor<Vec<u8>>> {
		Archive {
			header: Header::default(),
			registry: Registry::empty(),
			handle: Cursor::new(Vec::new()),
			key: None,
		}
	}
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
	pub fn from_handle(handle: T) -> anyhow::Result<Archive<impl Seek + Read>> {
		Archive::with_config(handle, &HeaderConfig::default())
	}

	pub fn with_config(
		mut handle: T, config: &HeaderConfig,
	) -> anyhow::Result<Archive<impl Seek + Read>> {
		Archive::validate(&mut handle, config)?;

		let header = Header::from_handle(&mut handle)?;
		let registry = Registry::from_handle(&mut handle, &header, config.public_key.is_some())?;

		Ok(Archive {
			header,
			registry,
			handle: BufReader::new(handle),
			key: config.public_key,
		})
	}

	// Query functions
	pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
		self.registry.fetch(id, &mut self.handle, &self.key)
	}
	pub fn fetch_write(&mut self, id: &str, target: impl Write) -> anyhow::Result<()> {
		self.registry
			.fetch_write(id, &mut self.handle, &self.key, target)
	}
	pub fn fetch_entry(&mut self, id: &str) -> Option<&RegistryEntry> {
		self.registry.fetch_entry(id)
	}
	pub fn entries(&self) -> &HashMap<String, RegistryEntry> {
		&self.registry.entries
	}

	pub fn validate(handle: &mut T, config: &HeaderConfig) -> anyhow::Result<()> {
		handle.seek(SeekFrom::Start(0))?;

		// Validate magic
		let mut buffer = [0x72; HeaderConfig::MAGIC_LENGTH];
		handle.read_exact(&mut buffer)?;

		if buffer != config.magic {
			anyhow::bail!(format!(
				"Invalid magic found in archive: {}",
				str::from_utf8(&buffer)?
			));
		};

		// Jump the flags
		handle.seek(SeekFrom::Current(2))?;

		// Validate version
		let mut buffer = [0x72; HeaderConfig::VERSION_SIZE];
		handle.read_exact(&mut buffer)?;

		let archive_version = u16::from_le_bytes(buffer);
		if config.minimum_version > archive_version {
			anyhow::bail!(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum acceptable version: {}",
                archive_version, config.minimum_version
            ))
		};

		Ok(())
	}
}

impl Default for Archive<Cursor<Vec<u8>>> {
	fn default() -> Archive<Cursor<Vec<u8>>> {
		Archive::empty()
	}
}

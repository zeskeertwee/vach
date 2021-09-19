use anyhow;
use super::resource::Resource;
use crate::global::{
	header::{Header, HeaderConfig},
	registry::{Registry, RegistryEntry},
};
use std::{
	io::{BufReader, Cursor, Read, Seek, Write},
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
	#[inline]
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
		let header = Header::from_handle(&mut handle)?;
		Header::validate(&header, config)?;
		let registry = Registry::from_handle(&mut handle, &header, config.public_key.is_some())?;

		Ok(Archive {
			header,
			registry,
			handle: BufReader::new(handle),
			key: config.public_key,
		})
	}

	// Query functions
	#[inline]
	pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
		self.registry.fetch(id, &mut self.handle, &self.key)
	}
	#[inline]
	pub fn fetch_write(&mut self, id: &str, target: impl Write) -> anyhow::Result<()> {
		self.registry
			.fetch_write(id, &mut self.handle, &self.key, target)
	}
	#[inline]
	pub fn fetch_entry(&mut self, id: &str) -> Option<&RegistryEntry> {
		self.registry.fetch_entry(id)
	}
	#[inline]
	pub fn entries(&self) -> &HashMap<String, RegistryEntry> {
		&self.registry.entries
	}
}

impl Default for Archive<Cursor<Vec<u8>>> {
	fn default() -> Archive<Cursor<Vec<u8>>> {
		Archive::empty()
	}
}

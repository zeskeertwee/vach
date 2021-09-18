use anyhow;
use super::resource::Resource;
use crate::global::{
	header::{Header, HeaderConfig},
	reg_entry::{RegistryEntry},
	types::{FlagType},
};
use std::{
	io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write},
	str,
};
use ed25519_dalek::{self as esdalek, Verifier};
use lz4_flex as lz4;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct Archive<T> {
	header: Header,
	handle: T,
	key: Option<esdalek::PublicKey>,
	entries: HashMap<String, RegistryEntry>,
}

impl Archive<Cursor<Vec<u8>>> {
	#[inline(always)]
	pub fn empty() -> Archive<Cursor<Vec<u8>>> {
		Archive {
			header: Header::default(),
			handle: Cursor::new(Vec::new()),
			key: None,
			entries: HashMap::new()
		}
	}
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
	#[inline(always)]
	pub fn from_handle(handle: T) -> anyhow::Result<Archive<impl Seek + Read>> {
		Archive::with_config(handle, &HeaderConfig::default())
	}

	pub fn with_config(
		mut handle: T, config: &HeaderConfig,
	) -> anyhow::Result<Archive<impl Seek + Read>> {
		let header = Header::from_handle(&mut handle)?;
		Header::validate(&header, config)?;
		// Generate and store Registry Entries
		let mut entries = HashMap::new();
		for _ in 0..header.capacity {
			let (entry, id) = RegistryEntry::from_handle(&mut handle, config.public_key.is_some())?;
			entries.insert(id, entry);
		};

		Ok(Archive {
			header,
			handle: BufReader::new(handle),
			key: config.public_key,
			entries,
		})
	}

	// Query functions
	pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
		let mut buffer = Vec::new();
		let (flags, content_version) = self.fetch_write(id, &mut buffer)?;
		Ok(Resource{
			content_version,
			flags,
			data: buffer
		})
	}
	pub fn fetch_write(&mut self, id: &str, mut target: impl Write) -> anyhow::Result<(FlagType, u8)> {
		if let Some(entry) = self.fetch_entry(id) {
			let handle = &mut self.handle;
			handle.seek(SeekFrom::Start(entry.location))?;

			let mut take = handle.take(entry.offset);
			let mut buffer = Vec::new();
			take.read_to_end(&mut buffer)?;

			// The path is part of the signature, so you do not mess with the addressed data
			buffer.extend(id.as_bytes());

			// Validate signature
			if let Some(pub_key) = &self.key {
				if let Err(error) = pub_key.verify(&buffer, &entry.signature) {
					anyhow::bail!(format!(
						"({}): Invalid signature found for leaf with ID: {}",
						error, id
					))
				};
			};

			// Decompress
			if entry.flags.contains(FlagType::COMPRESSED) {
				io::copy(
					&mut lz4::frame::FrameDecoder::new(buffer.take(entry.offset)),
					&mut target,
				)?;
			} else {
				io::copy(&mut buffer.take(entry.offset), &mut target)?;
			};

			Ok((entry.flags, entry.content_version))
		} else {
			anyhow::bail!(format!("Resource not found: {}", id))
		}
	}
	pub fn fetch_entry(&mut self, id: &str) -> Option<RegistryEntry> {
		match self.entries.get(id) {
			 Some(entry) => { Some(entry.clone()) },
			 None => None,
		}
	}
	#[inline(always)]
	pub fn entries(&self) -> &HashMap<String, RegistryEntry> { &self.entries }
}

impl Default for Archive<Cursor<Vec<u8>>> {
	#[inline(always)]
	fn default() -> Archive<Cursor<Vec<u8>>> {
		Archive::empty()
	}
}

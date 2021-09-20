use anyhow;
use super::resource::Resource;
use crate::global::{
	header::{Header, HeaderConfig},
	reg_entry::{RegistryEntry},
	types::{Flags},
};
use std::{
	io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write},
	str,
};
use ed25519_dalek::{self as esdalek, Verifier};
use lz4_flex as lz4;
use hashbrown::HashMap;

/// A wrapper for loading data from archive sources.
/// It also provides query functions for fetching data and information about said data.
/// It is configurable and can be configured using the `HeaderConfig` struct.
#[derive(Debug)]
pub struct Archive<T> {
	header: Header,
	handle: T,
	key: Option<esdalek::PublicKey>,
	entries: HashMap<String, RegistryEntry>,
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
		}

		Ok(Archive {
			header,
			handle: BufReader::new(handle),
			key: config.public_key,
			entries,
		})
	}

	/// Fetch a `Resource` with the given `ID`.
	/// If the `ID` does not exist within the source, `None` is returned.
	pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
		let mut buffer = Vec::new();
		let (flags, content_version) = self.fetch_write(id, &mut buffer)?;
		Ok(Resource {
			content_version,
			flags,
			data: buffer,
		})
	}
	/// Fetch data with the given `ID` and write it directly into the given `target`.
	/// Returns a tuple containing the `Flags` and `content_version` of the data.
	pub fn fetch_write(&mut self, id: &str, mut target: impl Write) -> anyhow::Result<(Flags, u8)> {
		if let Some(entry) = self.fetch_entry(id) {
			let handle = &mut self.handle;
			handle.seek(SeekFrom::Start(entry.location))?;

			let mut take = handle.take(entry.offset);

			// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
			if let Some(pub_key) = &self.key {
				// Read  all the data into a buffer, then validate the signature
				let mut buffer = Vec::new();
				take.read_to_end(&mut buffer)?;

				// The ID is part of the signature, this prevents redirects d by mangling the registry entry
				buffer.extend(id.as_bytes());

				if let Err(error) = pub_key.verify(&buffer, &entry.signature) {
					anyhow::bail!(format!(
						"({}): Invalid signature found for leaf with ID: {}",
						error, id
					))
				};

				// Decompress
				if entry.flags.contains(Flags::COMPRESSED_FLAG) {
					io::copy(
						&mut lz4::frame::FrameDecoder::new(buffer.take(entry.offset)),
						&mut target,
					)?;
				} else {
					io::copy(&mut buffer.take(entry.offset), &mut target)?;
				};

				Ok((entry.flags, entry.content_version))
			} else {
				// Decompress
				if entry.flags.contains(Flags::COMPRESSED_FLAG) {
					io::copy(
						&mut lz4::frame::FrameDecoder::new(take),
						&mut target,
					)?;
				} else {
					io::copy(&mut take, &mut target)?;
				};

				Ok((entry.flags, entry.content_version))
			}
		} else {
			anyhow::bail!(format!("Resource not found: {}", id))
		}
	}
	/// Fetch an `RegistryEntry` from this `Archive`.
	/// This can be used for debugging, as the `RegistryEntry` holds information about some data within a source.
	/// If no data has the given `id`, then None is returned.
	pub fn fetch_entry(&mut self, id: &str) -> Option<RegistryEntry> {
		match self.entries.get(id) {
			Some(entry) => Some(entry.clone()),
			None => None,
		}
	}
	/// Returns a reference to the underlying `HashMap`. This hashmap stores `RegistryEntry` values and uses `String` keys
	#[inline(always)]
	pub fn entries(&self) -> &HashMap<String, RegistryEntry> {
		&self.entries
	}
}

impl Default for Archive<Cursor<Vec<u8>>> {
	#[inline(always)]
	fn default() -> Archive<Cursor<Vec<u8>>> {
		Archive {
			header: Header::default(),
			handle: Cursor::new(Vec::new()),
			key: None,
			entries: HashMap::new(),
		}
	}
}

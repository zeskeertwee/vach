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
/// It can be configured using the `HeaderConfig` struct.
#[derive(Debug)]
pub struct Archive<T> {
	header: Header,
	handle: T,
	key: Option<esdalek::PublicKey>,
	entries: HashMap<String, RegistryEntry>,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
	/// Load an `Archive` with the default settings from a `Read` target.
	/// The same as doing:
	/// ```ignore
	/// Archive::with_config(READ_HANDLE, &HeaderConfig::default())?;
	/// ```
	#[inline(always)]
	pub fn from_handle(handle: T) -> anyhow::Result<Archive<impl Seek + Read>> {
		Archive::with_config(handle, &HeaderConfig::default())
	}

	/// Given a read handle, this will read and parse the data into an `Archive` struct.
	/// Provide a refference to `HeaderConfig` and it will be used to validate the source and for further configuration.
	/// If parsing fails, an `Err()` is returned.
	pub fn with_config( mut handle: T, config: &HeaderConfig ) -> anyhow::Result<Archive<impl Seek + Read>> {
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
	/// If the `ID` does not exist within the source, `Err(---)` is returned.
	pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
		let mut buffer = Vec::new();
		let (flags, content_version, validated) = self.fetch_write(id, &mut buffer)?;

		Ok(Resource {
			content_version,
			flags,
			data: buffer,
			is_valid: validated
		})
	}

	/// Fetch data with the given `ID` and write it directly into the given `target: impl Read`.
	/// Returns a tuple containing the `Flags`, `content_version` and `is_valid`, ie validity, of the data.
	pub fn fetch_write<W: Write>(&mut self, id: &str, mut target: W) -> anyhow::Result<(Flags, u8, bool)> {
		if let Some(entry) = self.fetch_entry(id) {
			let handle = &mut self.handle;
			let mut is_valid = false;
			handle.seek(SeekFrom::Start(entry.location))?;

			let mut take = handle.take(entry.offset);

			// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
			if let Some(pub_key) = &self.key {
				// Read  all the data into a buffer, then validate the signature
				let mut buffer = Vec::new();
				take.read_to_end(&mut buffer)?;

				// The ID is part of the signature, this prevents redirects d by mangling the registry entry
				buffer.extend(id.as_bytes());

				// If there is an error the data is flagged as invalid
				is_valid = pub_key.verify(&buffer, &entry.signature).is_ok();

				// Decompress
				if entry.flags.contains(Flags::COMPRESSED_FLAG) {
					io::copy(
						&mut lz4::frame::FrameDecoder::new(buffer.take(entry.offset)),
						&mut target,
					)?;
				} else {
					io::copy(&mut buffer.take(entry.offset), &mut target)?;
				};

				Ok((entry.flags, entry.content_version, is_valid))
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

				Ok((entry.flags, entry.content_version, is_valid))
			}
		} else {
			anyhow::bail!(format!("Resource not found: {}", id))
		}
	}
	/// Fetch a `RegistryEntry` from this `Archive`.
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

use std::{
	str,
	io::{self, BufReader, Read, Seek, SeekFrom, Write},
	collections::HashMap,
};

use super::resource::Resource;
use crate::{
	global::{
		edcryptor::EDCryptor,
		error::InternalError,
		flags::Flags,
		header::{Header, HeaderConfig},
		reg_entry::RegistryEntry,
		result::InternalResult,
	},
};

use ed25519_dalek as esdalek;
use lz4_flex as lz4;

/// A wrapper for loading data from archive sources.
/// It also provides query functions for fetching `Resources` and `RegistryEntry`s.
/// It can be customized with the `HeaderConfig` struct.
/// Buffers all calls to the underlying handle with `BufReader`, so avoid passing in a buffered handle.
/// > **A word of advice:** Since `Archive` takes in a `impl io::Seek` (Seekable), handle. Make sure the `stream_position` is at the right location to avoid hair-splitting bugs.
#[derive(Debug)]
pub struct Archive<T> {
	header: Header,
	handle: T,
	key: Option<esdalek::PublicKey>,
	entries: HashMap<String, RegistryEntry>,
	decryptor: Option<EDCryptor>,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
	/// Load an `Archive` with the default settings from a source.
	/// The same as doing:
	/// ```ignore
	/// Archive::with_config(HANDLE, &HeaderConfig::default())?;
	/// ```
	/// ### Errors
	/// - If the internal call to `Archive::with_config(-)` returns an error
	#[inline(always)]
	pub fn from_handle(handle: T) -> InternalResult<Archive<impl Seek + Read>> {
		Archive::with_config(handle, &HeaderConfig::default())
	}

	/// Given a read handle, this will read and parse the data into an `Archive` struct.
	/// Provide a reference to `HeaderConfig` and it will be used to validate the source and for further configuration.
	/// ### Errors
	///  - If parsing fails, an `Err(-)` is returned.
	///  - The archive fails to validate
	///  - `io` errors
	///  - If any `ID`s are not valid UTF-8
	pub fn with_config(
		mut handle: T, config: &HeaderConfig,
	) -> InternalResult<Archive<impl Seek + Read>> {
		let header = Header::from_handle(&mut handle)?;
		Header::validate(&header, config)?;

		// Generate and store Registry EntriesF
		let mut use_decryption = false;
		let mut entries = HashMap::new();

		for _ in 0..header.capacity {
			let (entry, id) = RegistryEntry::from_handle(&mut handle)?;
			if entry.flags.contains(Flags::ENCRYPTED_FLAG) && !use_decryption {
				use_decryption = true;
			};
			entries.insert(id, entry);
		}

		// Build decryptor
		let mut decryptor = None;

		if use_decryption {
			if let Some(pk) = config.public_key {
				decryptor = Some(EDCryptor::new(&pk, config.magic))
			}
		}

		Ok(Archive {
			header,
			handle: BufReader::new(handle),
			key: config.public_key,
			entries,
			decryptor,
		})
	}

	/// Fetch a `Resource` with the given `ID`.
	/// If the `ID` does not exist within the source, `Err(---)` is returned.
	/// ### Errors:
	///  - If the internal call to `Archive::fetch_write()` returns an Error, then it is hoisted and returned
	pub fn fetch(&mut self, id: &str) -> InternalResult<Resource> {
		let mut buffer = Vec::new();
		let (flags, content_version, validated) = self.fetch_write(id, &mut buffer)?;

		Ok(Resource {
			content_version,
			flags,
			data: buffer,
			secured: validated,
		})
	}

	/// Fetch data with the given `ID` and write it directly into the given `target: impl Read`.
	/// Returns a tuple containing the `Flags`, `content_version` and `secure`, ie validity, of the data.
	/// ### Errors
	///  - If no leaf with the specified `ID` exists
	///  - Any `io::Seek(-)` errors
	///  - Other `io` related errors
	///  - Cyclic linked leaf errors
	pub fn fetch_write<W: Write>(
		&mut self, id: &str, mut target: W,
	) -> InternalResult<(Flags, u8, bool)> {
		if let Some(entry) = self.fetch_entry(id) {
			let handle = &mut self.handle;
			let mut is_secure = false;

			// BUG: MAJOR SLOW-DOWN HERE; `io::Seek` is a very expensive operation, potentially avoids an expensive Seek operation
			handle.seek(SeekFrom::Start(entry.location))?;

			let mut raw = vec![];
			let raw_size = handle.take(entry.offset).read_to_end(&mut raw)?;

			// Signature validation
			// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
			if let Some(pub_key) = &self.key {
				// If there is an error the data is flagged as invalid
				raw.extend(id.as_bytes());
				if let Some(signature) = entry.signature {
					is_secure = pub_key.verify_strict(&raw, &signature).is_ok();
				}

				raw.truncate(raw_size);
			}

			// Add read layers
			// 1: Decryption layer
			if entry.flags.contains(Flags::ENCRYPTED_FLAG) {
				if let Some(dx) = &self.decryptor {
					raw = match dx.decrypt(&raw) {
						Ok(bytes) => bytes,
						Err(err) => {
							return Err(InternalError::CryptoError(format!(
								"Unable to decrypt resource: {}. Error: {}",
								id.to_string(),
								err
							)));
						}
					};
				} else {
					return Err(InternalError::NoKeypairError(format!("Encountered encrypted Leaf: {} but no decryption key(public key) was provided", id)));
				}
			}
			// 2: Decompression layer
			if entry.flags.contains(Flags::COMPRESSED_FLAG) {
				let mut rdr = lz4::frame::FrameDecoder::new(raw.as_slice());
				let mut buffer = vec![];
				rdr.read_to_end(&mut buffer)?;

				raw = buffer;
			};
			// 3: Deref layer, dereferences link leafs
			// NOTE: This may break the upcoming cache functionality in `vf`. So `vf` must check for linked `Leaf`s
			if entry.flags.contains(Flags::LINK_FLAG) {
				let mut target_id = String::new();
				raw.as_slice().read_to_string(&mut target_id)?;

				// Prevent cyclic hell
				match self.fetch_entry(target_id.as_str()) {
					Some(alias) if alias.flags.contains(Flags::LINK_FLAG) => {
						return Err(InternalError::CyclicLinkReferenceError(
							id.to_string(),
							target_id.to_string(),
						));
					}
					Some(_) => return self.fetch_write(&target_id, target),
					None => {
						return Err(InternalError::MissingResourceError(format!(
						"The linking Leaf: {} exists. However the Leaf it links to: {}, does not exist",
						id, target_id
					)))
					}
				};
			};

			io::copy(&mut raw.as_slice(), &mut target)?;

			Ok((entry.flags, entry.content_version, is_secure))
		} else {
			return Err(InternalError::MissingResourceError(format!(
				"Resource not found: {}",
				id
			)));
		}
	}

	/// Fetch a `RegistryEntry` from this `Archive`.
	/// This can be used for debugging, as the `RegistryEntry` holds information about some data within a source.
	/// ### `None` case:
	/// If no entry with the given ID exists then None is returned.
	pub fn fetch_entry(&mut self, id: &str) -> Option<RegistryEntry> {
		match self.entries.get(id) {
			Some(entry) => Some(entry.clone()),
			None => None,
		}
	}

	/// Returns a reference to the underlying `HashMap`. This hashmap stores `RegistryEntry` values and uses `String` keys.
	#[inline(always)]
	pub fn entries(&self) -> &HashMap<String, RegistryEntry> {
		&self.entries
	}

	/// Global flags extracted from the `Header` section of the source
	#[inline(always)]
	pub fn flags(&self) -> &Flags {
		&self.header.flags
	}
}

impl Default for Archive<&[u8]> {
	#[inline(always)]
	fn default() -> Archive<&'static [u8]> {
		Archive {
			header: Header::default(),
			handle: &[],
			key: None,
			entries: HashMap::new(),
			decryptor: None,
		}
	}
}

use std::{
	str,
	io::{self, Read, Seek, SeekFrom, Write},
	collections::HashMap,
};

use parking_lot::Mutex;

use super::resource::Resource;
use crate::{
	global::{
		error::InternalError,
		flags::Flags,
		header::{Header, ArchiveConfig},
		reg_entry::RegistryEntry,
		result::InternalResult,
	},
};

#[cfg(feature = "crypto")]
use crate::crypto;

#[cfg(feature = "compression")]
use crate::global::compressor::{Compressor, CompressionAlgorithm};

/// A wrapper for loading data from archive sources.
/// It also provides query functions for fetching [`Resource`]s and [`RegistryEntry`]s.
/// Specify custom `MAGIC` or provide a `PublicKey` for decrypting and authenticating resources using [`ArchiveConfig`].
/// > **A word of advice:**
/// > Does not buffer the underlying handle, so consider wrapping `handle` in a `BufReader`
#[derive(Debug)]
pub struct Archive<T> {
	/// Wrapping `handle` in a Mutex means that we only ever lock when reading from the underlying buffer, thus ensuring maximum performance across threads
	/// Since all the other work is done per thread
	handle: Mutex<T>,

	// Archive metadata
	header: Header,
	entries: HashMap<String, RegistryEntry>,

	// Optional parts
	#[cfg(feature = "crypto")]
	decryptor: Option<crypto::Encryptor>,
	#[cfg(feature = "crypto")]
	key: Option<crypto::PublicKey>,
}

impl<T> std::fmt::Display for Archive<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let bytes = self
			.entries
			.iter()
			.map(|(_, entry)| entry.offset)
			.reduce(|a, b| a + b)
			.unwrap_or(0);

		write!(
			f,
			"[Archive Header] Version: {}, Magic: {:?}, Members: {}, Compressed Size: {bytes}B, Header-Flags: <{:#x} : {:#016b}>",
			self.header.arch_version,
			self.header.magic,
			self.entries.len(),
			self.header.flags.bits,
			self.header.flags.bits,
		)
	}
}

impl<T> Archive<T> {
	/// Consume the [Archive] and return the underlying handle
	pub fn into_inner(self) -> T {
		self.handle.into_inner()
	}

	// Decompress and|or decrypt the data
	#[inline(never)]
	fn process(&self, values: (&RegistryEntry, &str, Vec<u8>)) -> InternalResult<(Vec<u8>, bool)> {
		/* Literally the hottest function in the block (????) */

		// buffer_a originally contains the raw data
		let (entry, id, mut raw) = values;
		let mut decrypted = None;
		let mut is_secure = false;

		// Signature validation
		// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
		#[cfg(feature = "crypto")]
		if let Some(pk) = self.key {
			let raw_size = raw.len();

			// If there is an error the data is flagged as invalid
			if let Some(signature) = entry.signature {
				raw.extend_from_slice(id.as_bytes());
				is_secure = pk.verify_strict(&raw, &signature).is_ok();
			}

			raw.truncate(raw_size);
		}

		// Add read layers
		// 1: Decryption layer
		if entry.flags.contains(Flags::ENCRYPTED_FLAG) {
			#[cfg(feature = "crypto")]
			match self.decryptor.as_ref() {
				Some(dc) => {
					decrypted = Some(dc.decrypt(&raw)?);
				},
				None => return Err(InternalError::NoKeypairError),
			}

			#[cfg(not(feature = "crypto"))]
			{
				return Err(InternalError::MissingFeatureError("crypto"));
			}
		}

		// 2: Decompression layer
		if entry.flags.contains(Flags::COMPRESSED_FLAG) {
			#[cfg(feature = "compression")]
			{
				let (source, mut target) = match decrypted {
					// data was decrypted and stored.
					Some(vec) => {
						raw.clear();
						(vec, raw)
					},
					// data was not decrypted nor stored.
					None => {
						let capacity = raw.len();
						(raw, Vec::with_capacity(capacity))
					},
				};

				if entry.flags.contains(Flags::LZ4_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::LZ4, &mut target)?
				} else if entry.flags.contains(Flags::BROTLI_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::Brotli(0), &mut target)?
				} else if entry.flags.contains(Flags::SNAPPY_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::Snappy, &mut target)?
				} else {
					return InternalResult::Err(InternalError::OtherError(
						format!("Unable to determine the compression algorithm used for entry with ID: {id}").into(),
					));
				};

				Ok((target, is_secure))
			}

			#[cfg(not(feature = "compression"))]
			Err(InternalError::MissingFeatureError("compression"))
		} else {
			match decrypted {
				Some(decrypted) => Ok((decrypted, is_secure)),
				None => Ok((raw, is_secure)),
			}
		}
	}
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T> Archive<T>
where
	T: Seek + Read,
{
	/// Load an [`Archive`] with the default settings from a source.
	/// The same as doing:
	/// ```ignore
	/// Archive::with_config(HANDLE, &ArchiveConfig::default())?;
	/// ```
	/// ### Errors
	/// - If the internal call to `Archive::with_config(-)` returns an error
	#[inline(always)]
	pub fn from_handle(handle: T) -> InternalResult<Archive<T>> {
		Archive::with_config(handle, &ArchiveConfig::default())
	}

	/// Given a read handle, this will read and parse the data into an [`Archive`] struct.
	/// Pass a reference to [ArchiveConfig] and it will be used to validate the source and for further configuration.
	/// ### Errors
	///  - If parsing fails, an `Err(---)` is returned.
	///  - The archive fails to validate
	///  - `io` errors
	///  - If any `ID`s are not valid UTF-8
	pub fn with_config(mut handle: T, config: &ArchiveConfig) -> InternalResult<Archive<T>> {
		// Start reading from the start of the input
		handle.seek(SeekFrom::Start(0))?;

		let header = Header::from_handle(&mut handle)?;
		Header::validate(config, &header)?;

		// Generate and store Registry Entries
		let mut entries = HashMap::with_capacity(header.capacity as usize);

		// Construct entries map
		for _ in 0..header.capacity {
			let (entry, id) = RegistryEntry::from_handle(&mut handle)?;
			entries.insert(id, entry);
		}

		#[cfg(feature = "crypto")]
		{
			// Build decryptor
			let use_decryption = entries
				.iter()
				.any(|(_, entry)| entry.flags.contains(Flags::ENCRYPTED_FLAG));

			// Errors where no decryptor has been instantiated will be returned once a fetch is made to an encrypted resource
			let mut decryptor = None;
			if use_decryption {
				if let Some(pk) = config.public_key {
					decryptor = Some(crypto::Encryptor::new(&pk, config.magic))
				}
			}

			Ok(Archive {
				header,
				handle: Mutex::new(handle),
				key: config.public_key,
				entries,
				decryptor,
			})
		}

		#[cfg(not(feature = "crypto"))]
		{
			Ok(Archive {
				header,
				handle: Mutex::new(handle),
				entries,
			})
		}
	}

	pub(crate) fn fetch_raw(&self, entry: &RegistryEntry) -> InternalResult<Vec<u8>> {
		let mut buffer = Vec::with_capacity(entry.offset as usize + 64);

		let mut guard = self.handle.lock();
		guard.seek(SeekFrom::Start(entry.location))?;

		let mut take = guard.by_ref().take(entry.offset);
		take.read_to_end(&mut buffer)?;

		Ok(buffer)
	}

	/// Fetch a [`RegistryEntry`] from this [`Archive`].
	/// This can be used for debugging, as the [`RegistryEntry`] holds information on data with the adjacent ID.
	pub fn fetch_entry(&self, id: impl AsRef<str>) -> Option<RegistryEntry> {
		self.entries.get(id.as_ref()).cloned()
	}

	/// Returns an immutable reference to the underlying [`HashMap`]. This hashmap stores [`RegistryEntry`] values and uses `String` keys.
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

impl<T> Archive<T>
where
	T: Read + Seek,
{
	/// Fetch a [`Resource`] with the given `ID`.
	/// If the `ID` does not exist within the source, [`InternalError::MissingResourceError`] is returned.
	pub fn fetch(&self, id: impl AsRef<str>) -> InternalResult<Resource> {
		// The reason for this function's unnecessary complexity is it uses the provided functions independently, thus preventing an unnecessary allocation [MAYBE TOO MUCH?]
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = self.fetch_raw(&entry)?;

			// Prepare contextual variables
			let independent = (&entry, id.as_ref(), raw);

			// Decompress and|or decrypt the data
			let (buffer, is_secure) = self.process(independent)?;

			Ok(Resource {
				content_version: entry.content_version,
				flags: entry.flags,
				data: buffer,
				authenticated: is_secure,
			})
		} else {
			return Err(InternalError::MissingResourceError(id.as_ref().to_string()));
		}
	}

	/// Fetch data with the given `ID` and write it directly into the given `target: impl Read`.
	/// Returns a tuple containing the `Flags`, `content_version` and `authenticity` (boolean) of the data.
	/// If no leaf with the specified `ID` exists, [`InternalError::MissingResourceError`] is returned.
	pub fn fetch_write(&self, id: impl AsRef<str>, target: &mut dyn Write) -> InternalResult<(Flags, u8, bool)> {
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = self.fetch_raw(&entry)?;

			// Prepare contextual variables
			let independent = (&entry, id.as_ref(), raw);

			// Decompress and|or decrypt the data
			let (buffer, is_secure) = self.process(independent)?;

			io::copy(&mut buffer.as_slice(), target)?;
			Ok((entry.flags, entry.content_version, is_secure))
		} else {
			return Err(InternalError::MissingResourceError(id.as_ref().to_string()));
		}
	}
}

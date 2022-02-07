use std::{
	str,
	io::{self, Read, Seek, SeekFrom, Write},
	collections::HashMap,
	sync::{Arc, Mutex},
};

use super::resource::Resource;
use crate::{
	global::{
		edcryptor::Encryptor,
		error::InternalError,
		flags::Flags,
		header::{Header, HeaderConfig},
		reg_entry::RegistryEntry,
		result::InternalResult,
	},
};

#[cfg(feature = "compression")]
use crate::global::compressor::{Compressor, CompressionAlgorithm};

use ed25519_dalek as esdalek;

/// A wrapper for loading data from archive sources.
/// It also provides query functions for fetching `Resources` and [`RegistryEntry`]s.
/// It can be customized with the `HeaderConfig` struct.
/// > **A word of advice:**
/// > Does not buffer the underlying handle, so consider wrapping `handle` in a `BufReader`
pub struct Archive<T> {
	header: Header,
	handle: Arc<Mutex<T>>,
	decryptor: Option<Encryptor>,
	key: Option<esdalek::PublicKey>,
	entries: HashMap<String, RegistryEntry>,
}

impl<T> std::fmt::Debug for Archive<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Archive")
			.field("header", &self.header)
			.field("decryptor", &self.decryptor)
			.field("key", &self.key)
			.field("entries", &self.entries)
			.finish()
	}
}

impl<T> Archive<T> {
	/// Consume the [Archive] and return the underlying handle
	pub fn into_inner(self) -> InternalResult<T> {
		match Arc::try_unwrap(self.handle) {
			Ok(mutex) => match mutex.into_inner() {
				Ok(inner) => Ok(inner),
				Err(err) => Err(InternalError::SyncError(format!(
					"Trying to consume a poisoned mutex {}",
					err
				))),
			},
			Err(_) => Err(InternalError::SyncError(
				"Cannot consume this archive as other copy-references (ARC) to it exist".to_string(),
			)),
		}
	}

	/// Helps in parallelized `Resource` fetching
	#[inline(never)]
	fn process_raw(
		dependencies: (&Option<Encryptor>, &Option<esdalek::PublicKey>), independent: (&RegistryEntry, &str, Vec<u8>),
	) -> InternalResult<(Vec<u8>, bool)> {
		/* Literally the hottest function in the block (🕶) */

		let (entry, id, mut raw) = independent;
		let (decryptor, key) = dependencies;
		let mut is_secure = false;

		// Signature validation
		// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
		{
			if let Some(pk) = key {
				let raw_size = raw.len();

				// If there is an error the data is flagged as invalid
				raw.extend(id.as_bytes());
				if let Some(signature) = entry.signature {
					is_secure = pk.verify_strict(&raw, &signature).is_ok();
				}

				raw.truncate(raw_size);
			}
		}

		// Add read layers
		// 1: Decryption layer
		if entry.flags.contains(Flags::ENCRYPTED_FLAG) {
			match decryptor {
				Some(dc) => {
					raw = match dc.decrypt(&raw) {
						Ok(bytes) => bytes,
						Err(err) => {
							return Err(InternalError::CryptoError(format!(
								"Unable to decrypt resource: {}. Error: {}",
								id, err
							)));
						}
					};
				}
				None => {
					return Err(InternalError::NoKeypairError(format!(
						"Encountered encrypted Resource: {} but no decryption key(public key) was provided",
						id
					)))
				}
			}
		}

		// 2: Decompression layer
		#[cfg(feature = "compression")]
		if entry.flags.contains(Flags::COMPRESSED_FLAG) {
			let mut buffer = vec![];

			if entry.flags.contains(Flags::LZ4_COMPRESSED) {
				Compressor::new(raw.as_slice()).decompress(CompressionAlgorithm::LZ4, &mut buffer)?
			} else if entry.flags.contains(Flags::BROTLI_COMPRESSED) {
				Compressor::new(raw.as_slice()).decompress(CompressionAlgorithm::Brotli(0), &mut buffer)?
			} else if entry.flags.contains(Flags::SNAPPY_COMPRESSED) {
				Compressor::new(raw.as_slice()).decompress(CompressionAlgorithm::Snappy, &mut buffer)?
			} else {
				return InternalResult::Err(InternalError::DeCompressionError(
					"Unspecified compression algorithm bits".to_string(),
				));
			};

			raw = buffer
		};

		let mut buffer = vec![];
		raw.as_slice().read_to_end(&mut buffer)?;

		Ok((buffer, is_secure))
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
	/// Archive::with_config(HANDLE, &HeaderConfig::default())?;
	/// ```
	/// ### Errors
	/// - If the internal call to `Archive::with_config(-)` returns an error
	#[inline(always)]
	pub fn from_handle(handle: T) -> InternalResult<Archive<T>> {
		Archive::with_config(handle, &HeaderConfig::default())
	}

	/// Given a read handle, this will read and parse the data into an [`Archive`] struct.
	/// Pass a reference to `HeaderConfig` and it will be used to validate the source and for further configuration.
	/// ### Errors
	///  - If parsing fails, an `Err(---)` is returned.
	///  - The archive fails to validate
	///  - `io` errors
	///  - If any `ID`s are not valid UTF-8
	pub fn with_config(mut handle: T, config: &HeaderConfig) -> InternalResult<Archive<T>> {
		// Start reading from the start of the input
		handle.seek(SeekFrom::Start(0))?;

		let header = Header::from_handle(&mut handle)?;
		Header::validate(&header, config)?;

		// Generate and store Registry Entries
		let mut entries = HashMap::new();

		// Construct entries map
		for _ in 0..header.capacity {
			let (entry, id) = RegistryEntry::from_handle(&mut handle)?;
			entries.insert(id, entry);
		}

		// Build decryptor
		let use_decryption = entries
			.iter()
			.any(|(_, entry)| entry.flags.contains(Flags::ENCRYPTED_FLAG));

		// Errors where no decryptor has been instantiated will be returned once a fetch is made to an encrypted resource
		let mut decryptor = None;
		if use_decryption {
			if let Some(pk) = config.public_key {
				decryptor = Some(Encryptor::new(&pk, config.magic))
			}
		}

		Ok(Archive {
			header,
			handle: Arc::new(Mutex::new(handle)),
			key: config.public_key,
			entries,
			decryptor,
		})
	}

	#[inline(always)]
	pub(crate) fn fetch_raw(&self, entry: &RegistryEntry) -> InternalResult<Vec<u8>> {
		{
			let mut guard = match self.handle.lock() {
				Ok(guard) => guard,
				Err(_) => {
					return Err(InternalError::SyncError(
						"The Mutex in this Archive has been poisoned, an error occured somewhere".to_string(),
					))
				}
			};

			guard.seek(SeekFrom::Start(entry.location))?;
		}

		let offset = entry.offset as usize;
		let mut raw = Vec::with_capacity(offset);

		// This is ok since we never **read** from the vector
		#[allow(clippy::uninit_vec)]
		unsafe {
			raw.set_len(offset);
		}

		{
			let mut guard = match self.handle.lock() {
				Ok(guard) => guard,
				Err(_) => {
					return Err(InternalError::SyncError(
						"The Mutex in this Archive has been poisoned, an error occured somewhere".to_string(),
					))
				}
			};

			guard.read_exact(raw.as_mut_slice())?;
		}

		Ok(raw)
	}

	/// Fetch a [`RegistryEntry`] from this [`Archive`].
	/// This can be used for debugging, as the [`RegistryEntry`] holds information about some data within a source.
	/// ### `None` case:
	/// If no entry with the given ID exists then `None` is returned.
	pub fn fetch_entry(&self, id: &str) -> Option<RegistryEntry> {
		match self.entries.get(id) {
			Some(entry) => Some(entry.clone()),
			None => None,
		}
	}

	/// Returns a reference to the underlying [`HashMap`]. This hashmap stores [`RegistryEntry`] values and uses `String` keys.
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
	/// If the `ID` does not exist within the source, `Err(---)` is returned.
	/// ### Errors:
	///  - If the internal call to `Archive::fetch_write()` returns an Error, then it is hoisted and returned
	pub fn fetch(&self, id: &str) -> InternalResult<Resource> {
		// The reason for this function's unnecessary complexity is it uses the provided functions independently, thus preventing an unnecessary allocation [MAYBE TOO MUCH?]
		let mut buffer = Vec::new();
		self.fetch_write(id, &mut buffer)?;

		if let Some(entry) = self.fetch_entry(id) {
			let raw = self.fetch_raw(&entry)?;

			// Prepare contextual variables
			let independent = (&entry, id, raw);
			let dependencies = (&self.decryptor, &self.key);

			let (buffer, is_secure) = Archive::<T>::process_raw(dependencies, independent)?;

			Ok(Resource {
				content_version: entry.content_version,
				flags: entry.flags,
				data: buffer,
				secured: is_secure,
			})
		} else {
			#[rustfmt::skip]
			return Err(InternalError::MissingResourceError(format!( "Resource not found: {}", id )));
		}
	}

	/// Fetch data with the given `ID` and write it directly into the given `target: impl Read`.
	/// Returns a tuple containing the `Flags`, `content_version` and `authenticity` (boolean) of the data.
	/// ### Errors
	///  - If no leaf with the specified `ID` exists
	///  - Any `io::Seek(-)` errors
	///  - Other `io` related errors
	pub fn fetch_write<W: Write>(&self, id: &str, mut target: W) -> InternalResult<(Flags, u8, bool)> {
		if let Some(entry) = self.fetch_entry(id) {
			let raw = self.fetch_raw(&entry)?;

			// Prepare contextual variables
			let independent = (&entry, id, raw);
			let dependencies = (&self.decryptor, &self.key);

			let (buffer, is_secure) = Archive::<T>::process_raw(dependencies, independent)?;

			io::copy(&mut buffer.as_slice(), &mut target)?;
			Ok((entry.flags, entry.content_version, is_secure))
		} else {
			#[rustfmt::skip]
			return Err(InternalError::MissingResourceError(format!( "Resource not found: {}", id )));
		}
	}
}

#[cfg(feature = "multithreaded")]
impl<T> Archive<T>
where
	T: Read + Seek + Send + Sync,
{
	/// Retrieves several resources in parallel. This is much faster than calling `Archive::fetch(---)` in a loop as it utilizes abstracted functionality.
	/// This function is only available with the `multithreaded` feature. Use `Archive::fetch(---)` | `Archive::fetch_write(---)` in your own loop construct otherwise
	pub fn fetch_batch<'a, I: Iterator<Item = S> + Send + Sync, S: Send + Sync + Into<&'a str>>(
		&mut self, items: I,
	) -> InternalResult<HashMap<String, InternalResult<Resource>>> {
		use rayon::prelude::*;

		let mut processed = HashMap::new();
		let (sender, receiver) = crossbeam_channel::unbounded();

		items.par_bridge().try_for_each(|id| -> InternalResult<()> {
			let id = id.into();
			let resource = self.fetch(id);

			let string = id.to_string();
			if let Err(err) = sender.send((string, resource)) {
				Err(InternalError::SyncError(format!(
					"Unable to send data over channel {}",
					err
				)))
			} else {
				Ok(())
			}
		})?;

		receiver.try_iter().for_each(|(id, res)| {
			processed.insert(id, res);
		});

		Ok(processed)
	}
}

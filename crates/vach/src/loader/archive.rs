use std::{
	collections::HashMap,
	io::{Read, Seek, SeekFrom},
	ops::DerefMut,
	str,
	sync::{Arc, Mutex},
};

use super::resource::Resource;
use crate::global::{error::*, flags::Flags, header::Header, reg_entry::RegistryEntry};

#[cfg(feature = "crypto")]
use crate::crypto;

#[cfg(feature = "compression")]
use crate::global::compressor::*;

/// Parses an Archive from a read handle.
/// > Wraps handle in a [`Mutex`] internally for shared access, use [`fetch_mut`](Archive::fetch_mut) for lock-free access.
#[derive(Debug)]
pub struct Archive<T> {
	/// Wrapping `handle` in a Mutex means that we only ever lock when reading from the underlying buffer, thus ensuring maximum performance across threads
	/// Since all other work is done per thread
	handle: Mutex<T>,

	// Registry Data
	header: Header,
	entries: HashMap<Arc<str>, RegistryEntry>,

	// Optional parts
	#[cfg(feature = "crypto")]
	decryptor: Option<crypto::Encryptor>,
	#[cfg(feature = "crypto")]
	key: Option<crypto::VerifyingKey>,
}

impl<T> std::fmt::Display for Archive<T> {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		let bytes = self.entries.values().map(|re| re.offset).sum::<u64>();

		write!(
			f,
			"[Archive Header] Version: {}, Members: {}, Compressed Size: {bytes}B, Header-Flags: <{:#x} : {:#016b}>",
			self.header.version,
			self.entries.len(),
			self.header.flags.bits,
			self.header.flags.bits,
		)
	}
}

impl<T> Archive<T> {
	/// Consume the [`Archive`] and return the underlying source. Only valid if internal [`Mutex`] isn't poisoned
	pub fn into_inner(self) -> Result<T, std::sync::PoisonError<T>> {
		self.handle.into_inner()
	}

	// Decompress and|or Decrypt some data
	#[inline(never)]
	fn process(
		&self,
		entry: &RegistryEntry,
		mut raw: Vec<u8>,
	) -> InternalResult<(Vec<u8>, bool)> {
		/* Literally the hottest function in the block (🕶) */

		// buffer_a originally contains the raw data
		let mut decrypted = None;
		let mut verified = false;

		// Signature validation
		// Validate signature only if a public key is present
		#[cfg(feature = "crypto")]
		if let Some(pk) = self.key {
			// If there is an error the data is flagged as invalid
			if let Some(signature) = entry.signature {
				let id_bytes = entry.id.as_bytes();
				raw.extend_from_slice(id_bytes);

				verified = pk.verify_strict(&raw, &signature).is_ok();
				raw.truncate(raw.len() - id_bytes.len());
			}
		}

		// 1: Decryption layer
		if entry.flags.contains(Flags::ENCRYPTED_FLAG) {
			#[cfg(feature = "crypto")]
			match self.decryptor.as_ref() {
				Some(dc) => match entry.nonce.as_ref() {
					Some(n) => decrypted = Some(dc.decrypt(&raw, n)?),
					None => return Err(InternalError::OtherError(format!("Entry {} is flagged as encrypted but doesn't contain a nonce", entry.id).into())),
				},
				None => return Err(InternalError::NoKeypairError),
			}

			#[cfg(not(feature = "crypto"))]
			return Err(InternalError::MissingFeatureError("crypto"));
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
						let capacity = raw.capacity();
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
					return InternalResult::Err(InternalError::OtherError(format!("Unable to determine the compression algorithm used for entry: {}", entry).into()));
				};

				Ok((target, verified))
			}

			#[cfg(not(feature = "compression"))]
			Err(InternalError::MissingFeatureError("compression"))
		} else {
			match decrypted {
				Some(decrypted) => Ok((decrypted, verified)),
				None => Ok((raw, verified)),
			}
		}
	}
}

impl<T> Archive<T>
where
	T: Seek + Read,
{
	/// Parses an [`Archive`] from the given source
	pub fn new(mut handle: T) -> InternalResult<Archive<T>> {
		// Start reading from the start of the input
		handle.seek(SeekFrom::Start(0))?;

		let header = Header::from_handle(&mut handle)?;
		header.validate()?;

		// Generate and store Registry Entries
		let mut entries = HashMap::new();

		// Construct entries map
		for _ in 0..header.capacity {
			let entry = RegistryEntry::from_handle(&mut handle)?;
			entries.insert(entry.id.clone(), entry);
		}

		let archive = Archive {
			header,
			handle: Mutex::new(handle),
			entries,

			#[cfg(feature = "crypto")]
			key: None,
			#[cfg(feature = "crypto")]
			decryptor: None,
		};

		Ok(archive)
	}

	/// Parse an [`Archive`], with an optional [`VerifyingKey`](crypto::VerifyingKey).
	#[cfg(feature = "crypto")]
	pub fn with_key(
		mut handle: T,
		vk: &ed25519_dalek::VerifyingKey,
	) -> InternalResult<Archive<T>> {
		// Start reading from the start of the input
		handle.seek(SeekFrom::Start(0))?;

		let header = Header::from_handle(&mut handle)?;
		header.validate()?;

		// Generate and store Registry Entries
		let mut entries = HashMap::new();

		// Construct entries map
		for _ in 0..header.capacity {
			let entry = RegistryEntry::from_handle(&mut handle)?;
			entries.insert(entry.id.clone(), entry);
		}

		let archive = Archive {
			header,
			handle: Mutex::new(handle),
			entries,
			key: Some(*vk),
			decryptor: Some(crypto::Encryptor::new(vk)),
		};

		Ok(archive)
	}

	/// Fetch a [`RegistryEntry`] from this [`Archive`].
	/// This can be used for debugging, as the [`RegistryEntry`] holds information on data with the adjacent ID.
	pub fn fetch_entry(
		&self,
		id: impl AsRef<str>,
	) -> Option<RegistryEntry> {
		self.entries.get(id.as_ref()).cloned()
	}

	/// Returns an immutable reference to the underlying [`HashMap`]. This hashmap stores [`RegistryEntry`] values and uses `String` keys.
	#[inline(always)]
	pub fn entries(&self) -> &HashMap<Arc<str>, RegistryEntry> {
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
	/// Read a [`RegistryEntry's`](RegistryEntry) adjacent raw data
	pub(crate) fn read_raw(
		handle: &mut T,
		entry: &RegistryEntry,
	) -> InternalResult<Vec<u8>> {
		let mut buffer = Vec::with_capacity(entry.offset as usize);
		handle.seek(SeekFrom::Start(entry.location))?;

		let mut take = handle.take(entry.offset);
		take.read_to_end(&mut buffer)?;

		Ok(buffer)
	}

	/// Cheaper alternative to [`fetch`](Archive::fetch) that doesn't lock the underlying [Mutex]
	pub fn fetch_mut(
		&mut self,
		id: impl AsRef<str>,
	) -> InternalResult<Resource> {
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = Archive::read_raw(self.handle.get_mut().unwrap(), &entry)?;
			let (buffer, verified) = self.process(&entry, raw)?;

			Ok(Resource {
				flags: entry.flags,
				data: buffer.into(),
				verified,
			})
		} else {
			Err(InternalError::MissingResourceError(id.as_ref().to_string()))
		}
	}

	/// Fetch a [`Resource`] with the given `ID`.
	/// Locks the underlying [`Mutex`], for a cheaper non-locking operation refer to [`Archive::fetch_mut`]
	pub fn fetch(
		&self,
		id: impl AsRef<str>,
	) -> InternalResult<Resource> {
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = {
				let mut guard = self.handle.lock().unwrap();
				Archive::read_raw(guard.deref_mut(), &entry)?
			};

			// Decompress and|or decrypt the data
			let (buffer, is_secure) = self.process(&entry, raw)?;

			Ok(Resource {
				flags: entry.flags,
				data: buffer.into(),
				verified: is_secure,
			})
		} else {
			Err(InternalError::MissingResourceError(id.as_ref().to_string()))
		}
	}
}

use crate::global::flags::Flags;

use std::{io::Read, fmt};
use std::convert::TryInto;
use ed25519_dalek as esdalek;
use super::{error::InternalError, result::InternalResult};

/// Stand-alone meta-data from an archive entry(Leaf). This can be parsed without reading data about the leaf.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
	/// The flags extracted from the archive entry and parsed into a struct
	pub flags: Flags,
	/// The content version of the extracted archive entry
	pub content_version: u8,
	/// The signature of the extracted archive entry
	pub signature: Option<esdalek::Signature>,
	/// The location of the file in the archive, as bytes from the beginning of the file
	pub location: u64,
	/// The offset|size of the [`Leaf`](crate::builder::Leaf), in bytes. This does not always correspond to the actual size of the file when read from the archive! ie when compressed
	pub offset: u64,
}

impl RegistryEntry {
	// (flags) + 1(content version) + 8(location) + 8(offset) + 2(path length) + ..Dynamic
	pub(crate) const MIN_SIZE: usize = Flags::SIZE + 19;

	#[inline(always)]
	pub(crate) fn empty() -> RegistryEntry {
		RegistryEntry {
			flags: Flags::empty(),
			content_version: 0,
			signature: None,
			location: 0,
			offset: 0,
		}
	}

	/// Given a read handle, will proceed to read and parse bytes into a [`RegistryEntry`] struct. (de-serialization)
	/// ### Errors
	/// Produces `io` errors and if the bytes in the id section is not valid UTF-8
	pub(crate) fn from_handle<T: Read>(mut handle: T) -> InternalResult<(Self, String)> {
		#![allow(clippy::uninit_assumed_init)]
		use std::mem::MaybeUninit;

		let mut buffer: [u8; RegistryEntry::MIN_SIZE] =
			unsafe { MaybeUninit::uninit().assume_init() };
		handle.read_exact(&mut buffer)?;

		// Construct entry
		let flags = Flags::from_bits(u32::from_le_bytes(buffer[0..4].try_into().unwrap()));
		let content_version = buffer[4];

		let location = u64::from_le_bytes(buffer[5..13].try_into().unwrap());
		let offset = u64::from_le_bytes(buffer[13..21].try_into().unwrap());

		let id_length = u16::from_le_bytes([buffer[21], buffer[22]]);
		let mut signature = None;

		/* The data after this is dynamically sized, therefore *MUST* be read conditionally */
		// Only produce a flag from data that is signed
		if flags.contains(Flags::SIGNED_FLAG) {
			let mut sig_bytes: [u8; crate::SIGNATURE_LENGTH] =
				unsafe { MaybeUninit::uninit().assume_init() };
			handle.read_exact(&mut sig_bytes)?;

			let sig: esdalek::Signature = match sig_bytes.try_into() {
				Ok(sig) => sig,
				Err(err) => return Err(InternalError::ParseError(err.to_string())),
			};

			signature = Some(sig);
		};

		// Construct ID
		let mut id = String::new();
		handle.take(id_length as u64).read_to_string(&mut id)?;

		// Build entry step manually, to prevent unnecessary `Default::default()` call, then changing fields individually
		let entry = RegistryEntry {
			flags,
			content_version,
			signature,
			location,
			offset,
		};

		Ok((entry, id))
	}

	/// Serializes a [`RegistryEntry`] struct into an array of bytes
	pub(crate) fn bytes(&self, id_length: &u16) -> Vec<u8> {
		let mut buffer = Vec::new();
		buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
		buffer.extend_from_slice(&self.content_version.to_le_bytes());
		buffer.extend_from_slice(&self.location.to_le_bytes());
		buffer.extend_from_slice(&self.offset.to_le_bytes());
		buffer.extend_from_slice(&id_length.to_le_bytes());

		// Only write signature if one exists
		if let Some(signature) = self.signature {
			buffer.extend_from_slice(&signature.to_bytes())
		};

		buffer
	}
}

impl Default for RegistryEntry {
	#[inline(always)]
	fn default() -> RegistryEntry {
		RegistryEntry::empty()
	}
}

impl fmt::Display for RegistryEntry {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[RegistryEntry] location: {}, length: {}, content_version: {}, flags: {}",
			self.location,
			self.offset,
			self.content_version,
			self.flags.bits()
		)
	}
}

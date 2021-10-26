use crate::global::types::Flags;

use std::{
	convert::TryInto,
	io::{Read, Seek},
	fmt,
};
use ed25519_dalek as esdalek;

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
	/// The size of the file
	pub offset: u64,
}

impl RegistryEntry {
	// 2(flags) + 1(content version) + 8(location) + 8(offset) + 2(path length) + ..Dynamic
	pub(crate) const MIN_SIZE: usize = 21;

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
	/// Given a read handle, will proceed to read and parse bytes into a `RegistryEntry` struct. (de-serialization)
	pub(crate) fn from_handle<T: Read + Seek>(
		mut handle: T, read_sig: bool,
	) -> anyhow::Result<(Self, String)> {
		let mut buffer = [0; RegistryEntry::MIN_SIZE];
		handle.read_exact(&mut buffer)?;

		// Construct entry
		let mut entry = RegistryEntry::empty();
		entry.flags = Flags::from_bits(u16::from_le_bytes([buffer[0], buffer[1]]));
		entry.content_version = buffer[2];

		entry.location = u64::from_le_bytes([
			buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10],
		]);

		entry.offset = u64::from_le_bytes([
			buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17],
			buffer[18],
		]);

		let id_length = u16::from_le_bytes([buffer[19], buffer[20]]);

		/* The data after this is dynamically sized, therefore *MUST* be read conditionally */
		// Only produce a flag from data that is signed
		if read_sig {
			let mut sig_bytes = [0u8; crate::SIGNATURE_LENGTH];
			handle.read_exact(&mut sig_bytes)?;
			entry.signature = Some(sig_bytes.try_into()?);
		};

		// Construct ID
		let mut id = String::new();
		handle.take(id_length as u64).read_to_string(&mut id)?;

		Ok((entry, id))
	}

	/// Serializes a `RegistryEntry` struct into an array of bytes
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

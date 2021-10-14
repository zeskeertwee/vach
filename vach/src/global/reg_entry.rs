use crate::global::types::Flags;

use std::{
	convert::TryInto,
	io::{Read, Seek},
	fmt,
};
use ed25519_dalek as esdalek;

#[derive(Debug, Clone)]
pub struct RegistryEntry {
	pub flags: Flags,
	pub content_version: u8,
	pub signature: Option<esdalek::Signature>,

	pub(crate) location: u64,
	pub(crate) offset: u64,
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
	pub(crate) fn from_handle<T: Read + Seek>(
		mut handle: T, read_sig: bool,
	) -> anyhow::Result<(Self, String)> {
		let mut buffer = [0; RegistryEntry::MIN_SIZE];
		handle.read_exact(&mut buffer)?;

		// Construct entry
		let mut entry = RegistryEntry::empty();
		entry.flags = Flags::from_bits(u16::from_le_bytes(buffer[0..2].try_into()?));
		entry.content_version = buffer[2];

		entry.location = u64::from_le_bytes(buffer[3..11].try_into()?);
		entry.offset = u64::from_le_bytes(buffer[11..19].try_into()?);

		let id_length = u16::from_le_bytes(buffer[19..RegistryEntry::MIN_SIZE].try_into()?);

		/* The data after this is dynamically sized, therefore *MUST* be read conditionally */
		// Only produce a flag from data that is signed
		if read_sig {
			let mut buffer = [0u8; crate::SIGNATURE_LENGTH];
			handle.read_exact(&mut buffer)?;
			entry.signature = Some(buffer.try_into()?);
		};

		// Construct ID
		let mut id = String::new();
		handle.take(id_length as u64).read_to_string(&mut id)?;

		Ok((entry, id))
	}

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

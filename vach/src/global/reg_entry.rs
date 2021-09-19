use crate::{
	global::{
		types::{Flags},
	},
};

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
	pub signature: esdalek::Signature,

	pub(crate) location: u64,
	pub(crate) offset: u64,
}

impl RegistryEntry {
	// 2(flags) + 1(content version) + 64(crate::SIGNATURE_LENGTH) + 8(location) + 8(offset) + 2(path length)
	pub(crate) const MIN_SIZE: usize = 85;

	#[inline(always)]
	pub(crate) fn empty() -> RegistryEntry {
		RegistryEntry {
			flags: Flags::empty(),
			content_version: 0,
			signature: esdalek::Signature::new([0; 64]),
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

		// Only produce a flag from data that is signed
		if read_sig {
			entry.signature = buffer[3..67].try_into()?
		};

		entry.location = u64::from_le_bytes(buffer[67..75].try_into()?);
		entry.offset = u64::from_le_bytes(buffer[75..83].try_into()?);

		// Construct ID
		let id_length = u16::from_le_bytes(buffer[83..RegistryEntry::MIN_SIZE].try_into()?);
		let mut id = String::new();
		handle.take(id_length as u64).read_to_string(&mut id)?;

		Ok((entry, id))
	}

	pub(crate) fn bytes(&self, id_length: &u16, sign: bool) -> Vec<u8> {
		let mut buffer = Vec::new();
		buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
		buffer.extend_from_slice(&self.content_version.to_le_bytes());
		if sign {
			buffer.extend_from_slice(&self.signature.to_bytes())
		} else {
			buffer.extend_from_slice(&[0x53u8; crate::SIGNATURE_LENGTH])
		};
		buffer.extend_from_slice(&self.location.to_le_bytes());
		buffer.extend_from_slice(&self.offset.to_le_bytes());
		buffer.extend_from_slice(&id_length.to_le_bytes());
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

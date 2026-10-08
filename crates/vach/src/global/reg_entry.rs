use super::{error::*, flags::Flags};
use std::{
	fmt,
	io::{Read, Seek},
	sync::Arc,
};

#[cfg(feature = "crypto")]
use crate::crypto;

/// Stand-alone meta-data for an archive entry(Leaf). This can be fetched without reading from the archive.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryEntry {
	/// Self explanatory?
	pub id: Arc<str>,
	/// The flags extracted from the archive entry and parsed into a accessible struct
	pub flags: Flags,
	/// The location of the file in the archive, as an offset of bytes from the beginning of the file
	pub location: u64,
	/// The offset|size of the [`Leaf`](crate::builder::Leaf), in bytes. This is the actual number of bytes in the leaf endpoint. But the size of the data may vary once processed, ie when decompressed
	pub offset: u64,
	/// The signature of the data in the archive, used when verifying data authenticity
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub signature: Option<crypto::Signature>,
	/// Cryptographic nonce, for cryptographic integrity
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub nonce: Option<[u8; 12]>,
}

impl RegistryEntry {
	// (flags) + 8(location) + 8(offset) + 2(id length)
	pub(crate) const CONSTANT: usize = Flags::BYTES + 18;

	#[inline(always)]
	pub(crate) fn empty() -> RegistryEntry {
		RegistryEntry {
			id: Arc::from("None"),
			flags: Flags::new(),
			location: 0,
			offset: 0,

			#[cfg(feature = "crypto")]
			signature: None,
			#[cfg(feature = "crypto")]
			nonce: None,
		}
	}

	/// Given a read handle, will proceed to read and parse bytes into a [`RegistryEntry`] struct. (de-serialization)
	pub(crate) fn from_handle<T: Seek + Read>(mut handle: T) -> InternalResult<RegistryEntry> {
		let mut base = RegistryEntry::empty();

		let mut buffer: [u8; RegistryEntry::CONSTANT] = [0u8; RegistryEntry::CONSTANT];
		handle.read_exact(&mut buffer)?;

		// Construct entry
		base.flags = Flags::from_bits(u32::from_le_bytes(buffer[0..4].try_into().unwrap()));

		base.location = u64::from_le_bytes(buffer[4..12].try_into().unwrap());
		base.offset = u64::from_le_bytes(buffer[12..20].try_into().unwrap());

		let id_length = u16::from_le_bytes([buffer[20], buffer[21]]);

		/* dynamically sized data */

		// read signature, if present
		#[cfg(feature = "crypto")]
		if base.flags.contains(Flags::SIGNED_FLAG) {
			let mut sig_bytes: [u8; crate::SIGNATURE_LENGTH] = [0u8; crate::SIGNATURE_LENGTH];
			handle.read_exact(&mut sig_bytes)?;

			base.signature = Some(crypto::Signature::from(sig_bytes));
		};

		// read nonce, if present
		#[cfg(feature = "crypto")]
		if base.flags.contains(Flags::ENCRYPTED_FLAG) {
			let mut nonce: [u8; crate::NONCE_LENGTH] = [0u8; crate::NONCE_LENGTH];
			handle.read_exact(&mut nonce)?;

			base.nonce = Some(nonce);
		};

		#[cfg(not(feature = "crypto"))]
		if base.flags.contains(Flags::SIGNED_FLAG) {
			handle.seek(std::io::SeekFrom::Current(crate::SIGNATURE_LENGTH as i64))?;
		}

		#[cfg(not(feature = "crypto"))]
		if base.flags.contains(Flags::ENCRYPTED_FLAG) {
			handle.seek(std::io::SeekFrom::Current(crate::NONCE_LENGTH as i64))?;
		}

		// Construct ID
		let mut id = String::with_capacity(id_length as usize);
		handle.take(id_length as u64).read_to_string(&mut id)?;
		base.id = Arc::from(id);

		Ok(base)
	}

	/// Serializes a [`RegistryEntry`] struct into an array of bytes
	pub(crate) fn to_bytes(&self) -> InternalResult<Vec<u8>> {
		// Make sure the ID is not too big or else it will break the archive
		let id = self.id.as_ref();

		if id.len() >= crate::MAX_ID_LENGTH {
			let copy = id.to_string();
			return Err(InternalError::IDSizeOverflowError(copy));
		};

		let mut buffer = Vec::with_capacity(RegistryEntry::CONSTANT + id.len());
		buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
		buffer.extend_from_slice(&self.location.to_le_bytes());
		buffer.extend_from_slice(&self.offset.to_le_bytes());
		buffer.extend_from_slice(&(id.len() as u16).to_le_bytes());

		#[cfg(feature = "crypto")]
		{
			if let Some(signature) = self.signature {
				buffer.extend_from_slice(&signature.to_bytes())
			}

			if let Some(nonce) = self.nonce {
				buffer.extend_from_slice(&nonce)
			}
		};

		// Append id
		buffer.extend_from_slice(id.as_bytes());

		Ok(buffer)
	}
}

impl Default for RegistryEntry {
	#[inline(always)]
	fn default() -> RegistryEntry {
		RegistryEntry::empty()
	}
}

impl fmt::Display for RegistryEntry {
	fn fmt(
		&self,
		f: &mut fmt::Formatter,
	) -> fmt::Result {
		write!(f, "[RegistryEntry] location: {}, length: {}, flags: {}", self.location, self.offset, self.flags.bits())
	}
}

use std::{fmt, io::Read};

#[cfg(feature = "crypto")]
use crate::crypto;
use super::{error::*, flags::Flags};

/// Used to configure and give extra information to the [`Archive`](crate::archive::Archive) loader.
/// Used exclusively in archive source and integrity validation.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveConfig {
	/// An ed25519 public key. **If no key is provided, (is `None`), then signature validation is ignored**. Even if the
	/// archive source has signatures.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub public_key: Option<crypto::VerifyingKey>,
}

impl ArchiveConfig {
	/// Create a new [`ArchiveConfig`] struct.
	#[inline(always)]
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub const fn new(key: Option<crypto::VerifyingKey>) -> ArchiveConfig {
		ArchiveConfig { public_key: key }
	}

	/// Create a new [`ArchiveConfig`] struct.
	/// ```
	/// use vach::prelude::ArchiveConfig;
	/// let config = ArchiveConfig::new(*b"_TEST");
	/// ```
	#[cfg(not(feature = "crypto"))]
	pub const fn new() -> ArchiveConfig {
		ArchiveConfig {}
	}

	/// Shorthand to load and parse an ed25519 public key from a [`Read`] handle, into this [`ArchiveConfig`],
	/// ```
	/// use vach::{crypto_utils::gen_keypair, prelude::ArchiveConfig};
	/// let mut config = ArchiveConfig::default();
	/// let keypair_bytes = gen_keypair().to_keypair_bytes();
	/// // let keypair_bytes = gen_keypair().verifying_key().to_bytes();
	/// // config.load_public_key(&keypair_bytes).unwrap();
	/// config.load_public_key(&keypair_bytes[32..]).unwrap();
	/// ```
	#[inline]
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub fn load_public_key<T: Read>(&mut self, handle: T) -> InternalResult {
		use crate::crypto_utils::read_public_key;
		self.public_key = Some(read_public_key(handle)?);
		Ok(())
	}

	/// Shorthand to load a PublicKey into the [ArchiveConfig]
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub fn key(mut self, verifying_key: crypto::VerifyingKey) -> ArchiveConfig {
		self.public_key = Some(verifying_key);
		self
	}
}

impl fmt::Display for ArchiveConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		#[rustfmt::skip]
		let has_pk = {
			#[cfg(feature = "crypto")] { if self.public_key.is_some() { "true" } else { "false" } }
			#[cfg(not(feature = "crypto"))] { "(crypto feature disabled)" }
		};

		write!(f, "[ArchiveConfig]  verifying_key: {}", has_pk)
	}
}

#[cfg(feature = "crypto")]
impl Default for ArchiveConfig {
	#[inline(always)]
	fn default() -> Self {
		ArchiveConfig::new(None)
	}
}

#[cfg(not(feature = "crypto"))]
impl Default for ArchiveConfig {
	#[inline(always)]
	fn default() -> Self {
		ArchiveConfig::new(crate::MAGIC_SEQUENCE)
	}
}

#[derive(Debug)]
pub(crate) struct Header {
	pub(crate) magic: [u8; crate::MAGIC_LENGTH],
	pub flags: Flags,
	pub version: u16,
	pub capacity: u16,
}

impl Default for Header {
	#[inline(always)]
	fn default() -> Header {
		Header {
			magic: crate::MAGIC_SEQUENCE,
			flags: Flags::default(),
			version: crate::VERSION,
			capacity: 0,
		}
	}
}

impl Header {
	pub const BASE_SIZE: usize = crate::MAGIC_LENGTH + Flags::BYTES + Self::VERSION_SIZE + Self::CAPACITY_SIZE;

	// Data appears in this order
	pub const VERSION_SIZE: usize = 2;
	pub const CAPACITY_SIZE: usize = 2;

	/// Validates a `Header` with a template [ArchiveConfig]
	pub(crate) fn validate(&self) -> InternalResult {
		// Validate magic
		if self.magic != crate::MAGIC_SEQUENCE {
			return Err(InternalError::MalformedArchiveSource(self.magic));
		};

		// Validate version
		if crate::VERSION != self.version {
			return Err(InternalError::IncompatibleArchiveVersionError(self.version));
		};

		Ok(())
	}

	pub(crate) fn from_handle<T: Read>(mut handle: T) -> InternalResult<Header> {
		let mut buffer: [u8; Header::BASE_SIZE] = [0u8; Header::BASE_SIZE];
		handle.read_exact(&mut buffer)?;

		// Construct header
		Ok(Header {
			// Read magic, [u8;5]
			magic: buffer[0..crate::MAGIC_LENGTH].try_into().unwrap(),
			// Read flags, u32 from [u8;4]
			flags: Flags::from_bits(u32::from_le_bytes(buffer[crate::MAGIC_LENGTH..9].try_into().unwrap())),
			// Read version, u16 from [u8;2]
			version: u16::from_le_bytes(buffer[9..11].try_into().unwrap()),
			// Read the capacity of the archive, u16 from [u8;2]
			capacity: u16::from_le_bytes(buffer[11..13].try_into().unwrap()),
		})
	}

	pub(crate) fn to_bytes(&self) -> [u8; Header::BASE_SIZE] {
		let mut buffer: [u8; Header::BASE_SIZE] = [0u8; Header::BASE_SIZE];
		buffer[0..crate::MAGIC_LENGTH].copy_from_slice(&self.magic);
		buffer[crate::MAGIC_LENGTH..9].copy_from_slice(&self.flags.bits().to_le_bytes());
		buffer[9..11].copy_from_slice(&self.version.to_le_bytes());
		buffer[11..13].copy_from_slice(&self.capacity.to_le_bytes());
		buffer
	}
}

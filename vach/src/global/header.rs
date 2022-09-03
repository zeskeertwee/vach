use std::{fmt, io::Read, str};

#[cfg(feature = "crypto")]
use crate::crypto;
use super::{error::InternalError, result::InternalResult, flags::Flags};

/// Used to configure and give extra information to the [`Archive`](crate::archive::Archive) loader.
/// Used exclusively in archive source and integrity validation.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveConfig {
	/// If the archive has a custom magic sequence, pass the custom _MAGIC_ sequence here.
	/// The custom _MAGIC_ sequence can then be used to validate archive sources.
	pub magic: [u8; crate::MAGIC_LENGTH],
	/// An ed25519 public key. **If no key is provided, (is `None`), then signature validation is ignored**. Even if the
	/// archive source has signatures.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub public_key: Option<crypto::PublicKey>,
}

impl ArchiveConfig {
	/// Construct a new [`ArchiveConfig`] struct.
	/// ```
	/// use vach::prelude::ArchiveConfig;
	/// let config = ArchiveConfig::new(*b"_TEST",  None);
	/// ```
	#[inline(always)]
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub const fn new(magic: [u8; crate::MAGIC_LENGTH], key: Option<crypto::PublicKey>) -> ArchiveConfig {
		ArchiveConfig { magic, public_key: key }
	}

	/// Construct a new [`ArchiveConfig`] struct.
	/// ```
	/// use vach::prelude::ArchiveConfig;
	/// let config = ArchiveConfig::new(*b"_TEST");
	/// ```
	#[cfg(not(feature = "crypto"))]
	pub const fn new(magic: [u8; crate::MAGIC_LENGTH]) -> ArchiveConfig {
		ArchiveConfig { magic }
	}

	/// Shorthand to load and parse an ed25519 public key from a [`Read`] handle, into this [`ArchiveConfig`],
	/// ```
	/// use vach::{crypto_utils::gen_keypair, prelude::ArchiveConfig};
	/// let mut config = ArchiveConfig::default();
	/// let keypair_bytes = gen_keypair().to_bytes();
	/// config.load_public_key(&keypair_bytes[32..]).unwrap();
	/// ```
	///
	/// ### Errors
	///  - If parsing of the public key fails
	///  - `io` errors
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
	pub fn key(mut self, public_key: crypto::PublicKey) -> ArchiveConfig {
		self.public_key = Some(public_key);
		self
	}

	/// Setter for the magic into a [ArchiveConfig]
	pub fn magic(mut self, magic: [u8; crate::MAGIC_LENGTH]) -> ArchiveConfig {
		self.magic = magic;
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

		write!(
			f,
			"[ArchiveConfig] magic: {}, has_public_key: {}",
			match str::from_utf8(&self.magic) {
				Ok(magic) => {
					magic
				},
				Err(_) => {
					return fmt::Result::Err(fmt::Error);
				},
			},
			has_pk
		)
	}
}

#[cfg(feature = "crypto")]
impl Default for ArchiveConfig {
	#[inline(always)]
	fn default() -> Self {
		ArchiveConfig::new(*crate::DEFAULT_MAGIC, None)
	}
}

#[cfg(not(feature = "crypto"))]
impl Default for ArchiveConfig {
	#[inline(always)]
	fn default() -> Self {
		ArchiveConfig::new(*crate::DEFAULT_MAGIC)
	}
}

#[derive(Debug)]
pub(crate) struct Header {
	pub magic: [u8; crate::MAGIC_LENGTH], // VfACH
	pub flags: Flags,
	pub arch_version: u16,
	pub capacity: u16,
}

impl Default for Header {
	#[inline(always)]
	fn default() -> Header {
		Header {
			magic: *crate::DEFAULT_MAGIC,
			flags: Flags::default(),
			arch_version: crate::VERSION,
			capacity: 0,
		}
	}
}

impl Header {
	pub const BASE_SIZE: usize = crate::MAGIC_LENGTH + Flags::SIZE + Self::VERSION_SIZE + Self::CAPACITY_SIZE;

	// Data appears in this order
	pub const VERSION_SIZE: usize = 2;
	pub const CAPACITY_SIZE: usize = 2;

	/// Validates a `Header` with a template [ArchiveConfig]
	/// ### Errors
	///  - (in)validation of magic and archive version
	pub(crate) fn validate(config: &ArchiveConfig, header: &Header) -> InternalResult {
		// Validate magic
		if header.magic != config.magic {
			return Err(InternalError::MalformedArchiveSource(header.magic));
		};

		// Validate version
		if crate::VERSION != header.arch_version {
			return Err(InternalError::IncompatibleArchiveVersionError(header.arch_version));
		};

		Ok(())
	}

	/// ### Errors
	///  - `io` errors
	pub(crate) fn from_handle<T: Read>(mut handle: T) -> InternalResult<Header> {
		#![allow(clippy::uninit_assumed_init)]
		let mut buffer: [u8; Header::BASE_SIZE] = [0u8; Header::BASE_SIZE];

		handle.read_exact(&mut buffer)?;

		// Construct header
		Ok(Header {
			// Read magic, [u8;5]
			magic: buffer[0..crate::MAGIC_LENGTH].try_into().unwrap(),
			// Read flags, u32 from [u8;4]
			flags: Flags::from_bits(u32::from_le_bytes(buffer[crate::MAGIC_LENGTH..9].try_into().unwrap())),
			// Read version, u16 from [u8;2]
			arch_version: u16::from_le_bytes(buffer[9..11].try_into().unwrap()),
			// Read the capacity of the archive, u16 from [u8;2]
			capacity: u16::from_le_bytes(buffer[11..13].try_into().unwrap()),
		})
	}
}

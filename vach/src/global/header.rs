use std::{fmt, io::Read, str};

use crate::{global::flags::Flags, utils::read_public_key};

use ed25519_dalek as esdalek;

use super::{error::InternalError, result::InternalResult};

/// Used to configure and give extra information to the [`Archive`](crate::archive::Archive) loader.
/// Used exclusively in archive source and integrity validation.
#[derive(Debug, Clone)]
pub struct HeaderConfig {
	/// If the archive has a custom magic sequence, pass the custom _MAGIC_ sequence here.
	/// The custom _MAGIC_ sequence can then be used to validate archive sources.
	pub magic: [u8; crate::MAGIC_LENGTH],
	/// An ed25519 public key. **If no key is provided, (is `None`), then signature validation is ignored**. Even if the
	/// archive source has signatures.
	pub public_key: Option<esdalek::PublicKey>,
}

impl HeaderConfig {
	/// Construct a new [`HeaderConfig`] struct.
	/// ```
	/// use vach::prelude::HeaderConfig;
	/// let config = HeaderConfig::new(*b"_TEST",  None);
	/// ```
	#[inline(always)]
	pub fn new(magic: [u8; 5], key: Option<esdalek::PublicKey>) -> HeaderConfig {
		HeaderConfig {
			magic,
			public_key: key,
		}
	}

	/// Shorthand to load and parse an ed25519 public key from a `Read` handle, into this `HeaderConfig`,
	/// ```
	/// use vach::{utils::gen_keypair, prelude::HeaderConfig};
	/// let mut config = HeaderConfig::default();
	/// let keypair_bytes = gen_keypair().to_bytes();
	/// config.load_public_key(&keypair_bytes[32..]).unwrap();
	/// ```
	///
	/// ### Errors
	///  - If parsing of the public key fails
	///  - `io` errors
	#[inline]
	pub fn load_public_key<T: Read>(&mut self, handle: T) -> InternalResult<()> {
		self.public_key = Some(read_public_key(handle)?);
		Ok(())
	}

	/// Shorthand to load a PublicKey into the HeaderConfig
	pub fn key(mut self, public_key: esdalek::PublicKey) -> HeaderConfig {
		self.public_key = Some(public_key);
		self
	}

	/// Setter for the magic into a HeaderConfig
	pub fn magic(mut self, magic: [u8; 5]) -> HeaderConfig {
		self.magic = magic;
		self
	}
}

impl fmt::Display for HeaderConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[HeaderConfig] magic: {}, has_public_key: {}",
			match str::from_utf8(&self.magic) {
				Ok(magic) => {
					magic
				}
				Err(_) => {
					return fmt::Result::Err(fmt::Error);
				}
			},
			self.public_key.is_some()
		)
	}
}

impl Default for HeaderConfig {
	#[inline(always)]
	fn default() -> Self {
		HeaderConfig::new(*crate::DEFAULT_MAGIC, None)
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
	pub const BASE_SIZE: usize =
		crate::MAGIC_LENGTH + Flags::SIZE + Self::VERSION_SIZE + Self::CAPACITY_SIZE;

	// Data appears in this order
	pub const VERSION_SIZE: usize = 2;
	pub const CAPACITY_SIZE: usize = 2;

	/// Validates a `Header` with a template `HeaderConfig`
	/// ### Errors
	///  - (in)validation of magic and archive version
	pub fn validate(header: &Header, config: &HeaderConfig) -> InternalResult<()> {
		// Validate magic
		if header.magic != config.magic {
			return Err(InternalError::ValidationError(format!(
				"Invalid magic found in Header, possible incompatibility with given source.\nMagic found {:?}", header.magic
			)));
		};

		// Validate version
		if crate::VERSION > header.arch_version {
			return Err(InternalError::ValidationError(format!(
                "The provided archive source has version: {}. While the loader has a version: {}. The current loader is likely out of date!",
                header.arch_version, crate::VERSION
            )));
		};

		Ok(())
	}

	/// ### Errors
	///  - `io` errors
	pub fn from_handle<T: Read>(mut handle: T) -> InternalResult<Header> {
		#![allow(clippy::uninit_assumed_init)]
		// We are never reading from `buffer`, so it's safe to use uninitialized memory. We initialize it instantly after

		use std::mem::MaybeUninit;
		let mut buffer: [u8; Header::BASE_SIZE] = unsafe { MaybeUninit::uninit().assume_init() };

		handle.read_exact(&mut buffer)?;

		// Construct header
		Ok(Header {
			// Read magic, [u8;5]
			magic: buffer[0..5].try_into().unwrap(),
			// Read flags, u32 from [u8;4]
			flags: Flags::from_bits(u32::from_le_bytes(buffer[5..9].try_into().unwrap())),
			// Read version, u16 from [u8;2]
			arch_version: u16::from_le_bytes([buffer[9], buffer[10]]),
			// Read the capacity of the archive, u16 from [u8;2]
			capacity: u16::from_le_bytes([buffer[11], buffer[12]]),
		})
	}
}

impl fmt::Display for Header {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[Archive Header] Version: {}, Magic: {}, Capacity: {}, Flags: {}",
			self.arch_version,
			str::from_utf8(&self.magic).expect("Error constructing str from Header::Magic"),
			self.capacity,
			self.flags
		)
	}
}

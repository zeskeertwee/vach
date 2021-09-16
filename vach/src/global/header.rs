use crate::global::types::Flags;
use anyhow;
use ed25519_dalek as esdalek;
use std::{
	convert::TryInto,
	fmt,
	io::{Read, Seek, SeekFrom},
	str,
};

#[derive(Debug)]
pub struct HeaderConfig {
	pub magic: [u8; crate::MAGIC_LENGTH],
	pub minimum_version: u16,
	pub public_key: Option<esdalek::PublicKey>,
}

// Used to store data about headers and to validate magic and content version
impl HeaderConfig {
	pub fn new(
		magic: [u8; 5], minimum_version: u16, key: Option<esdalek::PublicKey>,
	) -> HeaderConfig {
		HeaderConfig {
			magic,
			minimum_version,
			public_key: key,
		}
	}

	// Setters
	pub fn minimum_version(mut self, version: u16) -> HeaderConfig {
		self.minimum_version = version;
		self
	}
	pub fn magic(mut self, magic: [u8; 5]) -> HeaderConfig {
		self.magic = magic;
		self
	}
	pub fn key(mut self, key: Option<esdalek::PublicKey>) -> HeaderConfig {
		self.public_key = key;
		self
	}
	pub fn load_public_key<T: Read>(&mut self, mut handle: T) -> anyhow::Result<()> {
		let mut keypair_bytes = [4; crate::PUBLIC_KEY_LENGTH];
		handle.read_exact(&mut keypair_bytes)?;
		let public_key = esdalek::PublicKey::from_bytes(&keypair_bytes)?;
		self.public_key = Some(public_key);
		Ok(())
	}
}

impl fmt::Display for HeaderConfig {
	#[inline]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[HeaderConfig] magic: {}, minimum_version: {}",
			str::from_utf8(&self.magic).expect("Error constructing str from HeaderConfig::Magic"),
			self.minimum_version
		)
	}
}

impl Default for HeaderConfig {
	#[inline]
	fn default() -> Self {
		HeaderConfig::new(*crate::DEFAULT_MAGIC, crate::VERSION, None)
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
	#[inline]
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
	// BASE_SIZE => 11 + 64 = 75
	pub(crate) const BASE_SIZE: usize =
		crate::MAGIC_LENGTH + Self::FLAG_SIZE + Self::VERSION_SIZE + Self::CAPACITY_SIZE;

	// Data appears in this order
	pub(crate) const FLAG_SIZE: usize = 2;
	pub(crate) const VERSION_SIZE: usize = 2;
	pub(crate) const CAPACITY_SIZE: usize = 2;

	pub(crate) fn validate(header: &Header, config: &HeaderConfig) -> anyhow::Result<()> {
		// Validate magic
		if header.magic != config.magic {
			anyhow::bail!(format!(
				"Invalid magic found in Header: {}",
				str::from_utf8(&header.magic)?
			));
		};

		// Validate version
		if config.minimum_version > header.arch_version {
			anyhow::bail!(format!(
                "Minimum Archive Version requirement not met. Version found: {}, Minimum acceptable version: {}",
                header.arch_version, config.minimum_version
            ))
		};

		Ok(())
	}

	pub(crate) fn from_handle<T: Read + Seek>(mut handle: T) -> anyhow::Result<Header> {
		handle.seek(SeekFrom::Start(0))?;
		let mut buffer = [0x69; Header::BASE_SIZE];
		handle.read_exact(&mut buffer)?;

		// Construct header
		Ok(Header {
			// Read magic, [u8;5]
			magic: buffer[0..crate::MAGIC_LENGTH].try_into()?,
			// Read flags, u16 from [u8;2]
			flags: Flags::from_bits(u16::from_le_bytes(
				buffer[crate::MAGIC_LENGTH..7].try_into()?,
			)),
			// Read version, u16 from [u8;2]
			arch_version: u16::from_le_bytes(buffer[7..9].try_into()?),
			// Read the capacity of the archive, u16 from [u8;2]
			capacity: u16::from_le_bytes(buffer[9..Header::BASE_SIZE].try_into()?),
		})
	}
}

impl fmt::Display for Header {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[Archive Header] Version: {}, Magic: {}",
			self.arch_version,
			str::from_utf8(&self.magic).expect("Error constructing str from Header::Magic")
		)
	}
}

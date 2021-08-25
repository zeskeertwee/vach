use crate::global::types::FlagType;
use anyhow;
use ed25519_dalek as esdalek;
use std::{
    convert::TryFrom,
    fmt,
    io::{Read, Seek, SeekFrom},
    str,
};

#[derive(Debug)]
pub struct HeaderConfig {
    pub magic: [u8; HeaderConfig::MAGIC_LENGTH],
    pub minimum_version: u16,
    pub public_key: Option<esdalek::PublicKey>,
}

// Used to store data about headers and to validate magic and content version
impl HeaderConfig {
    // BASE_SIZE => 11 + 64 = 75
    pub const BASE_SIZE: usize = Self::MAGIC_LENGTH + Self::FLAG_SIZE + Self::VERSION_SIZE + Self::CAPACITY_SIZE + esdalek::SIGNATURE_LENGTH;
    pub const MAGIC: &'static [u8; 5] = b"VfACH";

    // Data appears in this order
    pub const MAGIC_LENGTH: usize = 5;
    pub const FLAG_SIZE: usize = 2;
    pub const VERSION_SIZE: usize = 2;
    pub const CAPACITY_SIZE: usize = 2;

    pub fn from( magic: [u8; 5], minimum_version: u16, key: Option<esdalek::PublicKey>, ) -> HeaderConfig {
        HeaderConfig {
            magic,
            minimum_version,
            public_key: key,
        }
    }
    pub fn new() -> HeaderConfig {
        HeaderConfig::from(*HeaderConfig::MAGIC, crate::VERSION, None)
    }
    pub fn empty() -> HeaderConfig {
        HeaderConfig::from([0; HeaderConfig::MAGIC_LENGTH], crate::VERSION, None)
    }

    // Setters
    pub fn set_minimum_version(mut self, version: u16) -> HeaderConfig {
        self.minimum_version = version;
        self
    }
    pub fn set_magic(mut self, magic: [u8; 5]) -> HeaderConfig {
        self.magic = magic;
        self
    }
    pub fn set_key(mut self, key: Option<esdalek::PublicKey>) -> HeaderConfig {
        self.public_key = key;
        self
    }
}

impl fmt::Display for HeaderConfig {
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
    fn default() -> Self {
        HeaderConfig {
            magic: HeaderConfig::MAGIC.clone(),
            minimum_version: crate::VERSION,
            public_key: None,
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub magic: [u8; HeaderConfig::MAGIC_LENGTH], // VfACH
    pub flags: FlagType,
    pub arch_version: u16,
    pub capacity: u16,
    pub reg_signature: Option<esdalek::Signature>,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            magic: HeaderConfig::MAGIC.clone(),
            flags: FlagType::default(),
            arch_version: crate::VERSION,
            capacity: 0,
            reg_signature: None,
        }
    }
}

impl Header {
    pub fn from<T: Read + Seek>(mut handle: T) -> anyhow::Result<Header> {
        handle.seek(SeekFrom::Start(0));

        // Construct header
        let mut header = Header::default();

        // Read magic, [u8;5]
        let mut buffer = [0x69; HeaderConfig::MAGIC_LENGTH];
        handle.read_exact(&mut buffer)?;
        header.magic = buffer;

        // Read flags, u16 from [u8;2]
        let mut buffer = [0x69; HeaderConfig::FLAG_SIZE];
        handle.read_exact(&mut buffer)?;
        header.flags = FlagType::from_bits(u16::from_le_bytes(buffer)).unwrap();

        // Read version, u16 from [u8;2]
        let mut buffer = [0x69; HeaderConfig::VERSION_SIZE];
        handle.read_exact(&mut buffer)?;
        header.arch_version = u16::from_le_bytes(buffer);

        // Read the capacity of the archive, u16 from [u8;2]
        let mut buffer = [0x69; HeaderConfig::CAPACITY_SIZE];
        handle.read_exact(&mut buffer)?;
        header.capacity = u16::from_le_bytes(buffer);

        // Read registry signature, esdalek::Signature from [u8; 64]
        if header.flags.contains(FlagType::SIGNED) {
            let mut buffer = [0x53; esdalek::SIGNATURE_LENGTH];
            handle.read_exact(&mut buffer)?;
            header.reg_signature = Some(esdalek::Signature::try_from(&buffer[..])?);
        };

        Ok(header)
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

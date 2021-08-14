use anyhow;
use std::{
    fmt,
    io::{BufReader, Read, Seek},
    str,
};

#[derive(Debug)]
pub struct HeaderConfig {
    pub magic: [u8; HeaderConfig::MAGIC_LENGTH],
    pub minimum_version: u16,
}

impl HeaderConfig {
    pub const MAGIC: &'static [u8; 5] = b"VfACH";
    pub const MAGIC_LENGTH: usize = 5;
    pub const FLAG_SIZE: usize = 2;
    pub const VERSION_SIZE: usize = 2;
    pub const ENTRY_SIZE: usize = 2;
    pub const SIZE: usize = 11;

    pub fn new(magic: [u8; 5], minimum_version: u16) -> HeaderConfig {
        HeaderConfig {
            magic,
            minimum_version,
        }
    }
    pub fn default() -> HeaderConfig {
        HeaderConfig::new(HeaderConfig::MAGIC.clone(), 0)
    }
    pub fn empty() -> HeaderConfig {
        HeaderConfig {
            magic: [0; HeaderConfig::MAGIC_LENGTH],
            minimum_version: 0,
        }
    }

    pub fn set_minimum_version(mut self, version: &u16) -> HeaderConfig {
        self.minimum_version = version.clone();
        self
    }
    pub fn set_magic(mut self, magic: [u8; 5]) -> HeaderConfig {
        self.magic = magic;
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

#[derive(Debug)]
pub struct Header {
    pub magic: [u8; HeaderConfig::MAGIC_LENGTH], // VfACH
    pub version: u16,
    pub flags: u16,
    pub capacity: u16,
}

impl Header {
    pub fn empty() -> Header {
        Header {
            magic: HeaderConfig::MAGIC.clone(),
            flags: 0,
            version: 0,
            capacity: 0,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.flags.to_ne_bytes());
        buffer.extend_from_slice(&self.version.to_ne_bytes());
        buffer.extend_from_slice(&self.capacity.to_ne_bytes());

        buffer
    }
}

impl Header {
    pub fn from<T: Read + Seek>(handle: &mut T) -> anyhow::Result<Header> {
        let mut reader = BufReader::new(handle);

        // Construct header
        let mut header = Header::empty();
        // TODO: Remove this repetitive garbage

        // Read magic
        let mut buffer = [0; HeaderConfig::MAGIC_LENGTH];
        reader.read(&mut buffer)?;
        header.magic = buffer;

        // Read flags, u32 from [u8;4]
        let mut buffer = [0; HeaderConfig::FLAG_SIZE];
        reader.read(&mut buffer)?;
        header.flags = u16::from_ne_bytes(buffer);

        // Read version, u16 from [u8;2]
        let mut buffer = [0; HeaderConfig::VERSION_SIZE];
        reader.read(&mut buffer)?;
        header.version = u16::from_ne_bytes(buffer);

        // Read number of entries, u16 from [u8;2]
        let mut buffer = [0; HeaderConfig::ENTRY_SIZE];
        reader.read(&mut buffer)?;
        header.capacity = u16::from_ne_bytes(buffer);

        Result::Ok(header)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Archive Header] Version: {}, Magic: {}",
            5u32,
            str::from_utf8(&self.magic).expect("Error constructing str from Header::Magic")
        )
    }
}

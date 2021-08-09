use std::{
    fmt,
    fs::File,
    io::{BufReader, Read},
    str,
};

#[derive(Debug)]
pub struct Config {
    pub magic: [u8; 5],
    pub minimum_version: u16,
}

impl Config {
    pub const MAGIC: &'static [u8; 5] = b"VfACH";
    pub const MAGIC_LENGTH: usize = 5;
    pub const FLAG_SIZE: usize = 4;
    pub const VERSION_SIZE: usize = 2;
    pub const ENTRY_SIZE: usize = 2;

    pub fn new(magic: [u8; 5], minimum_version: u16) -> Config {
        Config {
            magic,
            minimum_version,
        }
    }
    pub fn default() -> Config {
        Config::new(Config::MAGIC.clone(), 0)
    }
    pub fn set_minimum_version(mut self, version: &u16) -> Config {
        self.minimum_version = version.clone();
        self
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[HeaderConfig] magic: {}, minimum_version: {}",
            str::from_utf8(&self.magic).unwrap(),
            self.minimum_version
        )
    }
}

#[derive(Debug)]
pub struct Header {
    magic: [u8; Config::MAGIC_LENGTH], // VfACH
    version: u16,
    flags: u32,
    entries: u16,
}

impl Header {
    pub fn empty() -> Header {
        Header {
            magic: Config::MAGIC.clone(),
            flags: 0,
            version: 0,
            entries: 0,
        }
    }
    pub fn from_file(file: &File, big_endian: &bool) -> Result<Header, String> {
        let mut reader = BufReader::new(file);

        // Construct header
        let mut header = Header::empty();
        // TODO: Remove this repetitive garbage

        // Read magic
        let mut buffer = [0; Config::MAGIC_LENGTH];
        reader.read(&mut buffer).unwrap();
        header.magic = buffer.clone();

        // Read flags, u32 from [u8;4]
        let mut buffer = [0; Config::FLAG_SIZE];
        reader.read(&mut buffer).unwrap();
        header.flags = if *big_endian {
            u32::from_be_bytes(buffer)
        } else {
            u32::from_le_bytes(buffer)
        };

        // Read version, u16 from [u8;2]
        let mut buffer = [0; Config::VERSION_SIZE];
        reader.read(&mut buffer).unwrap();
        header.version = if *big_endian {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };

        // Read number of entries, u16 from [u8;2]
        let mut buffer = [0; Config::ENTRY_SIZE];
        reader.read(&mut buffer).unwrap();
        header.entries = if *big_endian {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };

        Result::Ok(header)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Archive Header] Version: {}, Magic: {}",
            5u32,
            str::from_utf8(&self.magic).unwrap()
        )
    }
}

use std::{
    fmt,
    fs::File,
    io::{BufReader, Read},
    str,
};

#[derive(Debug)]
pub struct HeaderConfig {
    pub magic: [u8; 5],
    pub minimum_version: u16,
}

impl HeaderConfig {
    pub const MAGIC: &'static [u8; 5] = b"VfACH";
    pub const MAGIC_LENGTH: usize = 5;
    pub const FLAG_SIZE: usize = 2;
    pub const VERSION_SIZE: usize = 2;
    pub const ENTRY_SIZE: usize = 2;

    pub fn new(magic: [u8; 5], minimum_version: u16) -> HeaderConfig {
        HeaderConfig {
            magic,
            minimum_version,
        }
    }
    pub fn default() -> HeaderConfig {
        HeaderConfig::new(HeaderConfig::MAGIC.clone(), 0)
    }
    pub fn set_minimum_version(mut self, version: &u16) -> HeaderConfig {
        self.minimum_version = version.clone();
        self
    }
}

impl fmt::Display for HeaderConfig {
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
    pub fn from_file(file: &File) -> Result<Header, String> {
        let mut reader = BufReader::new(file);

        // Construct header
        let mut header = Header::empty();
        // TODO: Remove this repetitive garbage

        // Read magic
        let mut buffer = [0; HeaderConfig::MAGIC_LENGTH];
        reader.read(&mut buffer).unwrap();
        header.magic = buffer.clone();

        // Read flags, u32 from [u8;4]
        let mut buffer = [0; HeaderConfig::FLAG_SIZE];
        reader.read(&mut buffer).unwrap();
        header.flags = u16::from_ne_bytes(buffer);

        // Read version, u16 from [u8;2]
        let mut buffer = [0; HeaderConfig::VERSION_SIZE];
        reader.read(&mut buffer).unwrap();
        header.version = u16::from_ne_bytes(buffer);

        // Read number of entries, u16 from [u8;2]
        let mut buffer = [0; HeaderConfig::ENTRY_SIZE];
        reader.read(&mut buffer).unwrap();
        header.capacity = u16::from_ne_bytes(buffer);

        Result::Ok(header)
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

#![allow(dead_code)]
#![allow(unused_variables)]

use std::{
    fmt::{self},
    fs::File,
    io::{BufReader, Read},
    str,
};
#[derive(Debug)]
pub struct Header {
    magic: [u8; ArchiveConfig::DEFAULT_MAGIC_LENGTH], // VfACH

    flags: u16,
    content_version: u16,

    uses_compressed: bool,
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // write!(f, "{}", 5u32);
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct Archive {
    header: Header,
    config: ArchiveConfig,
	 data: Box<[u8]>,
}

impl Archive {
    pub fn new(file: File) -> Self {
        Archive::with_options(file, ArchiveConfig::default())
    }
    pub fn with_options(file: File, options: ArchiveConfig) -> Self {
        unimplemented!()
    }

    pub fn validate(file: File, config: ArchiveConfig) -> Result<bool, String> {
        let mut reader = BufReader::new(file);
        let mut buffer = [0; 5];

        reader.read(&mut buffer).unwrap();

        match str::from_utf8(&buffer) {
            Ok(magic) => match magic == str::from_utf8(&config.magic).unwrap() {
                true => Result::Ok(true),
                false => Result::Err(format!("Invalid magic found in archive: {}", magic)),
            },
            Err(error) => Result::Err(error.to_string()),
        }
    }

	 pub fn fetch(){ unimplemented!() }
	 pub fn add_resource(){ unimplemented!() }
	 pub fn write_to_file() {}
}

impl fmt::Display for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct ArchiveConfig {
    pub magic: [u8; 5],
    pub flags: u16,
    pub minimum_version: u16,
}

impl ArchiveConfig {
    const DEFAULT_MAGIC: &'static [u8; 5] = b"VfACH";
    const DEFAULT_MAGIC_LENGTH: usize = 5;

    pub fn new(magic: [u8; 5], flags: u16, minimum_version: u16) -> Self {
        ArchiveConfig {
            magic,
            flags,
            minimum_version,
        }
    }
    pub fn default() -> Self {
        ArchiveConfig::new(ArchiveConfig::DEFAULT_MAGIC.clone(), 0, 0)
    }

    pub fn set_flags(&mut self, flag: u16) {
        self.flags = flag;
    }

    pub fn toggle_flag(&mut self, input: u16, mode: bool) {
        match mode {
            true => self.flags = self.flags | input,
            false => self.flags = !self.flags & input,
        };
    }
}

impl fmt::Display for ArchiveConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveConfig] flags: {:#016b}, magic: {}, minimum_version: {}",
            self.flags,
            str::from_utf8(&self.magic).unwrap(),
            self.minimum_version
        )
    }
}

// Basically data obtained from the archive
#[derive(Debug)]
struct ArchiveEntry {
    // Supports 65535 mime types which is more than enough
    mime_type: u16,
    data: Box<[u8]>,
}

impl fmt::Display for ArchiveEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveEntry] mime_type: {m_type}, size: {length}",
            m_type = self.mime_type,
            length = self.data.len()
        )
    }
}

trait Parse {
    fn parse_from_binary() {}
	 fn parse_from_location() {}
}

impl ArchiveEntry {
    fn generate() {
        unimplemented!()
    }
}

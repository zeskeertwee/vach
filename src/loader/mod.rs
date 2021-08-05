#![allow(dead_code)]
#![allow(unused_variables)]

use std::{fmt, fs::File, io::{BufReader, Read, Seek, SeekFrom}, str};

#[derive(Debug)]
pub struct Header {
    magic: [u8; ArchiveConfig::DEFAULT_MAGIC_LENGTH], // VfACH
    version: u16,
    flags: u32,
    entries: u16,
}

impl Header {
    pub fn empty() -> Self {
        Self {
            magic: ArchiveConfig::DEFAULT_MAGIC.clone(),
            flags: 0,
            version: 0,
            entries: 0,
        }
    }
    pub fn from_file(file: &File, big_endian: &bool) -> Self {
        let mut reader = BufReader::new(file);

        // Construct header
        let mut header = Header::empty();
        // TODO: Remove this repetitive garbage

        // Read magic
        let mut buffer = [0; ArchiveConfig::DEFAULT_MAGIC_LENGTH];
        reader.read(&mut buffer).unwrap();
        header.magic = buffer.clone();

        // Read flags, u32 from [u8;4]
        let mut buffer = [0; ArchiveConfig::DEFAULT_FLAG_SIZE];
        reader.read(&mut buffer).unwrap();
        header.flags = if *big_endian {
            u32::from_be_bytes(buffer)
        } else {
            u32::from_le_bytes(buffer)
        };

        // Read version, u16 from [u8;2]
        let mut buffer = [0; ArchiveConfig::DEFAULT_VERSION_SIZE];
        reader.read(&mut buffer).unwrap();
        header.version = if *big_endian {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };

        // Read number of entries, u16 from [u8;2]
        let mut buffer = [0; ArchiveConfig::DEFAULT_ENTRY_SIZE];
        reader.read(&mut buffer).unwrap();
        header.entries = if *big_endian {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };
        
        header
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

#[derive(Debug)]
pub struct Archive {
    header: Header,
    registry: Registry,
    big_endian: bool,
    data: File,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl Archive {
    pub fn new(file: File) -> Result<Archive, String> {
        Archive::with_options(file, ArchiveConfig::default())
    }
    pub fn with_options(file: File, config: ArchiveConfig) -> Result<Archive, String> {
        match Archive::validate(&file, &config) {
            Ok(_) => {
                let big_endian = cfg!(target_endian = "big");
                let header = Header::from_file(&file, &big_endian);
                unimplemented!()
            }
            Err(error) => Err(error),
        }
    }

    pub fn validate(file: &File, config: &ArchiveConfig) -> Result<bool, String> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(0)).unwrap();
        
        let mut buffer = [0; ArchiveConfig::DEFAULT_MAGIC_LENGTH];

        reader.read(&mut buffer).unwrap();

        match str::from_utf8(&buffer) {
            Ok(magic) => {
                if magic != str::from_utf8(&config.magic).unwrap() {
                    return Err(format!("Invalid magic found in archive: {}", magic));
                }
            }
            Err(error) => return Err(error.to_string()),
        };

        let mut buffer = [0; ArchiveConfig::DEFAULT_VERSION_SIZE];
        reader.read(&mut buffer).unwrap();

        // NOTE: Respect the OS's endianness
        let archive_version = if cfg!(target_endian = "big") {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };
        if config.minimum_version > archive_version {
            return Err(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum version: {}",
                archive_version, config.minimum_version
            ));
        };
        Result::Ok(true)
    }
}

impl fmt::Display for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct ArchiveConfig {
    pub magic: [u8; 5],
    pub minimum_version: u16,
}

impl ArchiveConfig {
    const DEFAULT_MAGIC: &'static [u8; 5] = b"VfACH";
    const DEFAULT_MAGIC_LENGTH: usize = 5;
    const DEFAULT_FLAG_SIZE: usize = 4;
    const DEFAULT_VERSION_SIZE: usize = 2;
    const DEFAULT_ENTRY_SIZE: usize = 2;

    pub fn new(magic: [u8; 5], minimum_version: u16) -> Self {
        ArchiveConfig {
            magic,
            minimum_version,
        }
    }
    pub fn default() -> Self {
        ArchiveConfig::new(ArchiveConfig::DEFAULT_MAGIC.clone(), 0)
    }
    pub fn set_minimum_version(mut self, version: &u16) -> Self {
        self.minimum_version = version.clone();
        self
    }
}

impl fmt::Display for ArchiveConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveConfig] magic: {}, minimum_version: {}",
            str::from_utf8(&self.magic).unwrap(),
            self.minimum_version
        )
    }
}

#[derive(Debug)]
pub struct Registry {
    entries_count: usize,
    entries: Vec<RegistryEntry>,
}

#[derive(Debug)]
pub struct RegistryEntry {
    content_version: u32,
    path_name_start: u64,
    path_name_end: u64,

    is_compressed: bool,

    is_signed: bool,
    signature: u32,

    index: u64,
    byte_offset: u64,

    mime_type: u16,
}

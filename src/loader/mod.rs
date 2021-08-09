#![allow(unused)]

pub mod header;
pub mod registry;

use std::{
    fmt,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    str,
    sync::Arc,
};

#[derive(Debug)]
pub struct Archive {
    header: header::Header,
    registry: registry::Registry,
    big_endian: bool,
    data: Option<File>,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl Archive {
    pub fn empty() -> Archive {
        Archive {
            header: header::Header::empty(),
            registry: registry::Registry::empty(),
            big_endian: cfg!(target_endian = "big"),
            data: None,
        }
    }
    pub fn from_file(file: File) -> Result<Archive, String> {
        Archive::with_config(file, &header::Config::default())
    }
    pub fn with_config(file: File, config: &header::Config) -> Result<Archive, String> {
        match Archive::validate(&file, config) {
            Result::Ok(_) => {
                let big_endian = cfg!(target_endian = "big");
                let header = header::Header::from_file(&file, &big_endian).unwrap();
                let registry = registry::Registry::from_file(&file, &big_endian).unwrap();
                Result::Ok(Archive {
                    header,
                    registry,
                    big_endian,
                    data: Some(file),
                })
            }
            Result::Err(error) => Result::Err(error),
        }
    }

    pub fn validate(file: &File, config: &header::Config) -> Result<bool, String> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(0)).unwrap();

        let mut buffer = [0; header::Config::MAGIC_LENGTH];

        reader.read(&mut buffer).unwrap();

        match str::from_utf8(&buffer) {
            Result::Ok(magic) => {
                if magic != str::from_utf8(&config.magic).unwrap() {
                    return Result::Err(format!("Invalid magic found in archive: {}", magic));
                }
            }
            Result::Err(error) => return Result::Err(error.to_string()),
        };

        let mut buffer = [0; header::Config::VERSION_SIZE];
        reader.read(&mut buffer).unwrap();

        // NOTE: Respect the OS's endianness
        let archive_version = if cfg!(target_endian = "big") {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        };
        if config.minimum_version > archive_version {
            return Result::Err(format!(
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

use anyhow;
use crate::global::{
    storage::Storage,
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
};
use std::{
    fmt,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    str,
    sync::Arc,
};

pub mod resource;
use resource::Resource;


#[derive(Debug)]
pub struct Archive {
    header: Header,
    registry: Registry,
    storage: Storage,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl Archive {
    pub fn empty() -> Archive {
        Archive {
            header: Header::empty(),
            registry: Registry::empty(),
            storage: Storage::Vector(vec![]),
        }
    }
    pub fn from_file(file: File) -> anyhow::Result<Archive> {
        Archive::with_config(file, &HeaderConfig::default())
    }
    pub fn with_config(file: File, config: &HeaderConfig) -> anyhow::Result<Archive> {
        match Archive::validate(&file, config) {
            Ok(_) => {
                let header = Header::from_file(&file)?;
                let registry = Registry::from_file(&file, &header)?;
                Result::Ok(Archive {
                    header,
                    registry,
                    storage: Storage::File(file),
                })
            }
            Err(error) => Result::Err(error),
        }
    }

    pub fn validate(file: &File, config: &HeaderConfig) -> anyhow::Result<bool> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(0))?;

        let mut buffer = [0; HeaderConfig::MAGIC_LENGTH];

        reader.read(&mut buffer)?;

        if &buffer != &config.magic {
            return Result::Err(anyhow::Error::msg(format!(
                "Invalid magic found in archive: {}",
                str::from_utf8(&buffer)?
            )));
        };

        let mut buffer = [0; HeaderConfig::VERSION_SIZE];
        reader.read(&mut buffer)?;

        let archive_version = u16::from_ne_bytes(buffer);
        if config.minimum_version > archive_version {
            return Result::Err(anyhow::Error::msg(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum version: {}",
                archive_version, config.minimum_version
            )));
        };

        Result::Ok(true)
    }

    // Filesystem functions
    pub fn fetch(&self, path: &String) -> anyhow::Result<Resource> {
        let entry = self.registry.fetch(path, &self.storage)?;

        match &self.storage {
            Storage::File(file) => {
                unimplemented!();
            },
            Storage::Vector(vector) => {
                unimplemented!();
            }
        }
    }
    pub fn append(&self, resource: &Resource, path: &String) -> anyhow::Result<()> {
        unimplemented!()
    }
    pub fn delete(&mut self, path: &String) -> anyhow::Result<()>{
        unimplemented!()
    }
}

impl fmt::Display for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

use anyhow;
use super::resource::Resource;
use crate::global::{
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
    storage::Storage,
};
use std::{
    fmt,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    str,
    sync::Arc,
};

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
    pub fn from_storage(store: Storage) -> anyhow::Result<Archive> {
        Archive::with_config(store, &HeaderConfig::default())
    }
    pub fn with_config(store: Storage, config: &HeaderConfig) -> anyhow::Result<Archive> {
        match Archive::validate(&store, config) {
            Ok(_) => {
                let header = Header::from_storage(&store)?;
                let registry = Registry::from_storage(&store, &header)?;
                Result::Ok(Archive {
                    header,
                    registry,
                    storage: store,
                })
            }
            Err(error) => Result::Err(error),
        }
    }

    pub fn validate(store: &Storage, config: &HeaderConfig) -> anyhow::Result<bool> {
        match store {
            Storage::File(file) => {
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
            },
            Storage::Vector(vector) => {
                unimplemented!()
            }
        }
    }

    // Filesystem functions
    pub fn fetch(&self, path: &String) -> anyhow::Result<&Resource> { self.registry.fetch(path, &self.storage) }
    pub fn append(&mut self, resource: &Resource, path: &String) -> anyhow::Result<RegistryEntry> { self.registry.append(path, resource, &mut self.storage) }
    pub fn delete(&mut self, path: &String) -> anyhow::Result<()> { self.registry.delete(path, &mut self.storage) }
}

impl fmt::Display for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

use anyhow;
use super::resource::Resource;
use crate::global::{
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
};
use std::{fmt, io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write}, str, sync::Arc};

#[derive(Debug)]
pub struct Archive<T> {
    header: Header,
    registry: Registry,
    storage: T,
}

impl Archive<Cursor<Vec<u8>>> {
    pub fn empty() -> Archive<Cursor<Vec<u8>>> {
        Archive {
            header: Header::empty(),
            registry: Registry::empty(),
            storage: Cursor::new(Vec::new()),
        }
    }
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
    pub fn from(storage: T) -> anyhow::Result<Archive<T>> {
        Archive::with_config(storage, &HeaderConfig::default())
    }
    pub fn with_config(mut storage: T, config: &HeaderConfig) -> anyhow::Result<Archive<T>> {
        match Archive::<T>::validate(&mut storage, config) {
            Ok(_) => {
                let header = Header::from(&mut storage)?;
                let registry = Registry::from(&mut storage, &header)?;
                Result::Ok(Archive { header, registry, storage })
            }
            Err(error) => Result::Err(error),
        }
    }

    pub fn validate(storage: &mut T, config: &HeaderConfig) -> anyhow::Result<bool> {
        let mut reader = BufReader::new(storage);
        reader.seek(SeekFrom::Start(0))?;

        let mut buffer = [0; HeaderConfig::MAGIC_LENGTH];

        reader.read(&mut buffer)?;

        if &buffer != &config.magic {
            return Result::Err( anyhow::Error::msg(format!("Invalid magic found in archive: {}", str::from_utf8(&buffer)?)) );
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
    pub fn fetch(&mut self, path: &String) -> anyhow::Result<&Resource> {
        let reader = BufReader::new(&mut self.storage);
        self.registry.fetch(path, &reader)
    }
}

impl<T: Read + Seek + Write> Archive<T> {
    pub fn append(&mut self, resource: &Resource, path: &String) -> anyhow::Result<RegistryEntry> {
        let mut writer = BufWriter::new(&mut self.storage);
        self.registry.append(path, resource, &mut writer)
    }
    pub fn delete(&mut self, path: &String) -> anyhow::Result<()> {
        let mut writer = BufWriter::new(&mut self.storage);
        self.registry.delete(path, &mut writer)
    }
}

impl<T> fmt::Display for Archive<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

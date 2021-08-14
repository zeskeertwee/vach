use anyhow;
use super::resource::Resource;
use crate::global::{
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
};
use std::{
    fmt,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    str,
    sync::Arc
};

#[derive(Debug)]
pub struct Archive<T: Seek + Read> {
    header: Header,
    registry: Registry,
    reader: BufReader<T>,
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
    pub fn empty() -> Archive<Cursor<Vec<u8>>> {
        Archive {
            header: Header::empty(),
            registry: Registry::empty(),
            reader: BufReader::new(Cursor::new(Vec::new())),
        }
    }
    pub fn from(reader: BufReader<T>) -> anyhow::Result<Archive<T>> {
        Archive::with_config(reader, &HeaderConfig::default())
    }
    pub fn with_config(mut reader: BufReader<T>, config: &HeaderConfig) -> anyhow::Result<Archive<T>> {
        match Archive::<T>::validate(&mut reader, config) {
            Ok(_) => {
                let header = Header::from(&mut reader)?;
                let registry = Registry::from(&mut reader, &header)?;
                Result::Ok(Archive { header, registry, reader })
            }
            Err(error) => Result::Err(error),
        }
    }

    pub fn validate(reader: &mut BufReader<T>, config: &HeaderConfig) -> anyhow::Result<bool> {
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
    pub fn fetch(&self, path: &String) -> anyhow::Result<&Resource> { self.registry.fetch(path, &self.reader) }
    pub fn append(&mut self, resource: &Resource, path: &String) -> anyhow::Result<RegistryEntry> { self.registry.append(path, resource, &mut self.reader) }
    pub fn delete(&mut self, path: &String) -> anyhow::Result<()> { self.registry.delete(path, &mut self.reader) }
}

impl<T: Seek + Read> fmt::Display for Archive<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!();
    }
}

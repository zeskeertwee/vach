use anyhow;
use super::resource::Resource;
use crate::global::{
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
};
use std::{fmt, io::{Cursor, Read, Seek, SeekFrom}, str, sync::Arc};

#[derive(Debug)]
pub struct Archive<T> { 
    header: Header,
    registry: Registry,
    handle: T,
}

impl Archive<Cursor<Vec<u8>>> {
    pub fn empty() -> Archive<Cursor<Vec<u8>>> {
        Archive {
            header: Header::empty(),
            registry: Registry::empty(),
            handle: Cursor::new(Vec::new()),
        }
    }
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
    pub fn from(handle: T) -> anyhow::Result<Archive<T>> {
        Archive::with_config(handle, &HeaderConfig::default())
    }
    
    pub fn with_config(mut handle: T, config: &HeaderConfig) -> anyhow::Result<Archive<T>> {
        match Archive::validate(&mut handle, config) {
            Ok(_) => {
                let header = Header::from(&mut handle)?;
                let registry = Registry::from(&mut handle, &header)?;

                Ok(Archive { header, registry, handle })
            }
            Err(error) => Err(error),
        }
    }

    pub fn fetch(&mut self, path: &str) -> anyhow::Result<Resource> {
        self.registry.fetch(path, &mut self.handle)
    }

    pub fn validate(handle: &mut T, config: &HeaderConfig) -> anyhow::Result<bool> {
        handle.seek(SeekFrom::Start(0))?;

        // Validate magic
        let mut buffer = [0; HeaderConfig::MAGIC_LENGTH];
        handle.read_exact(&mut buffer)?;

        if buffer != config.magic {
            anyhow::bail!(format!("Invalid magic found in archive: {}", str::from_utf8(&buffer)?));
        };

        // Validate version
        let mut buffer = [0; HeaderConfig::VERSION_SIZE];
        handle.read_exact(&mut buffer)?;

        let archive_version = u16::from_le_bytes(buffer);
        if config.minimum_version > archive_version {
            anyhow::bail!(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum version: {}",
                archive_version, config.minimum_version
            ))
        };

        Ok(true)
    }
}

impl<T> fmt::Display for Archive<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{header}\n{registry}", header=self.header, registry=self.registry)
    }
}

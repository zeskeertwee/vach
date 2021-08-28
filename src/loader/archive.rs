use anyhow;
use super::resource::Resource;
use crate::global::{
    header::{Header, HeaderConfig},
    registry::{Registry, RegistryEntry},
};
use std::{io::{BufReader, Cursor, Read, Seek, SeekFrom}, str};
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct Archive<T> { 
    header: Header,
    pub registry: Registry,
    handle: T,
    key: Option<esdalek::PublicKey>
}

impl Archive<Cursor<Vec<u8>>> {
    pub fn empty() -> Archive<Cursor<Vec<u8>>> {
        Archive {
            header: Header::default(),
            registry: Registry::empty(),
            handle: Cursor::new(Vec::new()),
            key: None
        }
    }
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T: Seek + Read> Archive<T> {
    pub fn from(handle: T) -> anyhow::Result<Archive<T>> {
        Archive::with_config(handle, &HeaderConfig::new())
    }

    pub fn with_config(mut handle: T, config: &HeaderConfig) -> anyhow::Result<Archive<T>> {
        let mut reader = BufReader::new(&mut handle);
        Archive::validate(&mut reader, config)?;

        let header = Header::from(&mut reader)?;
        let registry = Registry::from(&mut reader, &header, &config.public_key)?;

        Ok(Archive { header, registry, handle, key: config.public_key })
    }

    // Query functions
    pub fn fetch(&mut self, id: &str) -> anyhow::Result<Resource> {
        self.registry.fetch(id, &mut self.handle, &self.key)
    }
    pub fn fetch_entry(&mut self, id: &str) -> Option<&RegistryEntry> {
        self.registry.fetch_entry(id)
    }

    pub fn validate(handle: &mut T, config: &HeaderConfig) -> anyhow::Result<bool> {
        handle.seek(SeekFrom::Start(0))?;

        // Validate magic
        let mut buffer = [0x72; HeaderConfig::MAGIC_LENGTH];
        handle.read_exact(&mut buffer)?;

        if buffer != config.magic {
            anyhow::bail!(format!("Invalid magic found in archive: {}", str::from_utf8(&buffer)?));
        };

        // Jump the flags
        handle.seek(SeekFrom::Current(2))?;

        // Validate version
        let mut buffer = [0x72; HeaderConfig::VERSION_SIZE];
        handle.read_exact(&mut buffer)?;

        let archive_version = u16::from_le_bytes(buffer);
        if config.minimum_version > archive_version {
            anyhow::bail!(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum acceptable version: {}",
                archive_version, config.minimum_version
            ))
        };

        Ok(true)
    }
}

impl Default for Archive<Cursor<Vec<u8>>> {
    fn default() -> Archive<Cursor<Vec<u8>>> {
        Archive::empty()
    }
}
use crate::{
    global::{
        header::{Header, HeaderConfig},
        storage::Storage,
        types::RegisterType,
    },
    loader::resource::Resource,
};
use std::{
    convert::TryInto,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
};

#[derive(Debug)]
pub struct Registry {
    pub entries: Vec<RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry { entries: vec![] }
    }
    pub fn from_storage(store: &Storage, header: &Header) -> anyhow::Result<Registry> {
        match store {
            Storage::File(file) => {
                let mut reader = BufReader::new(file);
                reader.seek(SeekFrom::Start(HeaderConfig::SIZE as u64));

                let mut entries: Vec<RegistryEntry> = vec![];
                for i in 0..header.capacity {
                    let mut buffer = [0; RegistryEntry::SIZE];
                    reader.read(&mut buffer);
                    entries.push(RegistryEntry::from_bytes(buffer)?);
                }
                Result::Ok(Registry { entries })
            }
            Storage::Vector(vector) => {
                unimplemented!()
            }
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        self.entries.iter().for_each(|entry| {
            buffer.append(&mut entry.bytes());
        });

        buffer
    }

    pub fn fetch_entry(&self, path: &String, store: &Storage) -> Option<&RegistryEntry> {
        match store {
            Storage::File(file) => {
                unimplemented!()
            }
            Storage::Vector(vector) => {
                unimplemented!()
            }
        }
    }
    pub fn fetch(&self, path: &String, store: &Storage) -> anyhow::Result<&Resource> {
        let iter = self.entries.iter();
        let mut found = self
            .fetch_entry(path, store)
            .ok_or(anyhow::Error::msg(format!("Resource not found: {}", path)))?;
        unimplemented!()
    }
    pub fn append( &mut self, path: &String, resource: &Resource, store: &mut Storage, ) -> anyhow::Result<RegistryEntry> {
        unimplemented!()
    }
    pub fn delete(&mut self, path: &String, store: &mut Storage) -> anyhow::Result<()> {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegistryEntry {
    pub flags: u16,
    pub mime_type: u16,
    pub content_version: u8,
    pub signature: u32,

    pub path_name_start: RegisterType,
    pub path_name_end: RegisterType,

    pub location: RegisterType,
    pub length: RegisterType,
}

impl RegistryEntry {
    pub const SIZE: usize = 41;
    pub fn from_bytes(buffer: [u8; Self::SIZE]) -> anyhow::Result<RegistryEntry> {
        Ok(RegistryEntry {
            flags: u16::from_ne_bytes(buffer[0..2].try_into()?),
            mime_type: u16::from_ne_bytes(buffer[2..4].try_into()?),
            content_version: *buffer
                .get(4)
                .ok_or(anyhow::Error::msg("Out of bounds error"))?,
            signature: u32::from_ne_bytes(buffer[5..9].try_into()?),
            path_name_start: RegisterType::from_ne_bytes(buffer[9..17].try_into()?),
            path_name_end: RegisterType::from_ne_bytes(buffer[17..25].try_into()?),
            location: RegisterType::from_ne_bytes(buffer[25..33].try_into()?),
            length: RegisterType::from_ne_bytes(buffer[33..41].try_into()?),
        })
    }
    pub fn empty() -> RegistryEntry {
        RegistryEntry {
            flags: 0,
            mime_type: 0,
            content_version: 0,
            signature: 0,
            path_name_start: 0,
            path_name_end: 0,
            location: 0,
            length: 0,
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.flags.to_ne_bytes());
        buffer.extend_from_slice(&self.mime_type.to_ne_bytes());
        buffer.push(self.content_version);
        buffer.extend_from_slice(&self.signature.to_ne_bytes());
        buffer.extend_from_slice(&self.path_name_start.to_ne_bytes());
        buffer.extend_from_slice(&self.path_name_end.to_ne_bytes());
        buffer.extend_from_slice(&self.location.to_ne_bytes());
        buffer.extend_from_slice(&self.length.to_ne_bytes());

        buffer
    }
}

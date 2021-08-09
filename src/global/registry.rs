use crate::global::header::{Header, HeaderConfig};
use std::{convert::TryInto, fs::File, io::{BufReader, Read, Seek, SeekFrom}};

#[derive(Debug)]
pub struct Registry {
    entries: Vec<RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry {
            entries: vec![],
        }
    }
    pub fn from_file(file: &File, header: &Header) -> Result<Registry, String> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start((HeaderConfig::ENTRY_SIZE + HeaderConfig::FLAG_SIZE + HeaderConfig::VERSION_SIZE + HeaderConfig::MAGIC_LENGTH) as u64));
        
        let mut entries:Vec<RegistryEntry> = vec![];
        for i in 0..header.capacity{
            let mut buffer = [0; RegistryEntry::ENTRY_SIZE];
            reader.read(&mut buffer);
            entries.push(RegistryEntry::from_bytes(buffer));
        };
        Result::Ok(Registry { entries })
    }
}

#[derive(Debug)]
pub struct RegistryEntry {
    flags: u16,
    mime_type: u16,
    content_version: u8,
    signature: u32,

    path_name_start: u32,
    path_name_end: u32,

    index: u32,
    offset: u32,
}

impl RegistryEntry {
    const ENTRY_SIZE: usize = 25;
    pub fn from_bytes(buffer: [u8; Self::ENTRY_SIZE]) -> RegistryEntry {
        RegistryEntry{
            flags: u16::from_ne_bytes(buffer[0..2].try_into().unwrap()),
            mime_type: u16::from_ne_bytes(buffer[2..4].try_into().unwrap()),
            content_version: buffer[4],
            signature: u32::from_ne_bytes(buffer[5..9].try_into().unwrap()),
            path_name_start: u32::from_ne_bytes(buffer[9..13].try_into().unwrap()),
            path_name_end: u32::from_ne_bytes( buffer[13..17].try_into().unwrap()),
            index: u32::from_ne_bytes(buffer[17..21].try_into().unwrap()),
            offset: u32::from_ne_bytes(buffer[21..25].try_into().unwrap())
        }
    }
    pub fn bytes(&self) -> Vec<u8>{
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.flags.to_ne_bytes());
        buffer.extend_from_slice(&self.mime_type.to_ne_bytes());
        buffer.push(self.content_version);
        buffer.extend_from_slice(&self.signature.to_ne_bytes());
        buffer.extend_from_slice(&self.path_name_start.to_ne_bytes());
        buffer.extend_from_slice(&self.path_name_end.to_ne_bytes());
        buffer.extend_from_slice(&self.index.to_ne_bytes());
        buffer.extend_from_slice(&self.offset.to_ne_bytes());

        buffer
    }
}
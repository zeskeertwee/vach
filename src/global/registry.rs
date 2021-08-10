use crate::global::header::{Header, HeaderConfig};
use std::{convert::TryInto, fs::File, io::{BufReader, Read, Seek, SeekFrom}};

pub type RegisterType = u64;

#[derive(Debug)]
pub struct Registry {
    pub entries: Vec<RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry {
            entries: vec![],
        }
    }
    pub fn from_file(file: &File, header: &Header) -> anyhow::Result<Registry> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(HeaderConfig::SIZE as u64));
        
        let mut entries:Vec<RegistryEntry> = vec![];
        for i in 0..header.capacity{
            let mut buffer = [0; RegistryEntry::SIZE];
            reader.read(&mut buffer);
            entries.push(RegistryEntry::from_bytes(buffer)?);
        };
        dbg!(reader.stream_position()?);
        Result::Ok(Registry { entries })
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        self.entries.iter().for_each(|entry|{
            buffer.append(&mut entry.bytes().clone());
        });

        buffer
    }
}

#[derive(Debug)]
pub struct RegistryEntry {
    flags: u16,
    mime_type: u16,
    content_version: u8,
    signature: u32,

    path_name_start: RegisterType,
    path_name_end: RegisterType,

    index: RegisterType,
    offset: RegisterType,
}

impl RegistryEntry {
    pub const SIZE: usize = 41;
    pub fn from_bytes(buffer: [u8; Self::SIZE]) -> anyhow::Result<RegistryEntry> {
        Ok(RegistryEntry{
            flags: u16::from_ne_bytes(buffer[0..2].try_into()?),
            mime_type: u16::from_ne_bytes(buffer[2..4].try_into()?),
            content_version: *buffer.get(4).ok_or(anyhow::Error::msg("Out of bounds error"))?,
            signature: u32::from_ne_bytes(buffer[5..9].try_into()?),
            path_name_start: RegisterType::from_ne_bytes(buffer[9..17].try_into()?),
            path_name_end: RegisterType::from_ne_bytes( buffer[17..25].try_into()?),
            index: RegisterType::from_ne_bytes(buffer[25..33].try_into()?),
            offset: RegisterType::from_ne_bytes(buffer[33..41].try_into()?)
        })
    }
    pub fn empty() -> RegistryEntry {
        RegistryEntry{
            flags: 0,
            mime_type: 0,
            content_version: 0,
            signature: 0,
            path_name_start: 0,
            path_name_end: 0,
            index: 0,
            offset: 0,
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

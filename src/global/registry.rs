use crate::global::header::{Header, HeaderConfig};
use std::{
    fs::File,
    io::{BufReader, Seek, SeekFrom},
};

#[derive(Debug)]
pub struct Registry {
    entries_count: usize,
    entries: Vec<RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry {
            entries_count: 0,
            entries: vec![],
        }
    }
    pub fn from_file(file: &File, header: &Header) -> Result<Registry, String> {
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start((HeaderConfig::ENTRY_SIZE + HeaderConfig::FLAG_SIZE + HeaderConfig::VERSION_SIZE + HeaderConfig::MAGIC_LENGTH) as u64));
        
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct RegistryEntry {
    flags: u16,
    mime_type: u16,
    content_version: u32,
    signature: u32,

    path_name_start: u32,
    path_name_end: u32,

    index: u32,
    byte_offset: u32,
}

impl RegistryEntry {
    const ENTRY_SIZE: usize = 18;
}
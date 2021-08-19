use crate::{global::{
        header::{Header, HeaderConfig},
        types::{RegisterType, SignatureType},
        flags::RegEntryFlags
    }, loader::resource::Resource,
};
use std::{
    convert::TryInto,
    io::{Read, Seek, SeekFrom},
    collections::HashMap,
    fmt
};
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct Registry {
    pub entries: HashMap<String, RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry { entries: HashMap::new() }
    }
}

impl Registry {
    pub fn from<T: Seek + Read>(handle: &mut T, header: &Header) -> anyhow::Result<Registry> {
        handle.seek(SeekFrom::Start(HeaderConfig::BASE_SIZE as u64));

        let mut entries = HashMap::new();
        for i in 0..header.capacity {
            let (entry, path) = RegistryEntry::from(handle)?;
            entries.insert(path, entry);
        }

        Ok(Registry { entries })
    }

    pub fn fetch<T: Seek + Read>(&self, path: &str, handle: &mut T) -> anyhow::Result<Resource> {
        match self.fetch_entry(path) {
            None => anyhow::bail!(format!("Resource not found: {}", path)),
            Some(entry) => {
                let mut reader = handle.take(entry.length);
                let mut buffer = vec![];
                reader.read_to_end(&mut buffer);

                // --- snip --- IGNORED VALIDATION, DECOMPRESSION

                let mut resource = Resource::empty();
                resource.flags = entry.flags;
                resource.content_version = entry.content_version;
                resource.data = buffer;

                Ok(resource)
            }
        }
    }
    pub fn fetch_entry(&self, path: &str) -> Option<&RegistryEntry> { self.entries.get(path) }
}

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { unimplemented!() }
}

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub flags: u16,
    pub content_version: u8,
    pub signature: Option<SignatureType>,

    pub location: RegisterType,
    pub length: RegisterType,
}

impl RegistryEntry {
    // 2 + 1 + esdalek::SIGNATURE_LENGTH + 8 + 8
    pub const MAX_SIZE: usize = 83 + 8;

    pub fn empty() -> RegistryEntry {
        RegistryEntry {
            flags: 0,
            content_version: 0,
            signature: None,
            location: 0,
            length: 0
        }
    }
    pub fn from<T: Read + Seek>(handle: &mut T) -> anyhow::Result<(Self, String)> {
        let mut buffer = [0; RegistryEntry::MAX_SIZE];
        handle.read(&mut buffer);

        // Construct entry
        let mut entry = RegistryEntry::empty();
        entry.flags = u16::from_le_bytes(buffer[0..2].try_into()?);
        entry.content_version = buffer[2];
        entry.signature = Some(buffer[3..67].try_into()?);
        entry.location = RegisterType::from_le_bytes(buffer[67..75].try_into()?);
        entry.length = RegisterType::from_le_bytes(buffer[75..83].try_into()?);

        // Construct path
        let path_length  = u64::from_le_bytes(buffer[83..91].try_into()?);
        let mut path = String::new();
        handle.take(path_length).read_to_string(&mut path);

        Ok((entry, path))
    }

    // Flags helper functions
    pub fn is_compressed(&self) -> bool { (self.flags & RegEntryFlags::COMPRESSED) != 0 }
    pub fn is_signed(&self) -> bool { self.flags & RegEntryFlags::SIGNED != 0 }
}

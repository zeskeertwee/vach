use crate::{global::{
        header::{Header, HeaderConfig},
        types::{RegisterType, FlagType},
        flags::Flags
    }, loader::resource::Resource};
use std::{
    convert::TryInto,
    io::{Read, Seek, SeekFrom},
    fmt
};
use ed25519_dalek::{self as esdalek, Verifier};
use lz4_flex as lz4;
use hashbrown::HashMap;

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

    pub fn fetch<T: Seek + Read>(&self, path: &str, handle: &mut T, key: &Option<esdalek::PublicKey>) -> anyhow::Result<Resource> {
        if let Some(entry) = self.fetch_entry(path) {
            handle.seek(SeekFrom::Start(entry.location));

            let mut reader = handle.take(entry.length);
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer);

            // Validate then decompress
            if entry.is_signed() {
                match (&entry.signature, key) {
                    // It is signed, and we have a key
                    (Some(signature), Some(key)) => {
                        key.verify(&buffer, signature);
                    },

                    // It is signed but no key was provided
                    (_, None) => { anyhow::bail!(format!("Leaf: {}, found with signature, but no key was provided", path)) },

                    // Ignore all other possible configurations
                    (_, _) => {}
                };
            };

            if entry.is_compressed() { buffer = lz4::decompress_size_prepended(&buffer)? };

            let mut resource = Resource::empty();
            resource.flags = entry.flags;
            resource.content_version = entry.content_version;
            resource.data = buffer;

            Ok(resource)
        } else {
            anyhow::bail!(format!("Resource not found: {}", path))
        }
    }
    pub fn fetch_entry(&self, path: &str) -> Option<&RegistryEntry> { self.entries.get(path) }
}

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { unimplemented!() }
}

impl Default for Registry {
    fn default() -> Registry {
        Registry::empty()
    }
}

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub flags: FlagType,
    pub content_version: u8,
    pub signature: Option<esdalek::Signature>,

    pub location: RegisterType,
    pub length: RegisterType,
}

impl RegistryEntry {
    // 2 + 1 + esdalek::SIGNATURE_LENGTH + 8 + 8
    pub const MIN_SIZE: usize = 83 + 8;

    pub fn empty() -> RegistryEntry {
        RegistryEntry {
            flags: FlagType::default(),
            content_version: 0,
            signature: None,
            location: 0,
            length: 0
        }
    }
    pub fn from<T: Read + Seek>(handle: &mut T) -> anyhow::Result<(Self, String)> {
        let mut buffer = [0; RegistryEntry::MIN_SIZE];
        handle.read_exact(&mut buffer);

        // Construct entry
        let mut entry = RegistryEntry::empty();
        entry.flags = FlagType::from_bits(u16::from_le_bytes(buffer[0..2].try_into()?)).unwrap();
        entry.content_version = buffer[2];

        // Only produce a flag from data that is signed
        if entry.flags.contains(FlagType::SIGNED) { entry.signature = Some(buffer[3..67].try_into()?) };

        entry.location = RegisterType::from_le_bytes(buffer[67..75].try_into()?);
        entry.length = RegisterType::from_le_bytes(buffer[75..83].try_into()?);

        // Construct path
        let path_length  = u64::from_le_bytes(buffer[83..91].try_into()?);
        let mut path = String::new();
        handle.take(path_length).read_to_string(&mut path);

        Ok((entry, path))
    }

    // Flags helper functions
    pub fn is_compressed(&self) -> bool { (Flags::COMPRESSED.contains(self.flags)) }
    pub fn is_signed(&self) -> bool { Flags::SIGNED.contains(self.flags) }

    pub fn bytes(&self, path_length: &RegisterType) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
        buffer.extend_from_slice(&self.content_version.to_le_bytes());
        match self.signature {
            Some(signature) => { buffer.extend_from_slice(&signature.to_bytes()) },
            None => { buffer.extend_from_slice(&[0x53u8; esdalek::SIGNATURE_LENGTH]) }
        };
        buffer.extend_from_slice(&self.location.to_le_bytes());
        buffer.extend_from_slice(&self.length.to_le_bytes());
        buffer.extend_from_slice(&path_length.to_le_bytes());
        buffer
    }
}

impl Default for RegistryEntry {
    fn default() -> RegistryEntry {
        RegistryEntry::empty()
    }
}

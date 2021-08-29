use crate::{
    global::{
        header::{Header, HeaderConfig},
        types::{RegisterType, FlagType}
    },
    loader::resource::Resource
};
use std::{
    convert::TryInto,
    io::{Read, Seek, SeekFrom}
};
use ed25519_dalek::{self as esdalek, Verifier};
use lz4_flex as lz4;
use hashbrown::HashMap;

#[derive(Debug)]
pub(crate) struct Registry {
    pub entries: HashMap<String, RegistryEntry>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry { entries: HashMap::new() }
    }
}

impl Registry {
    pub fn from<T: Seek + Read>(handle: &mut T, header: &Header) -> anyhow::Result<Registry> {
        handle.seek(SeekFrom::Start(HeaderConfig::BASE_SIZE as u64))?;

        // Generate and store Registry Entries
        let mut entries = HashMap::new();
        for _ in 0..header.capacity {
            let (entry, id) = RegistryEntry::from(handle)?;
            entries.insert(id, entry);
        };

        Ok(Registry { entries })
    }

    pub fn fetch<T: Seek + Read>(&self, id: &str, handle: &mut T, key: &Option<esdalek::PublicKey>) -> anyhow::Result<Resource> {
        if let Some(entry) = self.fetch_entry(id) {
            handle.seek(SeekFrom::Start(entry.location))?;

            let mut take = handle.take(entry.offset);
            let mut buffer = Vec::new();
            take.read_to_end(&mut buffer)?;

            // Every time a fetch is done, check for tampering: May be made conditional
            if entry.is_signed() {
                if let Some(pub_key) = &key {
                    if let Err(error) = pub_key.verify(&buffer, &entry.signature){
                        anyhow::bail!(format!("({}): Invalid signature found for leaf with ID: {}", error, id))
                    };
                }
            };

            if entry.is_compressed() { buffer = lz4::decompress_size_prepended(&buffer)? };

            let mut resource = Resource::empty();
            resource.flags = entry.flags;
            resource.content_version = entry.content_version;
            resource.data = buffer;

            Ok(resource)
        } else {
            anyhow::bail!(format!("Resource not found: {}", id))
        }
    }
    pub fn fetch_entry(&self, id: &str) -> Option<&RegistryEntry> { self.entries.get(id) }
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
    pub signature: esdalek::Signature,

    pub location: RegisterType,
    pub offset: RegisterType,
}

impl RegistryEntry {
    // 2 + 1 + esdalek::SIGNATURE_LENGTH + 8 + 8
    pub const MIN_SIZE: usize = 83 + 8;

    pub fn empty() -> RegistryEntry {
        RegistryEntry {
            flags: FlagType::default(),
            content_version: 0,
            signature: esdalek::Signature::new([0; 64]),
            location: 0,
            offset: 0
        }
    }
    pub fn from<T: Read + Seek>(handle: &mut T) -> anyhow::Result<(Self, String)> {
        let mut buffer = [0; RegistryEntry::MIN_SIZE];
        handle.read_exact(&mut buffer)?;

        // Construct entry
        let mut entry = RegistryEntry::empty();
        entry.flags = FlagType::from_bits(u16::from_le_bytes(buffer[0..2].try_into()?)).unwrap();
        entry.content_version = buffer[2];

        // Only produce a flag from data that is signed
        if entry.flags.contains(FlagType::SIGNED) { entry.signature = buffer[3..67].try_into()? };

        entry.location = RegisterType::from_le_bytes(buffer[67..75].try_into()?);
        entry.offset = RegisterType::from_le_bytes(buffer[75..83].try_into()?);

        // Construct ID
        let id_length  = u64::from_le_bytes(buffer[83..91].try_into()?);
        let mut id = String::new();
        handle.take(id_length).read_to_string(&mut id)?;

        Ok((entry, id))
    }

    // Flags helper functions
    pub fn is_compressed(&self) -> bool { self.flags.contains(FlagType::COMPRESSED) }
    pub fn is_signed(&self) -> bool { self.flags.contains(FlagType::SIGNED) }

    pub fn bytes(&self, id_length: &RegisterType) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
        buffer.extend_from_slice(&self.content_version.to_le_bytes());
        if self.is_signed() {
            buffer.extend_from_slice(&self.signature.to_bytes())
        } else {
            buffer.extend_from_slice(&[0x53u8; crate::SIGNATURE_LENGTH])
        };
        buffer.extend_from_slice(&self.location.to_le_bytes());
        buffer.extend_from_slice(&self.offset.to_le_bytes());
        buffer.extend_from_slice(&id_length.to_le_bytes());
        buffer
    }
}

impl Default for RegistryEntry {
    fn default() -> RegistryEntry {
        RegistryEntry::empty()
    }
}

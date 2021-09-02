use crate::global::header::Header;
use std::{convert::TryInto, fs::File, io::{BufReader, Read, Seek, SeekFrom}};
use ed25519_dalek::{PublicKey, Verifier};
use log::info;
use signature::Signature;
use bitflags::bitflags;

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

    /// attempts to read the registry at the current stream position
    pub fn from_reader<R: Read>(reader: &mut BufReader<R>, header: &Header) -> anyhow::Result<Registry> {
        let mut read_buffer = Vec::new();
        let mut entries:Vec<RegistryEntry> = vec![];
        for i in 0..header.registry_size {
            entries.push(RegistryEntry::_from_reader_append_read(reader, &mut read_buffer)?);
        };

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

bitflags! {
    pub struct RegistryEntryFlags: u8 {
        const EMPTY         = 0b00000000;
        const IS_COMPRESSED = 0b00000001;
    }
}

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub(crate) flags: RegistryEntryFlags,
    pub(crate) content_version: u16,
    pub(crate) blob_signature: [u8; ed25519_dalek::SIGNATURE_LENGTH], // signature of the blob with path appended
    
    pub(crate) path_name_length: u16,
    pub(crate) path: Vec<u8>, // length of path_name_length
    
    pub(crate) compressed_size: u32,

    pub(crate) byte_offset: u64, // offset of the blob from the beginning of the file
}

impl RegistryEntry {
    /// size in bytes without the path (since it is variable-length)
    const BASE_SIZE: usize = 1 + 2 + ed25519_dalek::SIGNATURE_LENGTH + 2 + 4 + 8;

    /// attempts to read a registry entry from the current stream position
    fn _from_reader_append_read<R: Read>(reader: &mut BufReader<R>, read_buffer: &mut Vec<u8>) -> anyhow::Result<RegistryEntry> {
        let mut entry = RegistryEntry::empty();

        let mut buffer = [0; 5 + ed25519_dalek::SIGNATURE_LENGTH];
        reader.read_exact(&mut buffer)?;
        entry.flags = RegistryEntryFlags::from_bits(buffer[0]).ok_or(anyhow::anyhow!("Invalid flags"))?;
        entry.content_version = u16::from_le_bytes([buffer[1], buffer[2]]);
        entry.blob_signature.copy_from_slice(&buffer[3..(3 + ed25519_dalek::SIGNATURE_LENGTH)]);
        entry.path_name_length = u16::from_le_bytes([buffer[3 + ed25519_dalek::SIGNATURE_LENGTH], buffer[4 + ed25519_dalek::SIGNATURE_LENGTH]]);
        read_buffer.extend_from_slice(&buffer);

        let mut buffer = vec![0; entry.path_name_length as usize];
        reader.read_exact(&mut buffer)?;
        read_buffer.extend_from_slice(&buffer);
        entry.path = buffer;

        let mut buffer = [0; 12];
        reader.read_exact(&mut buffer)?;
        entry.compressed_size = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        entry.byte_offset = u64::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]]);
        read_buffer.extend_from_slice(&buffer);

        Ok(entry)
    }

    pub fn from_reader<R: Read>(reader: &mut BufReader<R>) -> anyhow::Result<RegistryEntry> {
        Self::_from_reader_append_read(reader, &mut Vec::new())
    }

    pub fn empty() -> RegistryEntry {
        RegistryEntry{
            flags: RegistryEntryFlags::EMPTY,
            content_version: 0,
            blob_signature: [0; ed25519_dalek::SIGNATURE_LENGTH],
            path_name_length: 0,
            path: vec![],
            compressed_size: 0,
            byte_offset: 0,
        }
    }

    pub fn bytes(&self) -> Vec<u8>{
        let mut buffer = Vec::with_capacity(Self::BASE_SIZE + self.path_name_length as usize);

        buffer.push(self.flags.bits());
        buffer.extend_from_slice(&self.content_version.to_le_bytes());
        buffer.extend_from_slice(&self.blob_signature);
        buffer.extend_from_slice(&self.path_name_length.to_le_bytes());
        buffer.extend_from_slice(&self.path);
        buffer.extend_from_slice(&self.compressed_size.to_le_bytes());
        buffer.extend_from_slice(&self.byte_offset.to_le_bytes());

        buffer
    }

    pub fn size(&self) -> usize {
        Self::BASE_SIZE + self.path.len()
    }

    pub fn path_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.path.clone())
    }
}

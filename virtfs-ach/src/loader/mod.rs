use crate::global::{
    header::{
        MAGIC_LENGTH,
        MAGIC,
        Header
    },
    registry::{
        Registry,
        RegistryEntryFlags
    },
};
use anyhow::bail;
use ed25519_dalek::{PublicKey, Verifier};
use signature::Signature;
use std::{
    fmt,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    str,
    sync::Arc,
};

const MINIMUM_VERSION: u16 = 0;

#[derive(Debug)]
pub struct Archive<R: Read + Seek> {
    pub(crate) header: Header,
    pub(crate) registry: Registry,
    reader: BufReader<R>,
}

// TODO: Verify signatures

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<R: Read + Seek> Archive<R> {
    /// attempt to read a archive from the current stream position
    pub fn from_reader(mut reader: BufReader<R>, public_key: &PublicKey) -> anyhow::Result<Archive<R>> {
        let header = Header::from_reader(&mut reader)?;
        
        if header.archive_version < MINIMUM_VERSION {
            return Result::Err(anyhow::Error::msg(format!(
                "Minimum Version requirement not met. Version found: {}, Minimum version: {}",
                header.archive_version, MINIMUM_VERSION
            )));
        };
        
        let registry = Registry::from_reader(&mut reader, &header)?;
        
        Ok(Archive {
            header,
            registry,
            reader,
        })
    }

    pub fn get_file_at_index(&mut self, index: usize, public_key: &PublicKey) -> anyhow::Result<Vec<u8>> {
        if self.registry.entries.len() - 1 < index {
            bail!("No file for index {}", index);
        }

        let entry = &self.registry.entries[index];
        let compressed = entry.flags.contains(RegistryEntryFlags::IS_COMPRESSED);
        self.reader.seek(SeekFrom::Start(entry.byte_offset));
        let mut buffer = vec![0; entry.compressed_size as usize];
        self.reader.read_exact(&mut buffer)?;

        buffer.extend(&entry.path);

        let expected_signature: ed25519_dalek::Signature = Signature::from_bytes(&entry.blob_signature)?;
        public_key.verify(&buffer, &expected_signature)?;

        // remove appended path
        buffer.truncate(entry.compressed_size as usize);

        if compressed {
            Ok(lz4_flex::decompress_size_prepended(&buffer)?)
        } else {
            Ok(buffer)
        }
    }
}
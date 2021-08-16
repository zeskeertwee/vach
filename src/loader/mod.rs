use crate::global::{
    header::{
        MAGIC_LENGTH,
        MAGIC,
        Header
    },
    registry::Registry,
};
use anyhow::bail;
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
    pub fn from_reader(mut reader: BufReader<R>) -> anyhow::Result<Archive<R>> {
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

    pub fn read_buffer(&mut self, index: usize) -> anyhow::Result<Vec<u8>> {
        let entry = &self.registry.entries[index];
        self.reader.seek(SeekFrom::Start(entry.byte_offset));
        let mut buffer = vec![0; entry.compressed_size as usize];
        self.reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn get_file_at_index(&mut self, index: usize) -> anyhow::Result<Vec<u8>> {
        if self.registry.entries.len() - 1 < index {
            bail!("No file for index {}", index);
        }

        let entry = &self.registry.entries[index];
        let compressed = entry.compressed_size != entry.uncompressed_size;
        self.reader.seek(SeekFrom::Start(entry.byte_offset));
        let mut buffer = vec![0; entry.compressed_size as usize];
        self.reader.read_exact(&mut buffer)?;

        if compressed {
            Ok(lz4_flex::decompress(&buffer, entry.uncompressed_size as usize)?)
        } else {
            Ok(buffer)
        }
    }
}
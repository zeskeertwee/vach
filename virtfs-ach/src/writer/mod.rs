#![allow(unused)]

use std::fmt;
use std::io::{Read, Seek, Write, Cursor};
use lz4_flex;
use ed25519_dalek::Signer;
use signature::Signature;
use log::info;
use crate::loader::Archive;
use crate::global::{
    registry::{
        Registry,
        RegistryEntry
    },
    header::{
        MAGIC,
        Header,
    }
};

const CURRENT_ARCHIVE_VERSION: u16 = 0;

pub struct ArchiveBuilder {
    leafs: Vec<ArchiveBuilderFile>,
}

struct ArchiveBuilderFile {
    data: Vec<u8>,
    path: String,
    content_version: u16,
    mime_type: u16,
    flags: u8,
}

impl ArchiveBuilder {
    pub fn new() -> Self {
        Self {
            leafs: Vec::new(),
        }
    }

    pub fn add_file<S: ToString>(
        &mut self,
        data: Vec<u8>,
        path: S,
        content_version: u16,
        mime_type: u16,
    ) {
        self.leafs.push(ArchiveBuilderFile {
            data,
            path: path.to_string(),
            content_version,
            mime_type,
            flags: 0,
        })
    }

    pub fn write_to<W: Write, S: Signer<ed25519_dalek::Signature>>(&self, writer: &mut W, signer: &S) -> anyhow::Result<()> {
        writer.write_all(&self.bytes(signer))?;
        
        Ok(())
    }

    pub fn bytes<S: Signer<ed25519_dalek::Signature>>(&self, signer: &S) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        buffer.extend_from_slice(MAGIC);
        buffer.extend_from_slice(&CURRENT_ARCHIVE_VERSION.to_le_bytes());
        buffer.extend_from_slice(&(self.leafs.len() as u16).to_le_bytes());

        let mut registry_buffer: Vec<u8> = Vec::new();
        let mut registry_entries = Vec::new();
        let mut offset: usize = Header::SIZE;
        let mut processed_data = Vec::new();

        for leaf in self.leafs.iter() {
            let mut registry_entry = leaf.to_registry_entry();
            
            let compressed_data = lz4_flex::compress(&leaf.data);
            let size_diff: f64 = compressed_data.len() as f64 / leaf.data.len() as f64;
            if compressed_data.len() >= leaf.data.len() {
                info!("Did not compress {} ({:.2}x original size)", registry_entry.path_string().unwrap(), size_diff);
                let signature = signer.sign(&leaf.data);
                registry_entry.blob_signature = signature.to_bytes();
                registry_entry.compressed_size = registry_entry.uncompressed_size;
                processed_data.push(leaf.data.clone());
            } else {
                info!("Compressed {} ({:.2}x original size)", registry_entry.path_string().unwrap(), size_diff);
                let signature = signer.sign(&compressed_data);
                registry_entry.blob_signature = signature.to_bytes();
                registry_entry.compressed_size = compressed_data.len() as u32;
                processed_data.push(compressed_data);
            }

            offset += registry_entry.size();
            registry_entries.push(registry_entry);
        }

        for (entry, data) in registry_entries.iter_mut().zip(&processed_data) {
            entry.byte_offset = offset as u64;
            offset += data.len();
            registry_buffer.extend_from_slice(&entry.bytes());
        }

        let signature = signer.sign(&registry_buffer);
        let signature_bytes = signature.as_bytes();
        buffer.extend_from_slice(signature_bytes);
        buffer.extend_from_slice(&registry_buffer);

        for data in processed_data {
            buffer.extend_from_slice(&data);
        }

        buffer
    }
}

impl ArchiveBuilderFile {
    fn to_registry_entry(&self) -> RegistryEntry {
        RegistryEntry {
            flags: self.flags,
            content_version: self.content_version,
            // TODO: signature
            blob_signature: [0; ed25519_dalek::SIGNATURE_LENGTH],
            path_name_length: self.path.len() as u16,
            path: self.path.as_bytes().to_owned(),
            // TODO: compression
            compressed_size: self.data.len() as u32,
            uncompressed_size: self.data.len() as u32,
            // TODO: offset
            byte_offset: 0,
        }
    }
}
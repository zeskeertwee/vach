mod config;
use super::leaf::{Leaf, LeafConfig};
use crate::global::{
    header::HeaderConfig,
    registry::RegistryEntry,
    types::{FlagType, RegisterType},
};
pub use config::BuilderConfig;

use ed25519_dalek::Signer;
use hashbrown::HashMap;
use lz4_flex as lz4;
use std::io::{self, BufWriter, Write, Read};

#[derive(Debug)]
pub struct Builder<T> {
    leafs: HashMap<String, Leaf<T>>,
}

impl<T: Read> Default for Builder<T> {
    fn default() -> Builder<T> {
        Builder {
            leafs: HashMap::new(),
        }
    }
}

impl<T: Read> Builder<T> {
    pub fn new() -> Builder<T> { Builder::default() }
    pub fn add(&mut self, data: T, id: &str) -> anyhow::Result<()> {
        let mut config = LeafConfig::default();
        config.id = id.to_string();
        let leaf = Leaf::from(data, config.clone())?;
        self.leafs.insert(config.id, leaf);
        Ok(())
    }
    pub fn add_with_config(&mut self, data: T, leaf_config: &LeafConfig) -> anyhow::Result<()> {
        let leaf = Leaf::from(data, leaf_config.clone())?;
        self.leafs.insert(leaf_config.id.clone(), leaf);
        Ok(())
    }
    pub fn add_leaf(&mut self, leaf: Leaf<T>) -> anyhow::Result<()> {
        self.leafs
            .insert(leaf.config.id.clone(), leaf)
            .ok_or(anyhow::anyhow!("Unable to add leaf"))?;
        Ok(())
    }

    pub fn write<W: Write>(&mut self, target: &mut W, config: &BuilderConfig) -> anyhow::Result<()> {
        // Write header in order defined in the spec document
        let mut buffer = BufWriter::new( target);
        buffer.write_all(&config.header_config.magic)?;

        // INSERT flags
        let mut temp = config.flags;
        if config.keypair.is_some() { temp.insert(FlagType::SIGNED) };
        buffer.write_all(&temp.bits().to_le_bytes())?;

        buffer.write_all(&config.header_config.minimum_version.to_le_bytes())?;
        buffer.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

        let mut leaf_data = Vec::new();
        
        // Calculate the size of the registry
        let mut reg_size = 0usize;
        for (id, _) in self.leafs.iter() {
            reg_size += id.len() + RegistryEntry::MIN_SIZE
        };

        // Start counting the offset of the leafs from the end of the registry
        let mut leaf_offset = reg_size + HeaderConfig::BASE_SIZE;

        // Populate the archive glob
        for (id, leaf) in self.leafs.iter_mut() {
            let mut entry = leaf.to_registry_entry();
            let mut glob = Vec::new();

            // Create and compare compressed leaf data
            if leaf.config.compress {
                let mut compressor = lz4::frame::FrameEncoder::new(Vec::new());
                let length = io::copy(&mut leaf.handle, &mut compressor)?;
                let compressed_data = compressor.finish()?;

                let ratio = compressed_data.len() as f32 / length as f32;
                if ratio < 1f32 {
                    println!("Compressed {} ({:2}x original size)", id, ratio);
                    glob = compressed_data;
                    entry.flags.insert(FlagType::COMPRESSED);
                } else {
                    drop(compressed_data);
                };
            } else {
                io::copy(&mut leaf.handle, &mut glob)?;
            };

            let glob_length = glob.len();

            // Buffer the contents of the leaf, to be written later
            leaf_data.extend(&glob);

            entry.location = leaf_offset as RegisterType;
            leaf_offset += glob_length;
            entry.offset = glob_length as RegisterType;

            if let Some(keypair) = &config.keypair {
                // The reason we include the path in the signature is to prevent mangling in the registry,
                // For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
                // The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
                glob.extend(id.as_bytes());
                entry.signature = keypair.sign(&glob);
            };

            {
                // Write to the registry
                let mut entry_b = entry.bytes(&(id.len() as u64), config.keypair.is_some());
                entry_b.extend(id.as_bytes());
                buffer.write_all(&entry_b)?;
            }
        }

        // Write the glob
        buffer.write_all(&leaf_data)?;
        drop(leaf_data);

        Ok(())
    }
}

mod config;
use super::leaf::{Leaf, LeafConfig};
use crate::global::{
    header::HeaderConfig,
    registry::RegistryEntry,
    types::{FlagType, RegisterType},
};
pub use config::BuilderConfig;

use ed25519_dalek::{self as esdalek, Signer};
use hashbrown::HashMap;
use lz4_flex as lz4;
use std::io::{BufWriter, Read, Write};

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

    pub fn write<W: Write>( &mut self, target: &mut W, config: &BuilderConfig ) -> anyhow::Result<()> {
        // Write header in order defined in the spec document
        let mut buffer = BufWriter::new( target);
        buffer.write_all(&config.header_config.magic)?;

        // Some interior mutability sorcery
        let mut flags_temp = config.flags;
        if config.keypair.is_some() { flags_temp.insert(FlagType::SIGNED) };
        buffer.write_all(&flags_temp.bits().to_le_bytes())?;

        buffer.write_all(&config.header_config.minimum_version.to_le_bytes())?;
        buffer.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

        // Write the registry
        let mut leaf_data = vec![];
        let mut registry_buffer = vec![];
        
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
            let mut glob = vec![];
            let compressed_data;

            leaf.handle.read_to_end(&mut glob)?;
            let length = glob.len() as u64;

            // Create and compare compressed leaf data
            if leaf.config.compress {
                compressed_data = lz4::compress_prepend_size(&glob);
                let ratio = compressed_data.len() as f32 / length as f32;
                if ratio < 1f32 {
                    println!("Compressed {} ({:2}x original size)", id, ratio);
                    glob = compressed_data;
                    entry.flags.insert(FlagType::COMPRESSED);
                } else {
                    drop(compressed_data);
                };
            };

            let glob_length = glob.len();
            leaf_data.extend(&glob);

            entry.location = leaf_offset as RegisterType;
            leaf_offset += glob_length;
            entry.length = glob_length as RegisterType;

            if let Some(keypair) = &config.keypair {
                entry.signature = keypair.sign(&glob);
                entry.flags.insert(FlagType::SIGNED);
            };

            // Drop stuff
            drop(glob);

            let mut entry_b = entry.bytes(&(id.len() as u64));
            entry_b.extend(id.as_bytes());
            registry_buffer.extend(entry_b);
        }

        {
            // Sign the registry and write out the signature
            match &config.keypair {
                Some(keypair) => {
                    let signature = keypair.sign(&registry_buffer);
                    dbg!(&reg_size, &registry_buffer.len());
                    let signature_bytes = signature.to_bytes();
                    buffer.write_all(&signature_bytes)?;
                },
                None => {
                    buffer.write_all(&[0x53; esdalek::SIGNATURE_LENGTH])?;
                }
            }
        }
        // Write out the registry
        buffer.write_all(&registry_buffer)?;
        drop(registry_buffer);

        // Write the glob
        buffer.write_all(&leaf_data)?;
        drop(leaf_data);

        Ok(())
    }
}

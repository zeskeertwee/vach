mod config;
pub use config::BuilderConfig;
use super::leaf::{Leaf, LeafConfig};
use crate::global::{header::HeaderConfig, registry::RegistryEntry, types::RegisterType};

use std::{collections::HashMap, io::{Read, Write}};
use ed25519_dalek::Signer;
use lz4_flex as lz4;

pub struct Builder {
    leafs: HashMap<String, Leaf>,
}

impl Builder {
    pub fn empty() -> Self {
        Self {
            leafs: HashMap::new(),
        }
    }

    pub fn add<S: ToString, T: Read>(
        &mut self,
        mut data: T,
        config: &LeafConfig,
    ) -> anyhow::Result<()> {
        let leaf = Leaf::from(&mut data, config)?;
        self.leafs.insert(config.path.clone(), leaf);
        Ok(())
    }

    pub fn write<W: Write>(&self, target: &mut W, config: &BuilderConfig) -> anyhow::Result<()> {
        // Write header in order defined in the spec document
        target.write_all(&config.header.magic)?;
        target.write_all(&config.flags.to_le_bytes())?;
        target.write_all(&config.header.minimum_version.to_le_bytes())?;
        target.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

        // Write the registry
        let mut leaf_data = vec![];
        {
            let mut registry_buffer = vec![];
            let mut leaf_offset = HeaderConfig::BASE_SIZE;
            //   let mut data:Vec<(String, RegistryEntry, Vec<u8>)> = vec![];

            // Calculate the size of the registry
            let mut reg_size = 0usize;
            for (path, _) in self.leafs.iter() {
                reg_size += (path.len() + RegistryEntry::MIN_SIZE)
            }

            // Start counting the offset of the leafs from the end of the registry
            leaf_offset += reg_size;

            // Populate the archive glob
            for (path, leaf) in self.leafs.iter() {
                let mut entry = leaf.to_registry_entry();
                let mut glob;

                // Create and compare compressed leaf data
                let compressed_data = lz4::compress_prepend_size(&leaf.data);
                let ratio: f64 = compressed_data.len() as f64 / leaf.data.len() as f64;

                if compressed_data.len() >= leaf.data.len() {
                    println!("Did not compress {} ({:.2}x original size)", path, ratio);
                    entry.signature = Some(config.keypair.sign(&leaf.data));
                    glob = leaf.data.clone()
                } else {
                    println!("Compressed {} ({:.2}x original size)", path, ratio);
                    entry.signature = Some(config.keypair.sign(&compressed_data));
                    glob = compressed_data
                };

                let glob_length = glob.len();
                leaf_data.extend(glob);

                leaf_offset += glob_length;
                entry.length = glob_length as RegisterType;
                entry.location = leaf_offset as RegisterType;

                let mut entry_b = entry.bytes(&(path.len() as u64));
                entry_b.extend(path.as_bytes());
                registry_buffer.extend(entry_b);
            }

            // Assert that the reg_size did indeed match the size of the registry buffer
            assert_eq!(reg_size, registry_buffer.len());

            {
                // As we are still writing the Header to the target, write_all the signature bytes
                // In it's own scope so that the below values are dropped prematurely, so we release some memory
                let signature = config.keypair.sign(&registry_buffer);
                let signature_bytes = signature.to_bytes();
                target.write_all(&signature_bytes)?;
            };

            // Write the registry out
            target.write_all(&registry_buffer)?;
        };

        // Write the glob
        target.write_all(&leaf_data)?;

        Ok(())
    }
}

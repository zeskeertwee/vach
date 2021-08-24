mod config;
pub use config::LeafConfig;

use crate::{
	global::{
		registry::RegistryEntry,
		types::FlagType
	}
};
use std::{io::Read, fs::File};

pub struct Leaf {
    pub data: Vec<u8>,
    content_version: u8,
    flags: FlagType,
}

impl Leaf {
    pub fn empty() -> Leaf {
        Leaf {
            data: vec![],
            content_version: 0,
            flags: 0,
        }
    }
    pub fn from<T: Read>(data: &mut T, config: &LeafConfig) -> anyhow::Result<Leaf> {
        let mut buffer = vec![];
        data.read_to_end(&mut buffer)?;
        Ok(Leaf {
            data: buffer,
            content_version: config.version,
            flags: config.flags,
        })
    }
    pub fn from_file(path: &str, config: &LeafConfig) -> anyhow::Result<Leaf> {
        let mut file = File::open(path)?;
        let mut vector = vec![];
        file.read_to_end(&mut vector);
        Ok(Leaf {
            data: vector,
            content_version: config.version,
            flags: config.flags,
        })
    }
    pub fn to_registry_entry(&self) -> RegistryEntry {
        RegistryEntry {
            flags: self.flags,
            content_version: self.content_version,
            signature: None,

            length: 0,
            location: 0,
        }
    }
}

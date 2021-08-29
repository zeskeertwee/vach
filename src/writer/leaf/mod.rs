mod config;
pub use config::LeafConfig;

use crate::{
	global::{
		registry::RegistryEntry
	}
};
use std::{io::{Cursor, Read}};

#[derive(Debug)]
pub struct Leaf<T> {
    pub handle: T,
    pub config: LeafConfig
}

impl Leaf<Cursor<Vec<u8>>> {
    pub fn empty() -> Leaf<Cursor<Vec<u8>>> {
        Leaf {
            handle: Cursor::new(vec![]),
            config: LeafConfig::default()
        }
    }
}

impl<T: Read> Leaf<T> {
    pub fn from(handle: T, config: LeafConfig) -> anyhow::Result<Leaf<T>> {
        Ok(Leaf { handle, config })
    }
    pub(crate) fn to_registry_entry(&self) -> RegistryEntry {
        let mut entry = RegistryEntry::empty();
        entry.content_version = self.config.content_version;
        entry
    }
}

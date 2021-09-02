use crate::{
	global::{
		registry::RegistryEntry
	}
};
use std::{io::{Cursor, Read}};

#[derive(Debug)]
pub struct Leaf<T> {
    // NOTE: Replace T with Box<dyn T>, so that multiple types can be used
    pub handle: T,
    pub id: String,
	pub content_version: u8,
	pub compress: bool,
}

impl Default for Leaf<Cursor<Vec<u8>>> {
    fn default() -> Leaf<Cursor<Vec<u8>>> {
        Leaf {
            handle: Cursor::new(Vec::new()),
            id: String::new(),
            content_version: 0,
            compress: true
        }
    }
}

impl<T: Read> Leaf<T> {
    pub fn from(handle: T) -> anyhow::Result<Leaf<T>> {
        Ok(Leaf {
            handle,
            id: String::new(),
            content_version: 0,
            compress: true
        })
    }
    pub(crate) fn to_registry_entry(&self) -> RegistryEntry {
        let mut entry = RegistryEntry::empty();
        entry.content_version = self.content_version;
        entry
    }
    pub fn compress(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }
   pub fn version(mut self, version: u8) -> Self {
       self.content_version = version;
       self
   }
   pub fn id(mut self, id: &str) -> Self {
       self.id = id.to_string();
       self
   }
}

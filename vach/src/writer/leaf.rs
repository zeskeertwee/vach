use crate::{
	global::{
		registry::RegistryEntry
	}
};
use std::{io::{Cursor, Read}};

pub struct Leaf<'a> {
    // This lifetime simply reflects to the `Builder`'s lifetime, meaning the handle must live longer than or the same as the Builder
    pub handle: Box<dyn Read + 'a>,
    pub id: String,
    pub content_version: u8,
    pub compress: bool,
}

impl<'a> Default for Leaf<'a> {
    fn default() -> Leaf<'a> {
        Leaf {
            handle: Box::new(Cursor::new(Vec::new())),
            id: String::new(),
            content_version: 0,
            compress: true
        }
    }
}

impl<'a> Leaf<'a> {
    pub fn from(handle: impl Read + 'a) -> anyhow::Result<Leaf<'a>> {
        Ok(Leaf {
            handle: Box::new(handle),
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

use std::fmt;
use crate::{global::{registry::RegistryEntry, types::FlagType}};

// Basically data obtained from an archive
#[derive(Debug)]
pub struct Resource {
    pub data: Vec<u8>,
    pub flags: FlagType,
    pub content_version: u8,
}

impl Resource {
    pub fn new(data: &[u8], entry: &RegistryEntry) -> Resource {
        Resource{
            data: Vec::from(data),
            flags: entry.flags,
            content_version: entry.content_version
        }
    }
    pub fn empty() -> Resource {
        Resource{ data: vec![], flags: 0, content_version: 0 }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Resource] size: {length} bytes, version: {version}, flags: {flags}",
            length = self.data.len(),
            flags = &self.flags,
            version = &self.content_version
        )
    }
}

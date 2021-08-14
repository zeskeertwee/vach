use std::fmt;
use crate::global::registry::RegistryEntry;

// Basically data obtained from an archive
#[derive(Debug)]
pub struct Resource {
    pub mime_type: u16,
    pub data: Vec<u8>,
    pub flags: u16,
    pub content_version: u8,
}

impl Resource {
    pub fn new(data: &[u8], entry: &RegistryEntry) -> Resource {
        Resource{
            mime_type: entry.mime_type.clone(),
            data: Vec::from(data),
            flags: entry.flags.clone(),
            content_version: entry.content_version.clone()
        }
    }
    pub fn empty() -> Resource {
        Resource {
            mime_type: 0,
            data: vec![],
            flags: 0,
            content_version: 0
        }
    }

    pub fn set_flags(mut self, flags: u16) -> Self { self.flags = flags; self }
    pub fn set_version(mut self, version: u8) -> Self { self.content_version = version; self }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Resource] mime_type: {m_type}, size: {length}",
            m_type = self.mime_type,
            length = self.data.len()
        )
    }
}

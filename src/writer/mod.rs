#![allow(unused)]

use std::fmt;
use crate::loader::Archive;

// Basically data obtained from the archive
#[derive(Debug)]
struct ArchiveData {
    // INFO: Supports 65535 mime types which is more than enough
    mime_type: u16,
    data: Vec<u8>,
}

impl ArchiveData {
    fn append(&self, archive: &Archive, name: &str) -> Result<(), String>{
        unimplemented!()
    }
}

impl fmt::Display for ArchiveData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveEntry] mime_type: {m_type}, size: {length}",
            m_type = self.mime_type,
            length = self.data.len()
        )
    }
}
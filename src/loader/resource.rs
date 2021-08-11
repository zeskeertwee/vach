use std::fmt;

// Basically data obtained from the archive
#[derive(Debug)]
pub struct Resource {
    // INFO: Supports 65535 mime types which is more than enough
    pub mime_type: u16,
    pub data: Vec<u8>,
    pub flags: u16,
    pub content_version: u8,
}

impl Resource {
    pub fn new(data: &[u8], mime_type: u16) -> Resource {
        unimplemented!()
    }
    pub fn empty() -> Resource {
        Resource {
            mime_type: 0,
            data: vec![],
            flags: 0,
            content_version: 0
        }
    }

    pub fn set_flags(&mut self, ) {}
    pub fn toggle_flag(&mut self, flag: u16, toggle: bool) {}
    pub fn set_version(&mut self, ) {}
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveEntry] mime_type: {m_type}, size: {length}",
            m_type = self.mime_type,
            length = self.data.len()
        )
    }
}

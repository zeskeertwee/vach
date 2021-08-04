#![allow(dead_code)]

// Below constants are subject to change
const MAGIC_LENGTH: usize = 5;
const SIGNATURE_LENGTH: usize = 16;

// INFO: Any struct that implements ConstantSize always has a fixed size within the file
pub trait ConstantSize {
    fn size() -> usize;
}

// INFO: This struct mirrors the general structure of a .vach file
struct Archive {
    header: Header,
    registry: Box<Registry>,
    data: Box<u8>,
}

pub struct Header {
    magic: [u8; MAGIC_LENGTH], // VfACH

    flags: u16,
    content_version: u16,

    uses_compressed: bool,
}

impl ConstantSize for Header {
    fn size() -> usize {
        37 + (8 * MAGIC_LENGTH as usize)
    }
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
pub struct Registry {
    entries_count: usize,
    entries: [RegistryEntry],
}

impl Registry {
    fn size(&self) -> usize {
		 // NOTE: This is a method and note a static|associated function
        self.entries_count * RegistryEntry::size()
    }
}

pub struct RegistryEntry {
    path_name_start: u64,
    path_name_end: u64,

    is_compressed: bool,

    is_signed: bool,
    signature: [u8; SIGNATURE_LENGTH],

    index: u64,
    byte_offset: u64,

    mime_type: usize,
}

impl ConstantSize for RegistryEntry {
    fn size() -> usize {
        290 + (8 * SIGNATURE_LENGTH as usize)
    }
}

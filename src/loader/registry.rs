use std::fs::File;

#[derive(Debug)]
pub struct Registry {
    entries_count: usize,
    entries: Vec<RegistryEntry>,
}

impl Registry{
	pub fn empty() -> Registry { Registry{ entries_count: 0, entries: vec![] } }
	pub fn from_file(file: &File, big_endian: &bool) -> Result<Registry, String>{
		unimplemented!()
	}
}

#[derive(Debug)]
pub struct RegistryEntry {
    content_version: u32,
    path_name_start: u64,
    path_name_end: u64,

    is_compressed: bool,

    is_signed: bool,
    signature: u32,

    index: u64,
    byte_offset: u64,

    mime_type: u16,
}

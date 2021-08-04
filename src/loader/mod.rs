#![allow(dead_code)]
#![allow(unused_variables)]

use std::{fmt::{self}, fs::File};

const MAGIC_LENGTH: usize = 5;
const MAGIC: &[u8; 5] = b"VfACH";

#[derive(Debug)]
pub struct Header {
	magic: [u8; MAGIC_LENGTH], // VfACH

	flags: u16,
	content_version: u16,

	uses_compressed: bool,
}

impl fmt::Display for Header {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// write!(f, "{}", 5u32);
		unimplemented!();
	}
}

#[derive(Debug)]
pub struct Archive {
	header: Header,
	config: ArchiveConfig
}

impl Archive {
	pub fn new(file: File) -> Self {
		Archive::with_options(file, ArchiveConfig::default())
	}
	pub fn with_options(file: File, options: ArchiveConfig) -> Self { unimplemented!() }
	
	pub fn validate(file: File, options: ArchiveConfig) -> Result<bool, String> { unimplemented!() }
}

impl fmt::Display for Archive {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		unimplemented!();
	}
}

#[derive(Debug)]
pub struct ArchiveConfig {}

impl ArchiveConfig {
	fn default() -> Self {
		unimplemented!()
	}
}

impl fmt::Display for ArchiveConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		unimplemented!();
	}
}

// Basically data obtained from the archive
#[derive(Debug)]
struct ArchiveEntry{
	// Supports 65535 mime types which is more than enough
	mime_type: u16,
	data: Box<[u8]>
}

impl fmt::Display for ArchiveEntry {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "[ArchiveEntry] mime_type: {m_type}, size: {length}", m_type=self.mime_type, length=self.data.len())
	}
}
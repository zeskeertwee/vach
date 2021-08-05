#![allow(dead_code)]
#![allow(unused_variables)]

use std::{fmt::{self}, fs::File, str};

const MAGIC_LENGTH: usize = 5;
const DEFAULT_MAGIC: &[u8; 5] = b"VfACH";

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
pub struct ArchiveConfig {
	pub magic: [u8;5],
	pub flags: u16,
	pub minimum_version: u16
}

impl ArchiveConfig {
	pub fn new(magic: [u8;5], flags: u16, minimum_version: u16) -> Self {
		ArchiveConfig{ magic, flags, minimum_version }
	}
	pub fn default() -> Self {
		ArchiveConfig::new((*DEFAULT_MAGIC).clone(), 0, 0)
	}

	pub fn set_flags(&mut self, flag: u16) { self.flags = flag; }

	pub fn toggle_flag(&mut self, input: u16, mode: bool) {
		match mode {
			true => self.flags = self.flags | input,
			false => self.flags = !self.flags & input,
		};
	}
}

impl fmt::Display for ArchiveConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "[ArchiveConfig] flags: {:#016b}, magic: {}, minimum_version: {}", self.flags, str::from_utf8(&self.magic).unwrap(), self.minimum_version)
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

trait Generate {
	 fn generate(){}
}

impl ArchiveEntry {
	fn generate(){
		unimplemented!()
	}
}
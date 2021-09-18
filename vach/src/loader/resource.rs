use std::fmt;
use crate::{
	global::{reg_entry::RegistryEntry, types::Flags},
};

// Basically data obtained from an archive
#[derive(Debug)]
pub struct Resource {
	pub data: Vec<u8>,
	pub flags: Flags,
	pub content_version: u8,
}

impl Resource {
	pub fn new(data: &[u8], entry: &RegistryEntry) -> Resource {
		Resource {
			data: Vec::from(data),
			flags: entry.flags,
			content_version: entry.content_version,
		}
	}
}

impl fmt::Display for Resource {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[Resource] size: {length} bytes, content version: {version}, flags: {flags:b}",
			length = self.data.len(),
			flags = &self.flags.bits(),
			version = &self.content_version
		)
	}
}

impl Default for Resource {
	#[inline(always)]
	fn default() -> Resource {
		Resource {
			data: Vec::new(),
			flags: Flags::default(),
			content_version: 0,
		}
	}
}

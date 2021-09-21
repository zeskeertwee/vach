use std::fmt;
use crate::{
	global::{types::Flags},
};

/// Basically decompressed data obtained from an archive.
/// Contains `data`, `flags` and `content_version` fields.
/// Is returned by `archive.fetch()`
#[derive(Debug)]
pub struct Resource {
	/// The decompressed data, stored in a vector of bytes.
	pub data: Vec<u8>,
	/// The flags extracted from the archive source and parsed into a struct
	pub flags: Flags,
	/// The content version extracted from the archive source
	pub content_version: u8,
}

impl fmt::Display for Resource {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[Resource] size: {size} bytes, content version: {version}, flags: {flags:#016b}",
			size = self.data.len(),
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

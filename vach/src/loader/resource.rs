use std::fmt;
use crate::{
	global::{flags::Flags},
};

/// Basically decompressed data obtained from an archive.
/// Contains `data`, `flags` and `content_version` fields.
/// Is returned by `archive.fetch(...)`
#[derive(Debug, Default)]
pub struct Resource {
	/// The decompressed data, stored in a vector of bytes.
	pub data: Vec<u8>,
	/// The flags extracted from the archive entry and parsed into a struct
	pub flags: Flags,
	/// The content version of the extracted archive entry
	pub content_version: u8,
	/// If a [`Resource`] has been validated against tampering, corruption or obsolescence, then this value becomes false.
	/// By default a [`Resource`] is invalid
	pub secured: bool,
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

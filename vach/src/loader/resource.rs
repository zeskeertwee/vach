use std::fmt;
use crate::{
	global::{flags::Flags},
};

/// Basically processed data obtained from an archive.
/// Contains `data`, `flags` and `content_version` fields.
/// Is returned by [`archive.fetch(...)`](crate::archive::Archive)
#[non_exhaustive]
pub struct Resource {
	/// The processed data, stored as a vector of bytes `Vec<u8>`.
	pub data: Vec<u8>,
	/// The flags extracted from the archive's registry entry
	pub flags: Flags,
	/// The content version of the extracted archive entry
	pub content_version: u8,
	/// If a [`Resource`] signature has checked for authenticity, corruption or obsolescence, then this value becomes false.
	/// By default a [`Resource`] is insecure
	pub secured: bool,
}

impl fmt::Debug for Resource {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Resource")
			.field("data", &self.data)
			.field("flags", &self.flags)
			.field("content_version", &self.content_version)
			.field("secured", &self.secured)
			.finish()
	}
}

impl fmt::Display for Resource {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[Resource] size: {size} bytes, content version: {version}, flags: {flags}",
			size = self.data.len(),
			flags = &self.flags,
			version = &self.content_version
		)
	}
}

use std::fmt;
use crate::global::flags::Flags;

/// Basically processed data obtained from an archive.
/// Contains `data`, `flags` and `content_version` fields.
/// Is returned by [`archive.fetch(...)`](crate::archive::Archive)
#[non_exhaustive]
#[derive(Debug)]
pub struct Resource {
	/// The processed data, stored as a vector of bytes `Vec<u8>`.
	pub data: Vec<u8>,
	/// The flags extracted from the archive's registry entry
	pub flags: Flags,
	/// The content version of the extracted archive entry
	pub content_version: u8,
	/// A [`Resource`] is checked for authenticity, corruption or obsolescence against it's signature.
	/// If the checks pass, then this becomes true, this is always false if the `crypto` feature is off or if the data had no signature
	pub authenticated: bool,
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

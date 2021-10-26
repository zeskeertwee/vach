use crate::{
	global::{reg_entry::RegistryEntry, types::Flags},
};
use std::{io::Read};

/// Configures how `Leaf`s should be compressed.
/// Default is `CompressMode::Never`.
#[derive(Clone, Copy)]
pub enum CompressMode {
	/// The data will always be compressed
	Always,
	/// The compressed data is used, only if it is smaller than the original data.
	Detect,
	/// The data is never compressed and is embedded as is.
	Never,
}

/// A wrapper around an `io::Read` handle.
/// Allows for multiple types of data implementing `io::Read` to be used under one structure.
/// Also used to configure how data will be processed and embedded into an write target.
pub struct Leaf<'a> {
	pub(crate) handle: Box<dyn Read + 'a>, // This lifetime simply reflects to the `Builder`'s lifetime, meaning the handle must live longer than or the same as the Builder
	/// The `ID` under which the embedded data will be referenced
	pub id: String,
	/// The version of the content, allowing you to track obsolete data.
	pub content_version: u8,
	/// How a `Leaf` should be compressed
	pub compress: CompressMode,
	/// The flags that will go into the archive write target.
	pub flags: Flags,
	/// Use encryption when writing into the target.
	pub encrypt: bool,
}

impl<'a> Default for Leaf<'a> {
	/// The default leaf holds no bytes at all, this is expected to be used as a stencil|template.
	#[inline(always)]
	fn default() -> Leaf<'a> {
		Leaf {
			handle: Box::<&[u8]>::new(&[]),
			id: String::new(),
			content_version: 0,
			compress: CompressMode::Never,
			flags: Flags::default(),
			encrypt: false,
		}
	}
}

impl<'a> Leaf<'a> {
	#[inline(always)]
	/// Wrap a `Leaf` around the given handle.
	/// Using the `Default` configuration.
	///```
	/// use vach::prelude::Leaf;
	/// use std::io::Cursor;
	///
	/// let leaf = Leaf::from_handle(Cursor::new(vec![]));
	///```
	pub fn from_handle<H: Read + 'a>(handle: H) -> Leaf<'a> {
		Leaf {
			handle: Box::new(handle),
			..Default::default()
		}
	}
	pub(crate) fn to_registry_entry(&self) -> RegistryEntry {
		let mut entry = RegistryEntry::empty();
		entry.content_version = self.content_version;
		entry.flags = self.flags;
		entry
	}

	/// Copy the `compress`, `content_version` and `flags` fields from another `Leaf`.
	/// Meant to be used like a setter:
	/// ```rust
	/// use std::io::Cursor;
	/// use vach::prelude::{Leaf, CompressMode};
	/// let template = Leaf::default()
	///    .version(12)
	///    .compress(CompressMode::Always);
	///
	/// let leaf = Leaf::from_handle(Cursor::new(vec![])).template(&template);
	/// ```
	pub fn template(mut self, other: &Leaf) -> Self {
		self.compress = other.compress;
		self.content_version = other.content_version;
		self.flags = other.flags;
		self.encrypt = other.encrypt;
		self
	}

	// Setters
	/// Setter used to set the `CompressMode` of a `Leaf`
	/// ```rust
	/// use vach::prelude::{Leaf, CompressMode};
	///
	/// let leaf = Leaf::default().compress(CompressMode::Always);
	/// ```
	pub fn compress(mut self, compress: CompressMode) -> Self {
		self.compress = compress;
		self
	}
	/// Setter used to set the `content_version` of a `Leaf`
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().version(2);
	/// ```
	pub fn version(mut self, content_version: u8) -> Self {
		self.content_version = content_version;
		self
	}
	/// Setter used to set the `id` field of a `Leaf`
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().id("whatzitouya");
	/// ```
	pub fn id(mut self, id: &str) -> Self {
		self.id = id.to_string();
		self
	}
	/// Setter used to set the `Flags` field of a `Leaf`
	/// ```rust
	/// use vach::prelude::{Leaf, Flags};
	///
	/// let leaf = Leaf::default().flags(Flags::default());
	/// ```
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}
	/// Setter for the `encrypt` field
	///```
	///use vach::prelude::Leaf;
	/// let config = Leaf::default().encrypt(true);
	///```
	pub fn encrypt(mut self, encrypt: bool) -> Self {
		self.encrypt = encrypt;
		self
	}
}

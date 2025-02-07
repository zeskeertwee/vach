#[cfg(feature = "compression")]
use crate::global::compressor::CompressionAlgorithm;
use crate::global::{reg_entry::RegistryEntry, flags::Flags};

use std::{fmt, io::Read, sync::Arc};

/// Configures how `Leaf`s should be compressed.
/// Default is `CompressMode::Never`.
#[derive(Debug, Clone, Copy, Default)]
#[cfg(feature = "compression")]
#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
pub enum CompressMode {
	/// The data is never compressed and is embedded as is.
	#[default]
	Never,
	/// The data will always be compressed
	Always,
	/// The compressed data is used, only if it is smaller than the original data.
	Detect,
}

/// A wrapper around an [`io::Read`](std::io::Read) handle.
/// Allows for multiple types of data implementing [`io::Read`](std::io::Read) to be used under one struct.
/// Also used to configure how data will be processed and embedded into an write target.
pub struct Leaf<'a> {
	/// Boxed read handle
	pub handle: Box<dyn Read + Send + Sync + 'a>,

	/// The `ID` under which the embedded data will be referenced
	pub id: Arc<str>,
	/// The version of the content, allowing you to track obsolete data.
	pub content_version: u8,
	/// The flags that will go into the archive write target.
	pub flags: Flags,

	/// How a [`Leaf`] should be compressed
	#[cfg(feature = "compression")]
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	pub compress: CompressMode,
	/// The specific compression algorithm to use
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	#[cfg(feature = "compression")]
	pub compression_algo: CompressionAlgorithm,

	/// Use encryption when writing into the target.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub encrypt: bool,
	/// Whether to include a signature with this [`Leaf`], defaults to false.
	/// If set to true then a hash generated and validated when loaded.
	/// > *NOTE:* **Turning `sign` on severely hurts the performance of `Archive::fetch(---)`**. This is because signature authentication is an intentionally taxing process, which prevents brute-forcing.
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub sign: bool,
}

impl<'a> Leaf<'a> {
	#[inline(always)]
	/// Wrap a [`Leaf`] around the given handle.
	/// Using the `Default` configuration.
	///```
	/// use vach::prelude::Leaf;
	///
	/// let leaf = Leaf::new([].as_slice(), "example#1");
	///```
	pub fn new<R: Read + Send + Sync + 'a, S: AsRef<str>>(handle: R, id: S) -> Leaf<'a> {
		Leaf {
			handle: Box::new(handle),
			id: Arc::from(id.as_ref()),
			..Default::default()
		}
	}

	/// Consume the [Leaf] and return the underlying Boxed handle
	pub fn into_inner(self) -> Box<dyn Read + Send + 'a> {
		self.handle
	}

	/// Copy all fields from another [`Leaf`], except for `handle` and `id`
	/// Meant to be used like a setter:
	/// ```rust
	/// use std::io::Cursor;
	/// use vach::prelude::Leaf;
	/// let template = Leaf::default().version(12);
	///
	/// let leaf = Leaf::new([].as_slice(), "example#1").template(&template);
	/// assert_eq!(&leaf.content_version, &template.content_version);
	/// ```
	pub fn template(self, other: &Leaf<'a>) -> Self {
		Leaf {
			handle: self.handle,
			id: self.id,
			..*other
		}
	}

	// Setters
	/// Setter used to set the [`CompressMode`] of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf, CompressMode};
	///
	/// let leaf = Leaf::default().compress(CompressMode::Always);
	/// ```
	#[cfg(feature = "compression")]
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	pub fn compress(mut self, compress: CompressMode) -> Self {
		self.compress = compress;
		self
	}

	/// Setter used to set the `content_version` of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().version(2);
	/// ```
	pub fn version(mut self, content_version: u8) -> Self {
		self.content_version = content_version;
		self
	}

	/// Setter used to set the `id` field of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().id("whatzitouya");
	/// ```
	pub fn id<S: AsRef<str>>(mut self, id: S) -> Self {
		self.id = Arc::from(id.as_ref());
		self
	}

	/// Setter used to set the [`flags`](crate::builder::Flags) field of a [`Leaf`]
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
	/// use vach::prelude::Leaf;
	/// let config = Leaf::default().encrypt(true);
	///```
	#[cfg(feature = "crypto")]
	pub fn encrypt(mut self, encrypt: bool) -> Self {
		self.encrypt = encrypt;
		self
	}

	/// Setter for the `sign` field
	///```
	/// use vach::prelude::Leaf;
	/// let config = Leaf::default().sign(true);
	///```
	#[cfg(feature = "crypto")]
	pub fn sign(mut self, sign: bool) -> Self {
		self.sign = sign;
		self
	}

	/// Setter for the `compression_algo` field
	#[cfg(feature = "compression")]
	pub fn compression_algo(mut self, compression_algo: CompressionAlgorithm) -> Self {
		self.compression_algo = compression_algo;
		self
	}
}

impl<'a> Default for Leaf<'a> {
	/// The default leaf holds no bytes at all, this is expected to be used as a stencil|template.
	#[inline(always)]
	fn default() -> Leaf<'a> {
		Leaf {
			handle: Box::<&[u8]>::new(&[]),

			id: Arc::from(""),
			flags: Default::default(),
			content_version: Default::default(),

			#[cfg(feature = "crypto")]
			encrypt: Default::default(),
			#[cfg(feature = "crypto")]
			sign: Default::default(),

			#[cfg(feature = "compression")]
			compress: Default::default(),
			#[cfg(feature = "compression")]
			compression_algo: Default::default(),
		}
	}
}

impl fmt::Debug for Leaf<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut d = f.debug_struct("Leaf");
		d.field("id", &self.id)
			.field("content_version", &self.content_version)
			.field("flags", &self.flags);

		#[cfg(feature = "crypto")]
		{
			d.field("encrypt", &self.encrypt);
			d.field("sign", &self.sign);
		}

		#[cfg(feature = "compression")]
		{
			d.field("compress", &self.compress);
			d.field("compression_algo", &self.compression_algo);
		}

		d.finish()
	}
}

impl From<&mut Leaf<'_>> for RegistryEntry {
	fn from(leaf: &mut Leaf<'_>) -> Self {
		RegistryEntry {
			id: leaf.id.clone(),
			flags: leaf.flags,
			content_version: leaf.content_version,
			..RegistryEntry::empty()
		}
	}
}

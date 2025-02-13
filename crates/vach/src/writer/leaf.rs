use crate::global::{reg_entry::RegistryEntry, flags::Flags};
use crate::global::error::InternalResult;

#[cfg(feature = "compression")]
use crate::global::compressor::{CompressionAlgorithm, Compressor};

#[cfg(feature = "crypto")]
use crate::crypto::Encryptor;

#[cfg(not(feature = "crypto"))]
type Encryptor = ();

use std::{io::Read, sync::Arc};

/// Configures how a [`Leaf`] should be compressed.
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

/// A named ([`ID`](Leaf::id)) wrapper around an [`io::Read`](Read) handle, tagged with extra metadata.
#[derive(Debug, Default, Clone)]
pub struct Leaf<R = &'static [u8]> {
	/// source data
	pub handle: R,

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
	/// Whether to include a signature with this [`Leaf`]
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub sign: bool,
}

impl<R: Read + Send + Sync> Leaf<R> {
	/// Creates a new [`Leaf`] wrapping around the given [`Read`] handle, with an ID
	pub fn new<S: AsRef<str>>(handle: R, id: S) -> Leaf<R> {
		let default = Leaf::<&'static [u8]>::default();

		Leaf {
			handle,
			id: Arc::from(id.as_ref()),

			// copy from default implementation
			content_version: default.content_version,
			flags: default.flags,

			#[cfg(feature = "compression")]
			compress: default.compress,
			#[cfg(feature = "compression")]
			compression_algo: default.compression_algo,
			#[cfg(feature = "crypto")]
			encrypt: default.encrypt,
			#[cfg(feature = "crypto")]
			sign: default.sign,
		}
	}

	/// Copy all fields from another [`Leaf`], except for `handle` and `id`.
	pub fn template<R2>(self, other: &Leaf<R2>) -> Self {
		Leaf {
			handle: self.handle,
			id: self.id,

			content_version: other.content_version,
			flags: other.flags,

			#[cfg(feature = "compression")]
			compress: other.compress,
			#[cfg(feature = "compression")]
			compression_algo: other.compression_algo,
			#[cfg(feature = "crypto")]
			encrypt: other.encrypt,
			#[cfg(feature = "crypto")]
			sign: other.sign,
		}
	}

	/// Setter for the [`compress`](Leaf::compress) field
	#[cfg(feature = "compression")]
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	pub fn compress(mut self, compress: CompressMode) -> Self {
		self.compress = compress;
		self
	}

	/// Setter for the [`content_version`](Leaf::content_version) field
	pub fn version(mut self, content_version: u8) -> Self {
		self.content_version = content_version;
		self
	}

	/// Setter for the [`flags`](crate::builder::Flags) field
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}

	/// Setter for the [`encrypt`](Leaf::encrypt) field
	#[cfg(feature = "crypto")]
	pub fn encrypt(mut self, encrypt: bool) -> Self {
		self.encrypt = encrypt;
		self
	}

	/// Setter for the [`sign`](Leaf::sign) field
	#[cfg(feature = "crypto")]
	pub fn sign(mut self, sign: bool) -> Self {
		self.sign = sign;
		self
	}

	/// Setter for the [`compression_algo`](Leaf::compression_algo) field
	#[cfg(feature = "compression")]
	pub fn compression_algo(mut self, compression_algo: CompressionAlgorithm) -> Self {
		self.compression_algo = compression_algo;
		self
	}
}

impl<R> From<&mut Leaf<R>> for RegistryEntry {
	fn from(leaf: &mut Leaf<R>) -> Self {
		RegistryEntry {
			id: leaf.id.clone(),
			flags: leaf.flags,
			content_version: leaf.content_version,
			..RegistryEntry::empty()
		}
	}
}

// Processed data ready to be inserted into a `Write + Clone` target during Building
pub(crate) struct ProcessedLeaf {
	pub(crate) data: Vec<u8>,
	pub(crate) entry: RegistryEntry,
	#[cfg(feature = "crypto")]
	pub(crate) sign: bool,
}

// Process Leaf into Prepared Data, externalised for multithreading purposes
#[inline(never)]
pub(crate) fn process_leaf<R: Read + Send + Sync>(
	leaf: &mut Leaf<R>, _encryptor: Option<&Encryptor>,
) -> InternalResult<ProcessedLeaf> {
	let mut entry: RegistryEntry = leaf.into();
	let mut raw = Vec::new();

	// Compression comes first
	#[cfg(feature = "compression")]
	match leaf.compress {
		CompressMode::Never => {
			leaf.handle.read_to_end(&mut raw)?;
		},
		CompressMode::Always => {
			Compressor::new(&mut leaf.handle).compress(leaf.compression_algo, &mut raw)?;

			entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
			entry.flags.force_set(leaf.compression_algo.into(), true);
		},
		CompressMode::Detect => {
			let mut buffer = Vec::new();
			leaf.handle.read_to_end(&mut buffer)?;

			let mut compressed_data = Vec::new();
			Compressor::new(buffer.as_slice()).compress(leaf.compression_algo, &mut compressed_data)?;

			if compressed_data.len() <= buffer.len() {
				entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
				entry.flags.force_set(leaf.compression_algo.into(), true);

				raw = compressed_data;
			} else {
				buffer.as_slice().read_to_end(&mut raw)?;
			};
		},
	}

	// If the compression feature is turned off, simply reads into buffer
	#[cfg(not(feature = "compression"))]
	{
		use crate::global::error::InternalError;

		if entry.flags.contains(Flags::COMPRESSED_FLAG) {
			return Err(InternalError::MissingFeatureError("compression"));
		};

		leaf.handle.read_to_end(&mut raw)?;
	}

	// Encryption comes second
	#[cfg(feature = "crypto")]
	if leaf.encrypt {
		if let Some(ex) = _encryptor {
			raw = ex.encrypt(&raw)?;
			entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
		}
	}

	Ok(ProcessedLeaf {
		data: raw,
		entry,
		#[cfg(feature = "crypto")]
		sign: leaf.sign,
	})
}

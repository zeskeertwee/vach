use crate::global::error::InternalResult;
use crate::global::{flags::Flags, reg_entry::RegistryEntry};

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
	pub fn new<S: AsRef<str>>(
		handle: R,
		id: S,
	) -> Leaf<R> {
		let default = Leaf::<&'static [u8]>::default();

		Leaf {
			handle,
			id: Arc::from(id.as_ref()),

			// copy from default implementation
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
	pub fn template<R2>(
		self,
		other: &Leaf<R2>,
	) -> Self {
		Leaf {
			handle: self.handle,
			id: self.id,

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
	pub fn compress(
		mut self,
		compress: CompressMode,
	) -> Self {
		self.compress = compress;
		self
	}

	/// Setter for the [`flags`](crate::builder::Flags) field
	pub fn flags(
		mut self,
		flags: Flags,
	) -> Self {
		self.flags = flags;
		self
	}

	/// Setter for the [`encrypt`](Leaf::encrypt) field
	#[cfg(feature = "crypto")]
	pub fn encrypt(
		mut self,
		encrypt: bool,
	) -> Self {
		self.encrypt = encrypt;
		self
	}

	/// Setter for the [`sign`](Leaf::sign) field
	#[cfg(feature = "crypto")]
	pub fn sign(
		mut self,
		sign: bool,
	) -> Self {
		self.sign = sign;
		self
	}

	/// Setter for the [`compression_algo`](Leaf::compression_algo) field
	#[cfg(feature = "compression")]
	pub fn compression_algo(
		mut self,
		compression_algo: CompressionAlgorithm,
	) -> Self {
		self.compression_algo = compression_algo;
		self
	}

	pub(crate) fn calculate_entry_bytes(
		&self,
		sign: bool,
	) -> usize {
		#[cfg(feature = "crypto")]
		let sig_len = if sign && self.sign { crate::SIGNATURE_LENGTH } else { 0 };
		#[cfg(not(feature = "crypto"))]
		let sig_len = 0;

		#[cfg(feature = "crypto")]
		let nonce_len = if sign && self.encrypt { crate::NONCE_LENGTH } else { 0 };
		#[cfg(not(feature = "crypto"))]
		let nonce_len = 0;

		self.id.len() + RegistryEntry::CONSTANT + sig_len + nonce_len
	}
}

impl<R> From<&mut Leaf<R>> for RegistryEntry {
	fn from(leaf: &mut Leaf<R>) -> Self {
		RegistryEntry {
			id: leaf.id.clone(),
			flags: leaf.flags,
			..RegistryEntry::empty()
		}
	}
}

// Processed data ready to be inserted into a `Write + Clone` target during Building
pub(crate) struct ProcessedLeaf {
	pub(crate) data: Vec<u8>,
	pub(crate) entry: RegistryEntry,
}

// Process Leaf into Prepared Data, externalised for multithreading purposes
#[inline(never)]
pub(crate) fn process_leaf<R: Read + Send + Sync>(
	leaf: &mut Leaf<R>,
	config: &super::BuilderConfig,
	_encryptor: Option<&Encryptor>,
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
	if let Some(ex) = _encryptor
		&& leaf.encrypt
	{
		entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
		let (_raw, nonce) = ex.encrypt(&raw)?;

		raw = _raw;
		entry.nonce = Some(nonce);
	}

	// Sign final data as-is in binary
	#[cfg(feature = "crypto")]
	if let Some(keypair) = &config.signing_key
		&& leaf.sign
	{
		entry.flags.force_set(Flags::SIGNED_FLAG, true);

		let entry_bytes = entry.id.as_bytes();
		raw.extend_from_slice(entry_bytes);

		// Include entry id in the signature
		entry.signature = Some(ed25519_dalek::Signer::sign(keypair, &raw));

		// truncate leaf data as it's not indicative of serialized data
		raw.truncate(raw.len() - entry.id.len());
	};

	Ok(ProcessedLeaf { data: raw, entry })
}

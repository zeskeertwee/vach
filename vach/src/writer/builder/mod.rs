use std::io::{BufWriter, Write, Seek, SeekFrom};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{
	Arc, Mutex,
	atomic::{Ordering, AtomicUsize},
};

mod config;
pub use config::BuilderConfig;
use super::leaf::{Leaf, HandleTrait};

#[cfg(feature = "compression")]
use {crate::global::compressor::Compressor, super::compress_mode::CompressMode, std::io::Read};

use crate::global::error::InternalError;
use crate::global::result::InternalResult;
use crate::{
	global::{header::Header, reg_entry::RegistryEntry, flags::Flags},
};

#[cfg(feature = "crypto")]
use {crate::crypto::Encryptor, ed25519_dalek::Signer};

/// A toggle blanket-trait wrapping around `io::Write + Seek` allowing for seamless switching between single and multithreaded execution, by implementing `Send + Sync`
#[cfg(feature = "multithreaded")]
pub trait DumpTrait: Write + Seek + Send + Sync {}
#[cfg(feature = "multithreaded")]
impl<T: Write + Seek + Send + Sync> DumpTrait for T {}

#[cfg(not(feature = "multithreaded"))]
/// A toggle blanket-trait wrapping around `io::Write + Seek` allowing for seamless switching between single and multithreaded execution, by implementing `Send + Sync`
pub trait DumpTrait: Write + Seek {}
#[cfg(not(feature = "multithreaded"))]
impl<T: Write + Seek> DumpTrait for T {}

/// The archive builder. Provides an interface with which one can configure and build valid `vach` archives.
#[derive(Default)]
pub struct Builder<'a> {
	pub(crate) leafs: Vec<Leaf<'a>>,
	pub(crate) id_set: HashSet<String>,
	leaf_template: Leaf<'a>,
}

impl<'a> Builder<'a> {
	/// Instantiates a new [`Builder`] with an empty processing queue.
	#[inline(always)]
	pub fn new() -> Builder<'a> {
		Builder::default()
	}

	/// Appends a read handle wrapped in a [`Leaf`] into the processing queue.
	/// The `data` is wrapped in the default [`Leaf`].
	/// The second argument is the `ID` with which the embedded data will be tagged
	/// ### Errors
	/// Returns an `Err(())` if a Leaf with the specified ID exists.
	pub fn add<D: HandleTrait + 'a>(&mut self, data: D, id: impl AsRef<str>) -> InternalResult<()> {
		let leaf = Leaf::from_handle(data)
			.id(id.as_ref().to_string())
			.template(&self.leaf_template);
		self.add_leaf(leaf)?;
		Ok(())
	}

	/// Removes all the [`Leaf`]s from the [`Builder`]. Leaves the `template` intact. Use this to re-use [`Builder`]s instead of instantiating new ones
	pub fn clear(&mut self) {
		self.id_set.clear();
		self.leafs.clear();
	}

	/// Loads all files from a directory, parses them into [`Leaf`]s and appends them into the processing queue.
	/// An optional [`Leaf`] is passed as a template from which the new [`Leaf`]s shall implement, pass `None` to use the [`Builder`] internal default template.
	/// Appended [`Leaf`]s have an `ID` in the form of of: `directory_name/file_name`. For example: "sounds/footstep.wav", "sample/script.data"
	/// ## Errors
	/// - Any of the underlying calls to the filesystem fail.
	/// - The internal call to `Builder::add_leaf()` returns an error.
	pub fn add_dir(&mut self, path: impl AsRef<Path>, template: Option<&Leaf<'a>>) -> InternalResult<()> {
		use std::fs;

		let directory = fs::read_dir(path)?;
		for file in directory {
			let uri = file?.path();

			let v = uri
				.iter()
				.map(|u| String::from(u.to_str().unwrap()))
				.collect::<Vec<String>>();

			if !uri.is_dir() {
				// Therefore a file
				let file = fs::File::open(uri)?;
				let leaf = Leaf::from_handle(file)
					.template(template.unwrap_or(&self.leaf_template))
					.id(&format!("{}/{}", v.get(v.len() - 2).unwrap(), v.last().unwrap()));

				self.add_leaf(leaf)?;
			}
		}

		Ok(())
	}

	/// Append a preconstructed [`Leaf`] into the processing queue.
	/// [`Leaf`]s added directly do not implement data from the [`Builder`]s internal template.
	/// ### Errors
	/// - Returns an error if a [`Leaf`] with the specified `ID` exists.
	pub fn add_leaf(&mut self, leaf: Leaf<'a>) -> InternalResult<()> {
		// Make sure no two leaves are written with the same ID
		if !self.id_set.insert(leaf.id.clone()) {
			return Err(InternalError::LeafAppendError(leaf.id));
		};

		self.leafs.push(leaf);
		Ok(())
	}

	/// Avoid unnecessary boilerplate by auto-templating all [`Leaf`]s added with `Builder::add(--)` with the given template
	/// ```
	/// use vach::builder::{Builder, Leaf};
	///
	/// let template = Leaf::default().version(12);
	/// let mut builder = Builder::new().template(template);
	///
	/// builder.add(b"JEB" as &[u8], "JEB_NAME").unwrap();
	/// // `JEB` is compressed and has a version of 12
	/// ```
	pub fn template(mut self, template: Leaf<'a>) -> Builder {
		self.leaf_template = template;
		self
	}

	/// This iterates over all [`Leaf`]s in the processing queue, parses them and writes the bytes out into a the target.
	/// Configure the custom *`MAGIC`*, `Header` flags and a [`Keypair`](crate::crypto::Keypair) using the [`BuilderConfig`] struct.
	/// Wraps the `target` in [BufWriter].
	/// ### Errors
	/// - Underlying `io` errors
	/// - If the optional compression or compression stages fails
	/// - If the requirements of a given stage, compression or encryption, are not met. Like not providing a keypair if a [`Leaf`] is to be encrypted.
	pub fn dump<W: DumpTrait>(&mut self, mut target: W, config: &BuilderConfig) -> InternalResult<usize> {
		// Keep track of how many bytes are written, and where bytes are being written
		#[cfg(feature = "multithreaded")]
		use rayon::prelude::*;

		// The total amount of bytes written
		let mut total_sync = 0usize;

		#[allow(unused_mut)]
		let mut reg_buffer_sync = Vec::new();

		// Calculate the size of the registry and check for [`Leaf`]s that request for encryption
		#[allow(unused_mut)]
		let mut leaf_offset_sync =
			self.leafs
				.iter()
				.map(|leaf| {
					// The size of it's ID, the minimum size of an entry without a signature, and the size of a signature only if a signature is incorporated into the entry
					leaf.id.len() + RegistryEntry::MIN_SIZE + {
						#[cfg(feature = "crypto")]
						if config.keypair.is_some() && leaf.sign {
							crate::SIGNATURE_LENGTH
						} else {
							0
						}
						#[cfg(not(feature = "crypto"))]
						{
							0
						}
					}
				})
				.reduce(|l1, l2| l1 + l2)
				.unwrap_or(0) + Header::BASE_SIZE;

		// Start at the very start of the file
		target.seek(SeekFrom::Start(0))?;

		// Write header in order defined in the spec document
		let mut wtr_sync = BufWriter::new(target);
		wtr_sync.write_all(&config.magic)?;

		// INSERT flags
		let mut temp = config.flags;

		#[cfg(feature = "crypto")]
		if config.keypair.is_some() {
			temp.force_set(Flags::SIGNED_FLAG, true);
		};

		wtr_sync.write_all(&temp.bits().to_le_bytes())?;

		// Write the version of the Archive Format|Builder|Loader
		wtr_sync.write_all(&crate::VERSION.to_le_bytes())?;
		wtr_sync.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

		// Update how many bytes have been written
		total_sync += Header::BASE_SIZE;

		// Configure encryption
		#[cfg(feature = "crypto")]
		let use_encryption = self.leafs.iter().any(|leaf| leaf.encrypt);

		#[cfg(feature = "crypto")]
		if use_encryption && config.keypair.is_none() {
			return Err(InternalError::NoKeypairError(
				"Leaf encryption error! A leaf requested for encryption, yet no keypair was provided(None)".to_string(),
			));
		};

		// Build encryptor
		#[cfg(feature = "crypto")]
		let encryptor = if use_encryption {
			let keypair = &config.keypair;

			Some(Encryptor::new(&keypair.as_ref().unwrap().public, config.magic))
		} else {
			None
		};

		// Define all arc-mutexes
		let leaf_offset_arc = Arc::new(AtomicUsize::new(leaf_offset_sync));
		let total_arc = Arc::new(AtomicUsize::new(total_sync));
		let wtr_arc = Arc::new(Mutex::new(wtr_sync));
		let reg_buffer_arc = Arc::new(Mutex::new(reg_buffer_sync));

		#[allow(unused_mut)]
		let mut iter_mut;

		// Conditionally define iterator
		#[cfg(feature = "multithreaded")]
		{
			iter_mut = self.leafs.as_mut_slice().par_iter_mut();
		}

		#[cfg(not(feature = "multithreaded"))]
		{
			iter_mut = self.leafs.iter_mut();
		}

		// Populate the archive glob
		iter_mut.try_for_each(|leaf: &mut Leaf<'a>| -> InternalResult<()> {
			let mut entry = leaf.to_registry_entry();
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

					let mut compressed_data = vec![];
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
				if entry.flags.contains(Flags::COMPRESSED_FLAG) {
					return Err(InternalError::MissingFeatureError("compression".to_string()));
				};

				leaf.handle.read_to_end(&mut raw)?;
			}

			// Encryption comes second
			#[cfg(feature = "crypto")]
			if leaf.encrypt {
				if let Some(ex) = &encryptor {
					raw = ex.encrypt(&raw)?;

					entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
				}
			}

			// Write processed leaf-contents and update offsets within `MutexGuard` protection
			let glob_length = raw.len();

			{
				// Lock writer
				let wtr_arc = Arc::clone(&wtr_arc);
				let mut wtr = wtr_arc.lock().unwrap();

				// Lock leaf_offset
				let leaf_offset_arc = Arc::clone(&leaf_offset_arc);
				let leaf_offset = leaf_offset_arc.load(Ordering::SeqCst);

				wtr.seek(SeekFrom::Start(leaf_offset as u64))?;
				wtr.write_all(&raw)?;

				// Update offset locations
				entry.location = leaf_offset as u64;
				leaf_offset_arc.fetch_add(glob_length, Ordering::SeqCst);

				// Update number of bytes written
				total_arc.fetch_add(glob_length, Ordering::SeqCst);
			};

			// Update the offset of the entry to be the length of the glob
			entry.offset = glob_length as u64;

			#[cfg(feature = "crypto")]
			if leaf.sign {
				if let Some(keypair) = &config.keypair {
					raw.extend_from_slice(leaf.id.as_bytes());

					// The reason we include the path in the signature is to prevent mangling in the registry,
					// For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
					// The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
					entry.signature = Some(keypair.sign(&raw));
					entry.flags.force_set(Flags::SIGNED_FLAG, true);

					drop(raw);
				};
			}

			// Make sure the ID is not too big or else it will break the archive
			if leaf.id.len() >= u16::MAX.into() {
				let mut copy = leaf.id.clone();
				copy.truncate(25);
				copy.shrink_to_fit();

				return Err(InternalError::IDSizeOverflowError(copy));
			};

			// Fetch bytes
			let mut entry_bytes = entry.bytes(&(leaf.id.len() as u16));
			entry_bytes.extend_from_slice(leaf.id.as_bytes());

			// Write to the registry-buffer and update total number of bytes written
			{
				let arc = Arc::clone(&reg_buffer_arc);
				let mut reg_buffer = arc.lock().unwrap();

				reg_buffer.write_all(&entry_bytes)?;
				total_arc.fetch_add(entry_bytes.len(), Ordering::SeqCst);
			}

			// Call the progress callback bound within the [`BuilderConfig`]
			if let Some(callback) = config.progress_callback {
				callback(&leaf.id, &entry);
			}

			Ok(())
		})?;

		// Write out the contents of the registry
		{
			let arc = Arc::clone(&wtr_arc);
			let mut wtr = arc.lock().unwrap();

			let reg_buffer_arc = Arc::clone(&reg_buffer_arc);
			let reg_buffer = reg_buffer_arc.lock().unwrap();

			wtr.seek(SeekFrom::Start(Header::BASE_SIZE as u64))?;
			wtr.write_all(reg_buffer.as_slice())?;
		};

		// Return total number of bytes written
		Ok(total_arc.load(Ordering::SeqCst))
	}
}

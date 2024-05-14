use std::{
	io::{Write, Seek, SeekFrom, Read},
	collections::HashSet,
	path::Path,
	sync::Arc,
};

#[cfg(feature = "multithreaded")]
use std::{thread, sync::mpsc};

mod config;
mod leaf;
mod prepared;

pub use config::BuilderConfig;
pub use leaf::Leaf;

#[cfg(feature = "compression")]
pub use leaf::CompressMode;

#[cfg(feature = "compression")]
use crate::global::compressor::Compressor;

use crate::global::error::*;
use crate::global::{header::Header, reg_entry::RegistryEntry, flags::Flags};

#[cfg(feature = "crypto")]
use {crate::crypto::Encryptor, ed25519_dalek::Signer};

#[cfg(not(feature = "crypto"))]
type Encryptor = ();

/// The archive builder. Provides an interface with which one can configure and build valid `vach` archives.
#[derive(Default)]
pub struct Builder<'a> {
	pub(crate) leafs: Vec<Leaf<'a>>,
	pub(crate) id_set: HashSet<Arc<str>>,
	leaf_template: Leaf<'a>,
}

impl<'a> Builder<'a> {
	/// Instantiates a new [`Builder`] with an empty processing queue.
	#[inline(always)]
	pub fn new() -> Builder<'a> {
		Builder::default()
	}

	/// Appends a read handle wrapped in a [`Leaf`] into the processing queue.
	/// The `data` is wrapped in the default [`Leaf`], without cloning the original data.
	/// The second argument is the `ID` with which the embedded data will be tagged
	/// ### Errors
	/// - if a Leaf with the specified ID exists.
	pub fn add<D: Read + Send + Sync + 'a>(&mut self, data: D, id: impl AsRef<str>) -> InternalResult {
		let leaf = Leaf::new(data)
			.id(id.as_ref().to_string())
			.template(&self.leaf_template);

		self.add_leaf(leaf)
	}

	/// Removes all the [`Leaf`]s from the [`Builder`]. Leaves the `template` intact. Use this to re-use [`Builder`]s instead of instantiating new ones
	pub fn clear(&mut self) {
		self.id_set.clear();
		self.leafs.clear();
	}

	/// Loads all files from a directory, parses them into [`Leaf`]s and appends them into the processing queue.
	/// An optional [`Leaf`] is passed as a template from which the new [`Leaf`]s shall implement, pass `None` to use the [`Builder`] internal default template.
	/// Appended [`Leaf`]s have an `ID` in the form of of: `directory_name/file_name`. For example: `sounds/footstep.wav1, `sample/script.data`
	/// ## Errors
	/// - Any of the underlying calls to the filesystem fail.
	/// - The internal call to `Builder::add_leaf()` fails.
	pub fn add_dir(&mut self, path: impl AsRef<Path>, template: Option<&Leaf<'a>>) -> InternalResult {
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
				let leaf = Leaf::new(file)
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
	pub fn add_leaf(&mut self, leaf: Leaf<'a>) -> InternalResult {
		// Make sure no two leaves are written with the same ID
		if !self.id_set.insert(leaf.id.clone()) {
			Err(InternalError::LeafAppendError(leaf.id))
		} else {
			self.leafs.push(leaf);
			Ok(())
		}
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

	fn process_leaf(leaf: &mut Leaf<'a>, encryptor: Option<&Encryptor>) -> InternalResult<prepared::Prepared> {
		let mut entry: RegistryEntry = leaf.into();
		let mut raw = Vec::new(); // 10MB

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
			if entry.flags.contains(Flags::COMPRESSED_FLAG) {
				return Err(InternalError::MissingFeatureError("compression"));
			};

			leaf.handle.read_to_end(&mut raw)?;
		}

		// Encryption comes second
		#[cfg(feature = "crypto")]
		if leaf.encrypt {
			if let Some(ex) = encryptor {
				raw = ex.encrypt(&raw)?;
				entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
			}
		}

		Ok(prepared::Prepared {
			data: raw,
			entry,
			#[cfg(feature = "crypto")]
			sign: leaf.sign,
		})
	}

	/// This iterates over all [`Leaf`]s in the processing queue, parses them and writes the bytes out into a the target.
	/// Configure the custom *`MAGIC`*, `Header` flags and a [`Keypair`](crate::crypto::Keypair) using the [`BuilderConfig`] struct.
	///
	/// ### Errors
	/// - Underlying `io` errors
	/// - If the optional compression or compression features aren't enabled
	/// - If the requirements of a given stage, compression or encryption, are not met. Like not providing a keypair if a [`Leaf`] is to be encrypted.
	pub fn dump<W: Write + Seek + Send>(self, mut target: W, config: &BuilderConfig) -> InternalResult<u64> {
		let Builder { mut leafs, .. } = self;

		// Calculate the size of the registry and check for [`Leaf`]s that request for encryption
		let mut bytes_written = 0;
		let mut leaf_offset = {
			leafs
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
				.unwrap_or(0) + Header::BASE_SIZE
		} as u64;

		// Start at the very start of the file
		target.seek(SeekFrom::Start(0))?;
		target.write_all(&config.magic)?;

		// INSERT flags
		let mut temp = config.flags;

		#[cfg(feature = "crypto")]
		if config.keypair.is_some() {
			temp.force_set(Flags::SIGNED_FLAG, true);
		};

		// Write remaining Header
		target.write_all(&temp.bits().to_le_bytes())?;
		target.write_all(&crate::VERSION.to_le_bytes())?;
		target.write_all(&(leafs.len() as u16).to_le_bytes())?;

		// Build encryptor
		#[cfg(feature = "crypto")]
		let encryptor = {
			let use_encryption = leafs.iter().any(|leaf| leaf.encrypt);
			if use_encryption {
				if let Some(keypair) = config.keypair.as_ref() {
					Some(Encryptor::new(&keypair.verifying_key(), config.magic))
				} else {
					return Err(InternalError::NoKeypairError);
				}
			} else {
				None
			}
		};

		#[cfg(not(feature = "crypto"))]
		let encryptor = None;

		// Callback for processing IO
		let mut registry = Vec::with_capacity(leaf_offset as usize - Header::BASE_SIZE);

		#[allow(unused_mut)]
		let mut write = |result: InternalResult<prepared::Prepared>| -> InternalResult<()> {
			let mut result = result?;
			let bytes = result.data.len() as u64;

			// write
			target.seek(SeekFrom::Start(leaf_offset))?;
			target.write_all(&result.data)?;

			// update entry
			result.entry.location = leaf_offset;
			result.entry.offset = bytes;

			// update state
			leaf_offset += result.data.len() as u64;
			bytes_written += bytes;

			// write out registry entry
			#[cfg(feature = "crypto")]
			if result.sign {
				if let Some(keypair) = &config.keypair {
					let entry_bytes = result.entry.encode(true)?;
					result.data.extend_from_slice(&entry_bytes); // DON"T FORGET TO TRUNCATE IF MODIFICATIONS ARE MADE

					// Include registry data in the signature
					result.entry.signature = Some(keypair.sign(&result.data));
					result.entry.flags.force_set(Flags::SIGNED_FLAG, true);
				};
			}

			// write to registry buffer, this one might include the Signature
			let entry_bytes = result.entry.encode(false)?;
			registry.write_all(&entry_bytes)?;

			// Call the progress callback bound within the [`BuilderConfig`]
			config.progress_callback.inspect(|c| c(&result.entry));

			Ok(())
		};

		#[cfg(feature = "multithreaded")]
		let (tx, rx) = mpsc::channel();

		#[cfg(feature = "multithreaded")]
		{
			thread::scope(|s| -> InternalResult<()> {
				let chunk_size = leafs.len() / config.num_threads;
				let chunks = leafs.chunks_mut(chunk_size);
				let encryptor = encryptor.as_ref();

				// Spawn CPU threads
				for chunk in chunks {
					let queue = tx.clone();

					s.spawn(move || {
						for leaf in chunk {
							let res = Builder::process_leaf(leaf, encryptor);
							queue.send(res).unwrap();
						}
					});
				}

				// Process IO, read results from
				while let Ok(result) = rx.recv() {
					write(result)?
				}

				Ok(())
			})?;
		};

		#[cfg(not(feature = "multithreaded"))]
		leafs
			.iter_mut()
			.map(|l| Builder::process_leaf(l, encryptor.as_ref()))
			.try_for_each(write)?;

		// write out Registry
		target.seek(SeekFrom::Start(Header::BASE_SIZE as _))?;
		target.write_all(&registry)?;

		// // Define all arc-mutexes
		// let leaf_offset_arc = Arc::new(AtomicU64::new(leaf_offset));
		// let total_arc = Arc::new(AtomicUsize::new(Header::BASE_SIZE));
		// let wtr_arc = Arc::new(Mutex::new(target));
		// let reg_buffer_arc = Arc::new(Mutex::new(reg_buffer_sync));

		// #[cfg(feature = "multithreaded")]
		// let iter_mut = self.leafs.as_mut_slice().par_iter_mut();

		// #[cfg(not(feature = "multithreaded"))]
		// let iter_mut = self.leafs.iter_mut();

		// // Populate the archive glob
		// iter_mut.try_for_each(|leaf: &mut Leaf<'a>| -> InternalResult {
		// 	let mut entry: RegistryEntry = leaf.into();
		// 	let mut raw = Vec::new();

		// 	// Compression comes first
		// 	#[cfg(feature = "compression")]
		// 	match leaf.compress {
		// 		CompressMode::Never => {
		// 			leaf.handle.read_to_end(&mut raw)?;
		// 		},
		// 		CompressMode::Always => {
		// 			Compressor::new(&mut leaf.handle).compress(leaf.compression_algo, &mut raw)?;

		// 			entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
		// 			entry.flags.force_set(leaf.compression_algo.into(), true);
		// 		},
		// 		CompressMode::Detect => {
		// 			let mut buffer = Vec::new();
		// 			leaf.handle.read_to_end(&mut buffer)?;

		// 			let mut compressed_data = Vec::new();
		// 			Compressor::new(buffer.as_slice()).compress(leaf.compression_algo, &mut compressed_data)?;

		// 			if compressed_data.len() <= buffer.len() {
		// 				entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
		// 				entry.flags.force_set(leaf.compression_algo.into(), true);

		// 				raw = compressed_data;
		// 			} else {
		// 				buffer.as_slice().read_to_end(&mut raw)?;
		// 			};
		// 		},
		// 	}

		// 	// If the compression feature is turned off, simply reads into buffer
		// 	#[cfg(not(feature = "compression"))]
		// 	{
		// 		if entry.flags.contains(Flags::COMPRESSED_FLAG) {
		// 			return Err(InternalError::MissingFeatureError("compression"));
		// 		};

		// 		leaf.handle.read_to_end(&mut raw)?;
		// 	}

		// 	// Encryption comes second
		// 	#[cfg(feature = "crypto")]
		// 	if leaf.encrypt {
		// 		if let Some(ex) = &encryptor {
		// 			raw = ex.encrypt(&raw)?;

		// 			entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
		// 		}
		// 	}

		// 	// Write processed leaf-contents and update offsets within `MutexGuard` protection
		// 	let glob_length = raw.len() as u64;

		// 	{
		// 		// Lock writer
		// 		let mut wtr = wtr_arc.lock();

		// 		// Lock leaf_offset
		// 		let leaf_offset = leaf_offset_arc.load(Ordering::SeqCst);

		// 		wtr.seek(SeekFrom::Start(leaf_offset))?;
		// 		wtr.write_all(&raw)?;

		// 		// Update offset locations
		// 		entry.location = leaf_offset;
		// 		leaf_offset_arc.fetch_add(glob_length, Ordering::SeqCst);

		// 		// Update number of bytes written
		// 		total_arc.fetch_add(glob_length as usize, Ordering::SeqCst);

		// 		// Update the offset of the entry to be the length of the glob
		// 		entry.offset = glob_length;
		// 	};

		// 	#[cfg(feature = "crypto")]
		// 	if leaf.sign {
		// 		if let Some(keypair) = &config.keypair {
		// 			raw.extend_from_slice(leaf.id.as_bytes());

		// 			// The reason we include the path in the signature is to prevent mangling in the registry,
		// 			// For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
		// 			// The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
		// 			entry.signature = Some(keypair.sign(&raw));
		// 			entry.flags.force_set(Flags::SIGNED_FLAG, true);

		// 			// RAW has exhausted it's usefulness, we save memory by deallocating
		// 			drop(raw);
		// 		};
		// 	}
		// 	// Fetch bytes
		// 	let mut entry_bytes = entry.bytes(&(leaf.id.len() as u16))?;
		// 	entry_bytes.extend_from_slice(leaf.id.as_bytes());

		// 	// Write to the registry-buffer and update total number of bytes written
		// 	{
		// 		let mut reg_buffer = reg_buffer_arc.lock();

		// 		reg_buffer.write_all(&entry_bytes)?;
		// 		total_arc.fetch_add(entry_bytes.len(), Ordering::SeqCst);
		// 	}

		// 	// Call the progress callback bound within the [`BuilderConfig`]
		// 	if let Some(callback) = config.progress_callback {
		// 		callback(&leaf, &entry)
		// 	}

		// 	Ok(())
		// })?;

		// // Write out the contents of the registry
		// {
		// 	let mut wtr = wtr_arc.lock();

		// 	let reg_buffer = reg_buffer_arc.lock();

		// 	wtr.seek(SeekFrom::Start(Header::BASE_SIZE as u64))?;
		// 	wtr.write_all(reg_buffer.as_slice())?;
		// };

		// // Return total number of bytes written
		// Ok(total_arc.load(Ordering::SeqCst))
		Ok(bytes_written)
	}
}

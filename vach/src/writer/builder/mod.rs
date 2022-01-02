use std::io::{BufWriter, Write, Read, Seek, SeekFrom};
use std::collections::HashSet;

mod config;
pub use config::BuilderConfig;
use super::leaf::{Leaf, CompressMode};
use crate::global::compressor::Compressor;
use crate::global::error::InternalError;
use crate::global::result::InternalResult;
use crate::{
	global::{edcryptor::Encryptor, header::Header, reg_entry::RegistryEntry, flags::Flags},
};

use ed25519_dalek::Signer;

/// The archive builder. Provides an interface with which one can configure and build out valid `vach` archives.
pub struct Builder<'a> {
	pub(crate) leafs: Vec<Leaf<'a>>,
	pub(crate) id_set: HashSet<String>,
	leaf_template: Leaf<'a>,
}

impl<'a> Default for Builder<'a> {
	#[inline(always)]
	fn default() -> Builder<'a> {
		Builder {
			leafs: Vec::new(),
			id_set: HashSet::new(),
			leaf_template: Leaf::default(),
		}
	}
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
	pub fn add<D: Read + 'a>(&mut self, data: D, id: &str) -> InternalResult<()> {
		let leaf = Leaf::from_handle(data).id(id).template(&self.leaf_template);
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
	pub fn add_dir(&mut self, path: &str, template: Option<&Leaf<'a>>) -> InternalResult<()> {
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
					.id(&format!(
						"{}/{}",
						v.get(v.len() - 2).unwrap(),
						v.last().unwrap()
					));

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
	/// use vach::builder::{Builder, Leaf, CompressMode};
	///
	/// let template = Leaf::default().compress(CompressMode::Always).version(12);
	/// let mut builder = Builder::new().template(template);
	///
	/// builder.add(b"JEB" as &[u8], "JEB").unwrap();
	/// // `JEB` is compressed and has a version of 12
	/// ```
	pub fn template(mut self, template: Leaf<'a>) -> Builder {
		self.leaf_template = template;
		self
	}

	/// This iterates over all [`Leaf`]s in the processing queue, parses them and writes the bytes out into a the target.
	/// Configure the custom *`MAGIC`*, Header flags and a `Keypair` using the [`BuilderConfig`] struct.
	/// ### Errors
	/// - Underlying `io` errors
	/// - If the optional compression or compression stages fails
	/// - If the requirements of a given stage, compression or encryption, are not met. Like not providing a keypair if a [`Leaf`] is to be encrypted.
	pub fn dump<W: Write + Seek>(
		&mut self, mut target: W, config: &BuilderConfig,
	) -> InternalResult<usize> {
		// Keep track of how many bytes are written, and where bytes are being written
		let mut size = 0usize;
		let mut reg_buffer = Vec::new();

		// Calculate the size of the registry and check for [`Leaf`]s that request for encryption
		let mut leaf_offset =
			self.leafs
				.iter()
				.map(|leaf| {
					// The size of it's ID, the minimum size of an entry without a signature, and the size of a signature only if a signature is incorporated into the entry
					leaf.id.len()
						+ RegistryEntry::MIN_SIZE
						+ (if config.keypair.is_some() { crate::SIGNATURE_LENGTH } else { 0 })
				})
				.reduce(|l1, l2| l1 + l2)
				.unwrap_or(0) + Header::BASE_SIZE;

		// Start at the very start of the file
		target.seek(SeekFrom::Start(0))?;

		// Write header in order defined in the spec document
		let mut wtr = BufWriter::new(target);
		wtr.write_all(&config.magic)?;

		// INSERT flags
		let mut temp = config.flags;
		if config.keypair.is_some() {
			temp.force_set(Flags::SIGNED_FLAG, true);
		};

		wtr.write_all(&temp.bits().to_le_bytes())?;

		// Write the version of the Archive Format|Builder|Loader
		wtr.write_all(&crate::VERSION.to_le_bytes())?;
		wtr.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

		// Update how many bytes have been written
		size += Header::BASE_SIZE;

		// Configure encryption
		let use_encryption = self.leafs.iter().any(|leaf| leaf.encrypt);

		if use_encryption && config.keypair.is_none() {
			return Err(InternalError::NoKeypairError("Leaf encryption error! A leaf requested for encryption, yet no keypair was provided(None)".to_string()));
		};

		// Build encryptor
		let encryptor = if use_encryption {
			let keypair = &config.keypair;

			Some(Encryptor::new(
				&keypair.as_ref().unwrap().public,
				config.magic,
			))
		} else {
			None
		};

		// Populate the archive glob
		for leaf in self.leafs.iter_mut() {
			let mut entry = leaf.to_registry_entry();
			let mut leaf_bytes = Vec::new();

			// Check if this is a linked [`Leaf`]
			if let Some(id) = &leaf.link_mode {
				if self.id_set.contains(id) {
					use std::io::Cursor;

					leaf.handle = Box::new(Cursor::new(id.as_bytes().to_vec()));
					entry.flags.force_set(Flags::LINK_FLAG, true);
				} else {
					return Err(InternalError::MissingResourceError(format!(
						"Linked Leaf: {}, references a non-existent Leaf: {}",
						leaf.id, id
					)));
				}
			}

			// Compression comes first
			match leaf.compress {
				CompressMode::Never => {
					leaf.handle.read_to_end(&mut leaf_bytes)?;
				}
				CompressMode::Always => {
					leaf_bytes = Compressor::new(&mut leaf.handle).compress(leaf.compression_algo)?;

					entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
					entry.flags.force_set(leaf.compression_algo.into(), true);
				}
				CompressMode::Detect => {
					let mut buffer = Vec::new();
					leaf.handle.read_to_end(&mut buffer)?;

					let compressed_data = Compressor::new(buffer.as_slice()).compress(leaf.compression_algo)?;
					let ratio = compressed_data.len() as f32 / buffer.len() as f32;

					if ratio < 1f32 {
						entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
						entry.flags.force_set(leaf.compression_algo.into(), true);

						leaf_bytes = compressed_data;
					} else {
						buffer.as_slice().read_to_end(&mut leaf_bytes)?;
					};
				}
			}

			// Encryption comes after
			if leaf.encrypt {
				if let Some(ex) = &encryptor {
					leaf_bytes = match ex.encrypt(&leaf_bytes) {
						Ok(bytes) => bytes,
						Err(err) => {
							return Err(InternalError::CryptoError(format!(
								"Unable to encrypt leaf: {}. Error: {}",
								leaf.id, err
							)))
						}
					};

					entry.flags.force_set(Flags::ENCRYPTED_FLAG, true);
				}
			}

			// Buffer the contents of the leaf, to be written later
			wtr.seek(SeekFrom::Start(leaf_offset as u64))?;
			let glob_length = leaf_bytes.len();
			wtr.write_all(&leaf_bytes)?;
			size += glob_length;

			entry.location = leaf_offset as u64;
			leaf_offset += glob_length;
			entry.offset = glob_length as u64;

			if leaf.sign {
				if let Some(keypair) = &config.keypair {
					// The reason we include the path in the signature is to prevent mangling in the registry,
					// For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
					// The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
					leaf_bytes.extend(leaf.id.as_bytes());
					entry.signature = Some(keypair.sign(&leaf_bytes));
					entry.flags.force_set(Flags::SIGNED_FLAG, true);
					drop(leaf_bytes);
				};
			}

			// Make sure the ID is not too big or else it will break the archive
			if leaf.id.len() >= u16::MAX.into() {
				let mut copy = leaf.id.clone();
				copy.truncate(25);

				return Err(InternalError::IDSizeOverflowError(copy));
			};

			// Fetch bytes
			let mut entry_bytes = entry.bytes(&(leaf.id.len() as u16));
			entry_bytes.extend(leaf.id.as_bytes());

			// Write to the registry
			reg_buffer.write_all(&entry_bytes)?;

			// Call the progress callback bound within the [`BuilderConfig`]
			if let Some(callback) = &config.progress_callback {
				callback(&leaf.id, glob_length, &entry);
			}

			// Update offsets
			size += entry_bytes.len();
		}

		wtr.seek(SeekFrom::Start(Header::BASE_SIZE as u64))?;
		wtr.write_all(reg_buffer.as_slice())?;

		Ok(size)
	}
}

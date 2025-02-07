use std::io::{Read, Seek, SeekFrom, Write};

#[cfg(feature = "multithreaded")]
use std::{thread, sync::mpsc};

mod config;
mod leaf;

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

// Processed data ready to be inserted into a `Write + Clone` target during Building
pub(crate) struct Prepared {
	pub(crate) data: Vec<u8>,
	pub(crate) entry: RegistryEntry,
	#[cfg(feature = "crypto")]
	pub(crate) sign: bool,
}

impl Prepared {
	// Process Leaf into Prepared Data, externalised for multithreading purposes
	fn from_leaf(leaf: &mut Leaf<'_>, encryptor: Option<&Encryptor>) -> InternalResult<Prepared> {
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

		Ok(Prepared {
			data: raw,
			entry,
			#[cfg(feature = "crypto")]
			sign: leaf.sign,
		})
	}
}

/// This iterates over all [`Leaf`]s in the processing queue, parses them and writes the bytes out into a the target.
/// Configure the custom *`MAGIC`*, `Header` flags and a [`Keypair`](crate::crypto::Keypair) using the [`BuilderConfig`] struct.
pub fn dump<'a, W: Write + Seek + Send>(
	mut target: W, leaves: &mut [Leaf<'a>], config: &BuilderConfig,
	mut callback: Option<&mut dyn FnMut(&RegistryEntry, &[u8])>,
) -> InternalResult<u64> {
	let set = leaves
		.iter()
		.map(|l| l.id.as_ref())
		.collect::<std::collections::HashSet<_>>();

	if set.len() < leaves.len() {
		for (idx, leaf) in leaves.iter().enumerate() {
			let slice = &leaves[idx + 1..];

			// find duplicate
			if slice.iter().any(|l| l.id == leaf.id) {
				return Err(InternalError::DuplicateLeafID(leaf.id.to_string()));
			}
		}
	}

	// Calculate the size of the registry and check for [`Leaf`]s that request for encryption
	let mut bytes_written = 0;
	let mut leaf_offset = {
		leaves
			.iter()
			.map(|leaf| {
				// The size of it's ID, the minimum size of an entry without a signature, and the size of a signature only if a signature is incorporated into the entry
				leaf.id.len() + RegistryEntry::MIN_SIZE + {
					#[cfg(feature = "crypto")]
					if config.signing_key.is_some() && leaf.sign {
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
			.unwrap_or(0)
			+ Header::BASE_SIZE
	} as u64;

	// Start at the very start of the file
	target.seek(SeekFrom::Start(0))?;
	target.write_all(&config.magic)?;

	// INSERT flags
	let mut temp = config.flags;

	#[cfg(feature = "crypto")]
	if config.signing_key.is_some() {
		temp.force_set(Flags::SIGNED_FLAG, true);
	};

	// Write remaining Header
	target.write_all(&temp.bits().to_le_bytes())?;
	target.write_all(&crate::VERSION.to_le_bytes())?;
	target.write_all(&(leaves.len() as u16).to_le_bytes())?;

	// Build encryptor
	#[cfg(feature = "crypto")]
	let encryptor = {
		let use_encryption = leaves.iter().any(|leaf| leaf.encrypt);
		if use_encryption {
			if let Some(keypair) = config.signing_key.as_ref() {
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
	let mut write = |result: InternalResult<Prepared>| -> InternalResult<()> {
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
			if let Some(keypair) = &config.signing_key {
				result.entry.flags.force_set(Flags::SIGNED_FLAG, true);

				let entry_bytes = result.entry.to_bytes(true)?;
				result.data.extend_from_slice(&entry_bytes);

				// Include registry data in the signature
				result.entry.signature = Some(keypair.sign(&result.data));
			};
		}

		// write to registry buffer, this one might include the Signature
		let entry_bytes = result.entry.to_bytes(false)?;
		registry.write_all(&entry_bytes)?;

		// Call the progress callback bound within the [`BuilderConfig`]
		if let Some(callback) = callback.as_mut() {
			callback(&result.entry, &result.data);
		}

		Ok(())
	};

	#[cfg(feature = "multithreaded")]
	let (tx, rx) = mpsc::sync_channel(leaves.len());

	#[cfg(feature = "multithreaded")]
	if !leaves.is_empty() {
		thread::scope(|s| -> InternalResult<()> {
			let count = leaves.len();
			#[rustfmt::skip]
				let chunk_size = if config.num_threads.get() > count { 6 } else { count / config.num_threads };

			let chunks = leaves.chunks_mut(chunk_size);
			let encryptor = encryptor.as_ref();

			// Spawn CPU threads
			for chunk in chunks {
				let queue = tx.clone();

				s.spawn(move || {
					for leaf in chunk {
						let res = Prepared::from_leaf(leaf, encryptor);
						queue.send(res).unwrap();
					}
				});
			}

			// Process IO, read results from
			let mut results = 0;
			loop {
				match rx.try_recv() {
					Ok(r) => {
						results += 1;
						write(r)?
					},
					Err(e) => match e {
						mpsc::TryRecvError::Empty => {
							if results >= count {
								break Ok(());
							}
						},
						mpsc::TryRecvError::Disconnected => break Ok(()),
					},
				}
			}
		})?;
	};

	#[cfg(not(feature = "multithreaded"))]
	leaves
		.iter_mut()
		.map(|l| Prepared::from_leaf(l, encryptor.as_ref()))
		.try_for_each(write)?;

	// write out Registry
	target.seek(SeekFrom::Start(Header::BASE_SIZE as _))?;
	target.write_all(&registry)?;

	Ok(bytes_written)
}

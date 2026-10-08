use std::io::{Read, Seek, SeekFrom, Write};

mod config;
mod leaf;

pub use config::BuilderConfig;
pub use leaf::Leaf;

#[cfg(feature = "compression")]
pub use {crate::global::compressor::Compressor, leaf::CompressMode};

use crate::global::error::*;
use crate::global::{header::Header, reg_entry::RegistryEntry};

#[cfg(feature = "crypto")]
use crate::{crypto::Encryptor, global::flags::Flags};

#[cfg(not(feature = "crypto"))]
type Encryptor = ();

/// Counts bytes written to the target
struct WriteCounter<W: Send> {
	bytes: u64,
	inner: W,
}

impl<W: Write + Send> Write for WriteCounter<W> {
	fn write(
		&mut self,
		buf: &[u8],
	) -> std::io::Result<usize> {
		let len = self.inner.write(buf)?;
		self.bytes += len as u64;
		Ok(len)
	}

	fn flush(&mut self) -> std::io::Result<()> {
		self.inner.flush()
	}
}

impl<W: Seek + Send> Seek for WriteCounter<W> {
	fn seek(
		&mut self,
		pos: SeekFrom,
	) -> std::io::Result<u64> {
		self.inner.seek(pos)
	}
}

/// iterates over all [`Leaf`], processes them and writes the output into the target. returns bytes written to `target`
pub fn dump<W, R>(
	target: W,
	leaves: &mut [Leaf<R>],
	config: Option<BuilderConfig>,
	mut callback: Option<&mut dyn FnMut(&RegistryEntry, &[u8])>,
) -> InternalResult<u64>
where
	W: Write + Seek + Send,
	R: Read + Sync + Send,
{
	let mut config = config.unwrap_or_default();
	let mut target = WriteCounter { bytes: 0, inner: target };

	// find duplicates
	let mut set = std::collections::HashSet::with_capacity(leaves.len());
	for id in leaves.iter().map(|l| l.id.as_ref()) {
		if !set.insert(id) {
			return Err(InternalError::DuplicateLeafID(id.to_string()));
		}
	}

	// Determines the offset at which to start writing leafs
	let mut leaf_offset = {
		Header::BASE_SIZE + {
			#[cfg(feature = "crypto")]
			let sign = config.signing_key.is_some();

			#[cfg(not(feature = "crypto"))]
			let sign = false;

			leaves.iter().map(|leaf| leaf.calculate_entry_bytes(sign)).sum::<usize>()
		}
	} as u64;

	#[cfg(feature = "crypto")]
	if config.signing_key.is_some() {
		config.flags.force_set(Flags::SIGNED_FLAG, true);
	};

	// write HEADER
	let header = crate::global::header::Header {
		magic: crate::MAGIC,
		flags: config.flags,
		version: crate::VERSION,
		capacity: leaves.len() as u16,
	};

	target.seek(SeekFrom::Start(0))?;
	target.write_all(&header.to_bytes())?;

	// Build encryptor
	#[cfg(feature = "crypto")]
	let encryptor = {
		let use_encryption = leaves.iter().any(|leaf| leaf.encrypt);
		if use_encryption {
			if let Some(keypair) = config.signing_key.as_ref() {
				Some(Encryptor::new(&keypair.verifying_key()))
			} else {
				return Err(InternalError::NoKeypairError);
			}
		} else {
			None
		}
	};

	#[cfg(not(feature = "crypto"))]
	let encryptor = None;

	// buffer registry data
	let mut registry = Vec::with_capacity(leaf_offset as usize - Header::BASE_SIZE);
	target.seek(SeekFrom::Start(leaf_offset))?;

	#[allow(unused_mut)]
	// Callback for processing IO
	let mut write = |result: InternalResult<leaf::ProcessedLeaf>| -> InternalResult<()> {
		let mut processed = result?;
		let bytes = processed.data.len() as u64;

		// write LEAF
		target.write_all(&processed.data)?;

		// update registry entry
		processed.entry.location = leaf_offset;
		processed.entry.offset = bytes;

		// increment leaf offset
		leaf_offset += processed.data.len() as u64;

		// write to registry buffer, this one might include the Signature
		let entry_bytes = processed.entry.to_bytes()?;
		registry.write_all(&entry_bytes)?;

		// Call the progress callback bound within the [`BuilderConfig`]
		if let Some(callback) = callback.as_mut() {
			(*callback)(&processed.entry, &processed.data);
		}

		Ok(())
	};

	if config.num_threads > 1 {
		use std::{sync::mpsc, thread};

		let (tx, rx) = mpsc::sync_channel(leaves.len());
		thread::scope(|s| -> InternalResult<()> {
			let count = leaves.len();

			#[rustfmt::skip]
			// if we have an insane number of threads send leafs in chunks of 8
			let chunk_size = if config.num_threads > count { 8 } else { count / config.num_threads.max(1) };
			let encryptor = encryptor.as_ref();

			// Spawn CPU threads
			for chunk in leaves.chunks_mut(chunk_size) {
				let queue = tx.clone();
				let _config = &config;

				s.spawn(move || {
					for leaf in chunk {
						let res = leaf::process_leaf(leaf, _config, encryptor);
						queue.send(res).unwrap();
					}
				});
			}

			// Process IO by waiting for each result instead of busy-polling the channel.
			for _ in 0..count {
				let result = rx.recv().map_err(|_| InternalError::OtherError("worker channel disconnected".into()))?;
				write(result)?;
			}

			Ok(())
		})?;
	} else {
		// processed all on the main thread baby!
		leaves.iter_mut().map(|l| leaf::process_leaf(l, &config, encryptor.as_ref())).try_for_each(write)?;
	};

	// write UPDATED REGISTRY
	target.seek(SeekFrom::Start(Header::BASE_SIZE as _))?;
	target.write_all(&registry)?;

	target.flush()?;
	Ok(target.bytes)
}

mod config;
use super::leaf::{Leaf, CompressMode};
use crate::global::{header::Header, reg_entry::RegistryEntry, types::{Flags}};
pub use config::BuilderConfig;

use ed25519_dalek::Signer;
use lz4_flex as lz4;
use std::io::{self, BufWriter, Write, Read};

pub struct Builder<'a> {
	leafs: Vec<Leaf<'a>>,
}

impl<'a> Default for Builder<'a> {
	#[inline(always)]
	fn default() -> Builder<'a> {
		Builder { leafs: Vec::new() }
	}
}

impl<'a> Builder<'a> {
	#[inline(always)]
	pub fn new() -> Builder<'a> {
		Builder::default()
	}
	pub fn add(&mut self, data: impl Read + 'a, id: &str) -> anyhow::Result<()> {
		let leaf = Leaf::from_handle(data)?.id(id);
		self.add_leaf(leaf);
		Ok(())
	}
	pub fn add_dir(&mut self, path: &str, template: &Leaf) -> anyhow::Result<()> {
		use std::fs;

		let directory = fs::read_dir(path)?;
		for file in directory {
			let uri = file?.path();
			let v = uri.iter().map(|u| String::from(u.to_str().unwrap())).collect::<Vec<String>>();

			if !uri.is_dir() {
				// Therefore a file
				let file = fs::File::open(uri)?;
				let leaf = Leaf::from_handle(file)?.template(template).id(&format!("{}/{}", v[0], v[1]));

				self.leafs.push(leaf);
			}
		}

		Ok(())
	}

	#[inline(always)]
	pub fn add_leaf(&mut self, leaf: Leaf<'a>) {
		self.leafs.push(leaf);
	}

	pub fn dump<W: Write>(&mut self, target: W, config: &BuilderConfig) -> anyhow::Result<usize> {
		// Keep track of how many bytes are written
		let mut size = 0usize;

		// Write header in order defined in the spec document
		let mut buffer = BufWriter::new(target);
		buffer.write_all(&config.magic)?;

		// INSERT flags
		let mut temp = config.flags;
		if config.keypair.is_some() {
			temp.force_set(Flags::SIGNED_FLAG, true);
		};
		buffer.write_all(&temp.bits().to_le_bytes())?;

		// Write the version of the Archive Format|Builder|Loader
		buffer.write_all(&crate::VERSION.to_le_bytes())?;
		buffer.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

		// Update how many bytes have been written
		size += Header::BASE_SIZE;

		let mut leaf_data = Vec::new();

		// Calculate the size of the registry
		let mut reg_size = 0usize;
		for leaf in self.leafs.iter() {
			reg_size += leaf.id.len() + RegistryEntry::MIN_SIZE
		}

		// Start counting the offset of the leafs from the end of the registry
		let mut leaf_offset = reg_size + Header::BASE_SIZE;

		// Populate the archive glob
		for leaf in self.leafs.iter_mut() {
			let mut entry = leaf.to_registry_entry();
			let mut glob = Vec::new();

			// Create and compare compressed leaf data
			match leaf.compress {
				CompressMode::Never => { io::copy(&mut leaf.handle, &mut glob)?; }
				CompressMode::Always => {
					let mut compressor = lz4::frame::FrameEncoder::new(&mut glob);
					io::copy(&mut leaf.handle, &mut compressor)?;
				}
				CompressMode::Detect => {
					let mut compressor = lz4::frame::FrameEncoder::new(Vec::new());
					let length = io::copy(&mut leaf.handle, &mut compressor)?;
					let compressed_data = compressor.finish()?;

					let ratio = compressed_data.len() as f32 / length as f32;
					if ratio < 1f32 {
						entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
						glob = compressed_data;
					} else {
						drop(compressed_data);
					};
				}
			}

			let glob_length = glob.len();

			// Buffer the contents of the leaf, to be written later
			leaf_data.extend(&glob);

			entry.location = leaf_offset as u64;
			leaf_offset += glob_length;
			entry.offset = glob_length as u64;

			if let Some(keypair) = &config.keypair {
				// The reason we include the path in the signature is to prevent mangling in the registry,
				// For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
				// The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
				glob.extend(leaf.id.as_bytes());
				entry.signature = keypair.sign(&glob);
			};

			{
				// Write to the registry
				let mut entry_bytes =
					entry.bytes(&(leaf.id.len() as u16), config.keypair.is_some());
				entry_bytes.extend(leaf.id.as_bytes());
				buffer.write_all(&entry_bytes)?;
				size += entry_bytes.len();
			};

			drop(glob)
		}

		// Write the glob
		buffer.write_all(&leaf_data)?;
		size += leaf_data.len();

		drop(leaf_data);

		Ok(size)
	}
}

impl<'a> Read for Builder<'a> {
	fn read(&mut self, target: &mut [u8]) -> Result<usize, io::Error> {
		match self.dump(target, &BuilderConfig::default()) {
			Ok(size) => Ok(size),
			Err(err) => Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
		}
	}
}

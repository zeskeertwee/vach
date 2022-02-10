use std::{convert::TryInto, fs::File};

use tabled::{Style, Table, Tabled};
use vach::{
	prelude::{HeaderConfig, Archive, Flags},
	archive::CompressionAlgorithm,
};
use indicatif::HumanBytes;

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.0.1";

/// This command lists the entries in an archive in tabulated form
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		let archive_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => {
				anyhow::bail!("Please provide an input archive file using the -i or --input keys!")
			},
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		let file = File::open(archive_path)?;
		let archive = Archive::with_config(file, &HeaderConfig::new(magic, None))?;

		if archive.entries().is_empty() {
			println!("<EMPTY ARCHIVE> @ {}", archive_path);
		} else {
			let table_entries: Vec<FileTableEntry> = archive
				.entries()
				.iter()
				.map(|(id, entry)| {
					let c_algo = if entry.flags.contains(Flags::LZ4_COMPRESSED) {
						Some(CompressionAlgorithm::LZ4)
					} else if entry.flags.contains(Flags::BROTLI_COMPRESSED) {
						Some(CompressionAlgorithm::Brotli(8))
					} else if entry.flags.contains(Flags::SNAPPY_COMPRESSED) {
						Some(CompressionAlgorithm::Snappy)
					} else {
						None
					};

					let c_algo = match c_algo {
						Some(algo) => algo.to_string(),
						None => "None".to_string(),
					};

					FileTableEntry {
						id,
						size: HumanBytes(entry.offset).to_string(),
						flags: entry.flags,
						compression: c_algo,
					}
				})
				.collect();

			let table = Table::new(table_entries).with(Style::PSEUDO_CLEAN);
			println!("{}", table);
		}

		Ok(())
	}
}

#[derive(Tabled)]
struct FileTableEntry<'a> {
	id: &'a str,
	size: String,
	flags: Flags,
	compression: String,
}

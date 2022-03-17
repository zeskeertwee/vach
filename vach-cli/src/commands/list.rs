use std::fs::File;

use tabled::{Style, Table, Tabled, Modify, Full, MaxWidth, Alignment, Column};
use vach::{
	prelude::{HeaderConfig, Archive, Flags},
	archive::{CompressionAlgorithm, RegistryEntry},
};
use indicatif::HumanBytes;

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.2.0";

enum Sort {
	SizeAscending,
	SizeDescending,
	Alphabetical,
	AlphabeticalReversed,
	None,
}

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

		let sort = match args.value_of(key_names::SORT) {
			Some("alphabetical") => Sort::Alphabetical,
			Some("alphabetical-reversed") => Sort::AlphabeticalReversed,
			Some("size-ascending") => Sort::SizeAscending,
			Some("size-descending") => Sort::SizeDescending,
			Some(_) => Sort::None,
			None => Sort::None,
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		let file = File::open(archive_path)?;
		let archive = Archive::with_config(file, &HeaderConfig::new(magic, None))?;

		if archive.entries().is_empty() {
			println!("<EMPTY ARCHIVE> @ {}", archive);
		} else {
			let mut entries: Vec<(String, RegistryEntry)> = archive
				.entries()
				.iter()
				.map(|(id, entry)| (id.clone(), entry.clone()))
				.collect();

			// Log some additional info about this archive
			println!("{}", archive);

			// Sort the entries accordingly
			match sort {
				Sort::SizeAscending => entries.sort_by(|a, b| a.1.offset.cmp(&b.1.offset)),
				Sort::SizeDescending => entries.sort_by(|a, b| b.1.offset.cmp(&a.1.offset)),
				Sort::Alphabetical => entries.sort_by(|a, b| a.0.cmp(&b.0)),
				Sort::AlphabeticalReversed => entries.sort_by(|a, b| b.0.cmp(&a.0)),
				Sort::None => (),
			};

			let table_entries: Vec<FileTableEntry> = entries
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

			let mut table = Table::new(table_entries)
				.with(Style::modern().horizontal_off())
				.with(Modify::new(Column(..1)).with(Alignment::left()));

			// Make sure table fills terminal
			if let Some((term_width, _)) = term_size::dimensions() {
				table = table.with(Modify::new(Full).with(MaxWidth::truncating(term_width - 50).suffix("...")));
			};

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

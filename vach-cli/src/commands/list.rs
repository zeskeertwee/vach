use std::{convert::TryInto, fs::File};

use tabled::{Style, Table, Tabled};
use vach::prelude::{HeaderConfig, Archive, Flags};
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
			}
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		let file = File::open(archive_path)?;
		let archive = Archive::with_config(file, &HeaderConfig::new(magic, None))?;

		if !archive.entries().is_empty() {
			let table_entries: Vec<FileTableEntry> = archive
				.entries()
				.iter()
				.map(|(id, entry)| FileTableEntry {
					id,
					size: HumanBytes(entry.offset).to_string(),
					flags: entry.flags,
				})
				.collect();

			let table = Table::new(table_entries).with(Style::PSEUDO_CLEAN);
			println!("{}", table.to_string());
		} else {
			println!("<EMPTY ARCHIVE> @ {}", archive_path);
		}

		Ok(())
	}
}

#[derive(Tabled)]
struct FileTableEntry<'a> {
	id: &'a str,
	size: String,
	flags: Flags,
}

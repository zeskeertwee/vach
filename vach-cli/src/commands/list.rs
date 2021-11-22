use std::{convert::TryInto, fs::File};

use tabled::{Style, Table, Tabled};
use anyhow::{Result, bail};
use vach::prelude::*;
use bytesize::ByteSize;

use super::CommandTrait;
use crate::keys::key_names;

/// This command lists the entries in an archive in tabulated form
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> Result<()> {
		let archive_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => bail!("Please provide an input archive file using the -i or --input keys!"),
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
					size: ByteSize(entry.offset).to_string(),
					flags: entry.flags,
				})
				.collect();

			let table = Table::new(table_entries).with(Style::pseudo_clean());
			println!("{}", table.to_string());
		} else {
			println!("<EMPTY ARCHIVE> @ {}", archive_path);
		}

		Ok(())
	}

	fn version(&self) -> &'static str {
		"0.0.1"
	}
}

#[derive(Tabled)]
struct FileTableEntry<'a> {
	id: &'a str,
	size: String,
	flags: Flags,
}

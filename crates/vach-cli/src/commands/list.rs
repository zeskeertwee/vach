use std::fs::File;

use indicatif::HumanBytes;
use tabled::{
	Table, Tabled,
	settings::{object::Columns, *},
};
use vach::prelude::*;

use super::CommandTrait;
use crate::cli;

#[derive(Tabled)]
struct FileTableEntry<'a> {
	id: &'a str,
	size: String,
	flags: Flags,
	compression: &'static str,
}

/// This command lists the entries in an archive in tabulated form
pub struct Subcommand;

impl CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.3"
	}

	fn evaluate(
		&self,
		cli: cli::CommandLine,
	) -> anyhow::Result<()> {
		let cli::Command::List { input, sort } = cli.command else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let file = File::open(input)?;
		let archive = Archive::new(file)?;

		// log basic metadata
		println!("{}", archive);

		let mut entries = archive.entries().values().collect::<Vec<_>>();
		match sort {
			None | Some(cli::SortSetting::Alphabetical) => entries.sort_by_key(|a| a.id.as_ref()),
			Some(cli::SortSetting::AlphabeticalReversed) => entries.sort_by_key(|b| std::cmp::Reverse(b.id.as_ref())),
			Some(cli::SortSetting::SizeAscending) => entries.sort_by_key(|a| a.offset),
			Some(cli::SortSetting::SizeDescending) => entries.sort_by_key(|b| std::cmp::Reverse(b.offset)),
		};

		let table_entries: Vec<FileTableEntry> = entries
			.into_iter()
			.map(|entry| {
				let c_algo = if entry.flags.contains(Flags::LZ4_COMPRESSED) {
					"LZ4"
				} else if entry.flags.contains(Flags::BROTLI_COMPRESSED) {
					"Brotli"
				} else if entry.flags.contains(Flags::SNAPPY_COMPRESSED) {
					"Snappy"
				} else {
					"None"
				};

				FileTableEntry {
					id: &entry.id,
					size: HumanBytes(entry.offset).to_string(),
					flags: entry.flags,
					compression: c_algo,
				}
			})
			.collect();

		let mut table = Table::new(table_entries);
		table.with(Style::rounded()).with(Modify::list(Columns::new(..1), Alignment::left()));

		println!("{}", table);

		Ok(())
	}
}

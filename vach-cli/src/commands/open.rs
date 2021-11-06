use std::fs::{create_dir, File};
use std::io::{Read, Seek};
use std::path::PathBuf;
use std::time::Instant;
use crate::config::Config;
use vach::prelude::*;
use tabled::{Style, Table, Tabled};
use anyhow::Result;
use log::{info, error};
use indicatif::{ProgressBar, ProgressStyle};

pub fn handle_open_command(
	config: &Config, archive_path: PathBuf, save_path: Option<PathBuf>,
) -> Result<()> {
	let archive_handle = File::open(archive_path)?;
	let mut header_config = HeaderConfig::default();
	header_config.public_key = config.public_key;
	let mut archive = Archive::with_config(archive_handle, &header_config)?;

	match save_path {
		None => list_archive_files(&archive),
		Some(path) => match extract_archive(&mut archive, path) {
			Ok(_) => (),
			Err(e) => error!("An error occurred while extracting the archive: {}", e),
		},
	}

	Ok(())
}

#[derive(Tabled)]
struct FileTableEntry<'a> {
	id: &'a str,
	size: String,
	compressed: &'static str,
	signed: &'static str,
	encrypted: &'static str,
}

fn list_archive_files(archive: &Archive<impl Seek + Read>) {
	let table_entries: Vec<FileTableEntry> = archive
		.entries()
		.iter()
		.map(|(id, entry)| FileTableEntry {
			id,
			size: byte_size_to_string(entry.offset),
			compressed: bool_to_string(entry.flags.contains(Flags::COMPRESSED_FLAG)),
			signed: bool_to_string(entry.flags.contains(Flags::SIGNED_FLAG)),
			encrypted: bool_to_string(entry.flags.contains(Flags::ENCRYPTED_FLAG)),
		})
		.collect();

	let table = Table::new(table_entries).with(Style::psql());
	println!("{}", table.to_string());
}

fn extract_archive(archive: &mut Archive<impl Read + Seek>, save_folder: PathBuf) -> Result<()> {
	let start = Instant::now();
	let ids: Vec<String> = archive.entries().iter().map(|(id, _)| id.clone()).collect();
	let id_len = ids.len();
	let pbar = ProgressBar::new(ids.len() as u64);
	pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

	for id in ids {
		pbar.set_message(id.to_owned());
		let mut save_path = save_folder.clone();
		save_path.push(&id);
		pbar.println(format!(
			"Extracting {} to {}",
			id,
			save_path.to_string_lossy()
		));

		for ancestor in save_path.ancestors().skip(1) {
			if ancestor.exists() {
				break;
			} else {
				pbar.println(format!("Creating folder {}", ancestor.to_string_lossy()));
				create_dir(ancestor)?;
			}
		}

		let mut file = File::create(save_path)?;
		archive.fetch_write(id.as_str(), &mut file)?;
		pbar.inc(1);
	}

	pbar.finish_and_clear();
	info!(
		"Extracted {} files in {}s",
		id_len,
		start.elapsed().as_secs_f64()
	);

	Ok(())
}

fn bool_to_string(value: bool) -> &'static str {
	match value {
		true => "YES",
		false => "NO",
	}
}

/// https://simple.wikipedia.org/wiki/Kibibyte
const KIBIBYTE: u64 = 2_u64.pow(10);
/// https://simple.wikipedia.org/wiki/Mebibyte
const MEBIBYTE: u64 = 2_u64.pow(20);
/// https://simple.wikipedia.org/wiki/Gibibyte
const GIBIBYTE: u64 = 2_u64.pow(30);
/// https://simple.wikipedia.org/wiki/Tebibyte
const TEBIBYTE: u64 = 2_u64.pow(40);

fn byte_size_to_string(size: u64) -> String {
	if size < KIBIBYTE {
		return format!("{} B", size);
	}

	if size >= KIBIBYTE && size < MEBIBYTE {
		return format!("{:.2} KiB", size as f64 / KIBIBYTE as f64);
	}

	if size >= MEBIBYTE && size < GIBIBYTE {
		return format!("{:.2} MiB", size as f64 / MEBIBYTE as f64);
	}

	if size >= GIBIBYTE && size < TEBIBYTE {
		return format!("{:.2} GiB", size as f64 / GIBIBYTE as f64);
	}

	format!("{} TiB", size as f64 / TEBIBYTE as f64)
}

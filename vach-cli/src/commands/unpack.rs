use std::fs::{create_dir, File};
use std::str::FromStr;
use std::{convert::TryInto};
use std::io::{Read, Seek};
use std::path::PathBuf;
use std::time::Instant;

use vach::prelude::*;
use anyhow::{Result, bail};
use log::info;
use indicatif::{ProgressBar, ProgressStyle};

use super::CommandTrait;
use crate::keys::key_names;

/// This command extracts an archive into the specified output folder
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> Result<()> {
		let input_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => bail!("Please provide an input path using the -i or --input key"),
		};

		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => PathBuf::from_str(path)?,
			None => PathBuf::from_str("./")?,
		};

		if output_path.is_file() {
			bail!("Please provide a directory|folder path as the value of -o | --output")
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		let public_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = match File::open(path) {
					Ok(it) => it,
					Err(err) => bail!("IOError: {} @ {}", err, path),
				};

				Some(vach::utils::read_keypair(file)?.public)
			}
			None => match args.value_of(key_names::PUBLIC_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(vach::utils::read_public_key(file)?)
				}
				None => None,
			},
		};

		let input_file = File::open(input_path)?;
		let header_config = HeaderConfig::new(magic, public_key);

		let mut archive = match Archive::with_config(input_file, &header_config) {
			 Ok(archive) => archive,
			 Err(err) => match err {
				  InternalError::NoKeypairError(_) => bail!("Please provide a public key or a keypair for use in decryption or signature verification"),
				  InternalError::ValidationError(err) => bail!("Unable to validate the archive: {}", err),
				  err => bail!("Encountered an error: {}", err.to_string())
			 },
		};

		extract_archive(&mut archive, output_path)
	}

	fn version(&self) -> &'static str {
		"0.0.1"
	}
}

fn extract_archive<T: Read + Seek>(archive: &mut Archive<T>, save_folder: PathBuf) -> Result<()> {
	// For measuring the time difference
	let time = Instant::now();

	let total_size = archive
		.entries()
		.iter()
		.map(|(_, entry)| entry.offset)
		.reduce(|a, b| a + b)
		.unwrap_or(0);

	let pbar = ProgressBar::new(total_size);
	// NOTE: More styling is to come
	pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

	// Some unsafe code to keep living dangerous
	let archive_pointer = archive as *mut Archive<T>;

	for (id, entry) in archive.entries() {
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

		// Let us dabble in a little unsafe
		unsafe {
			(*archive_pointer).fetch_write(id.as_str(), &mut file)?;
		}

		pbar.inc(entry.offset);
	}

	// Finished extracting
	pbar.finish_and_clear();
	info!(
		"Extracted {} files in {}s",
		archive.entries().len(),
		time.elapsed().as_secs_f64()
	);

	Ok(())
}

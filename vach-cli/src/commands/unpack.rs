use std::fs::{self, File};
use std::str::FromStr;
use std::{convert::TryInto};
use std::io::{Read, Seek};
use std::path::PathBuf;
use std::time::Instant;

use vach::prelude::{HeaderConfig, Archive, InternalError};
use vach::utils;
use indicatif::{ProgressBar, ProgressStyle};

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.0.1";

/// This command extracts an archive into the specified output folder
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		let input_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an input path using the -i or --input key"),
		};

		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => PathBuf::from_str(path)?,
			None => PathBuf::from_str("")?,
		};

		if output_path.is_file() {
			anyhow::bail!("Please provide a directory|folder path as the value of -o | --output")
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		// Attempting to extract a public key from a -p or -k input
		let public_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = match File::open(path) {
					Ok(it) => it,
					Err(err) => anyhow::bail!("IOError: {} @ {}", err, path),
				};

				Some(utils::read_keypair(file)?.public)
			}
			None => match args.value_of(key_names::PUBLIC_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(utils::read_public_key(file)?)
				}
				None => None,
			},
		};

		// Whether to truncate the original archive after extraction
		let truncate = args.is_present(key_names::TRUNCATE);

		let input_file = match File::open(input_path) {
			Ok(it) => it,
			Err(err) => anyhow::bail!("IOError: {} @ {}", err, input_path),
		};

		// Generate HeaderConfig using given magic and public key
		let header_config = HeaderConfig::new(magic, public_key);

		// Parse then extract archive
		let mut archive = match Archive::with_config(input_file, &header_config) {
			 Ok(archive) => archive,
			 Err(err) => match err {
				  InternalError::NoKeypairError(_) => anyhow::bail!("Please provide a public key or a keypair for use in decryption or signature verification"),
				  InternalError::ValidationError(err) => anyhow::bail!("Unable to validate the archive: {}", err),
				  err => anyhow::bail!("Encountered an error: {}", err.to_string())
			 },
		};

		extract_archive(&mut archive, output_path)?;

		// Delete original archive
		if truncate {
			println!("Truncating original archive @ {}", &input_path);
			std::fs::remove_file(input_path)?;
		};

		Ok(())
	}
}

fn extract_archive<T: Read + Seek>(
	archive: &mut Archive<T>, save_folder: PathBuf,
) -> anyhow::Result<()> {
	// For measuring the time difference
	let time = Instant::now();
	fs::create_dir_all(&save_folder)?;

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

		if let Some(parent_dir) = save_path.ancestors().nth(1) {
			fs::create_dir_all(parent_dir)?;
		};

		pbar.println(format!(
			"Extracting {} to {}",
			id,
			save_path.to_string_lossy()
		));

		let mut file = File::create(save_path)?;

		// Let us dabble in a little unsafe
		unsafe {
			(*archive_pointer).fetch_write(id.as_str(), &mut file)?;
		}

		pbar.inc(entry.offset);
	}

	// Finished extracting
	pbar.finish_and_clear();
	log::info!(
		"Extracted {} files in {}s",
		archive.entries().len(),
		time.elapsed().as_secs_f64()
	);

	Ok(())
}

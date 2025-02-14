use std::{
	fs::{self, File},
	io::{Cursor, Read, Seek, Write},
	path::PathBuf,
	str::FromStr,
	thread,
	time::Instant,
};

use vach::{crypto_utils, prelude::*};
use indicatif::{ProgressBar, ProgressStyle};

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.1.1";

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
			None => Default::default(),
		};

		if output_path.is_file() {
			anyhow::bail!("Please provide a directory|folder path as the value of -o | --output")
		};

		// Attempting to extract a public key from a -p or -k input
		let verifying_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = match File::open(path) {
					Ok(it) => it,
					Err(err) => anyhow::bail!("IOError: {} @ {}", err, path),
				};

				Some(crypto_utils::read_keypair(file)?.verifying_key())
			},
			None => match args.value_of(key_names::PUBLIC_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_verifying_key(file)?)
				},
				None => None,
			},
		};

		// load file into memory map, and init cursor
		let file = File::open(input_path)?;
		let mmap = unsafe { memmap2::Mmap::map(&file).expect("Unable to map file to memory") };
		#[cfg(unix)]
		mmap.advise(memmap2::Advice::Random);
		let cursor = Cursor::new(mmap.as_ref());

		// load archive, with optional key
		let archive = match verifying_key.as_ref() {
			Some(vk) => Archive::with_key(cursor, vk),
			None => Archive::new(cursor),
		};

		// Parse then extract archive
		let archive = match archive {
			Ok(archive) => archive,
			Err(err) => match err {
				InternalError::NoKeypairError => anyhow::bail!(
					"Please provide a public key or a keypair for use in decryption or signature verification"
				),
				InternalError::MalformedArchiveSource(_) => anyhow::bail!("Unable to validate the archive: {}", err),
				err => anyhow::bail!("Encountered an error: {}", err.to_string()),
			},
		};

		let num_threads = args
			.value_of(key_names::JOBS)
			.map(|v| v.parse::<usize>().ok())
			.flatten()
			.filter(|s| *s > 0)
			.unwrap_or(num_cpus::get());

		extract_archive(&archive, num_threads, output_path)?;
		Ok(())
	}
}

fn extract_archive<T: Read + Seek + Send + Sync>(
	archive: &Archive<T>, jobs: usize, target_folder: PathBuf,
) -> anyhow::Result<()> {
	// For measuring the time difference
	let time = Instant::now();
	fs::create_dir_all(&target_folder)?;

	let total_size = archive
		.entries()
		.iter()
		.map(|(_, entry)| entry.offset)
		.reduce(|a, b| a + b)
		.unwrap_or(0);

	let pbar = ProgressBar::new(total_size);

	pbar.set_style(
		ProgressStyle::default_bar()
			.template(super::PROGRESS_BAR_STYLE)?
			.progress_chars("█░-")
			.tick_chars("⢀ ⡀ ⠄ ⢂ ⡂ ⠅ ⢃ ⡃ ⠍ ⢋ ⡋ ⠍⠁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⢈⠩⡀⢙⠄⡙⢂⠩⡂⢘⠅⡘⢃⠨⡃⢐⠍⡐⢋⠠⡋⢀⠍⡁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⠈⠩ ⢙ ⡙ ⠩ ⢘ ⡘ ⠨ ⢐ ⡐ ⠠ ⢀ ⡀"),
	);

	// Extract all entries in parallel
	let entries = archive.entries().iter().map(|(_, entry)| entry).collect::<Vec<_>>();
	let chunk_size = (archive.entries().len() / jobs).max(archive.entries().len());

	thread::scope(|s| -> anyhow::Result<()> {
		for chunk in entries.chunks(chunk_size) {
			let pbar = pbar.clone();
			let target_folder = target_folder.clone();

			s.spawn(move || -> anyhow::Result<()> {
				for entry in chunk {
					let id = entry.id.as_ref();

					// Set's the Progress Bar message
					pbar.set_message(id.to_string());

					// Process filesystem
					let mut save_path = target_folder.clone();
					save_path.push(id);

					if let Some(parent_dir) = save_path.ancestors().nth(1) {
						fs::create_dir_all(parent_dir)?;
					};

					// Write to file and update process queue
					let mut file = File::create(save_path)?;
					let resource = archive.fetch(id)?;
					file.write_all(&resource.data)?;

					// Increment Progress Bar
					pbar.inc(entry.offset);
				}

				Ok(())
			});
		}

		Ok(())
	})?;

	// Finished extracting
	pbar.finish();
	println!(
		"Extracted {} files in {}s",
		archive.entries().len(),
		time.elapsed().as_secs_f64()
	);

	Ok(())
}

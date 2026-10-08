use std::{
	fs::{self, File},
	io::{Cursor, Read, Seek, Write},
	mem,
	path::PathBuf,
	thread,
	time::Instant,
};

use indicatif::{ProgressBar, ProgressStyle};
use vach::{crypto_utils, prelude::*};

use super::CommandTrait;
use crate::cli;

pub struct Subcommand;

impl CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.2"
	}

	fn evaluate(
		&self,
		cli: cli::CommandLine,
	) -> anyhow::Result<()> {
		let cli::Command::Unpack {
			input,
			output,
			keypair,
			public_key,
			jobs,
			chunks_size,
		} = cli.command
		else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let output = match output {
			Some(path) => {
				if path.is_file() {
					anyhow::bail!("Please provide a directory|folder path as the value of -o | --output")
				};

				path
			},
			None => PathBuf::from(input.file_stem().unwrap()),
		};

		// Attempting to extract a public key from a -p or -k input
		let verifying_key = match keypair {
			Some(path) => {
				let file = File::open(&path)?;
				Some(crypto_utils::read_keypair(file)?.verifying_key())
			},
			None => match public_key {
				Some(path) => {
					let file = File::open(&path)?;
					Some(crypto_utils::read_verifying_key(file)?)
				},
				None => None,
			},
		};

		// memory map file, init cursor
		let file = File::open(input)?;
		let mmap = unsafe { memmap2::Mmap::map(&file).expect("Unable to map file to memory") };
		#[cfg(unix)]
		mmap.advise(memmap2::Advice::Random).unwrap();
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
				InternalError::NoKeypairError => anyhow::bail!("Please provide a public key or a keypair for use in decryption or signature verification"),
				InternalError::MalformedArchiveSource(_) => anyhow::bail!("Unable to validate the archive: {}", err),
				err => anyhow::bail!("Encountered an error: {}", err),
			},
		};

		if !archive.entries().is_empty() {
			extract_archive(&archive, output, jobs, chunks_size)?;
		}

		Ok(())
	}
}

fn extract_archive<T: Read + Seek + Send + Sync>(
	archive: &Archive<T>,
	target_folder: PathBuf,
	jobs: usize,
	chunk_size: Option<usize>,
) -> anyhow::Result<()> {
	// For measuring the time difference
	let time = Instant::now();
	fs::create_dir_all(&target_folder)?;

	let total_size = archive.entries().values().map(|entry| entry.offset).sum::<u64>();
	let pbar = ProgressBar::new(total_size);

	pbar.set_style(
		ProgressStyle::default_bar()
			.template(super::PROGRESS_BAR_STYLE)?
			.progress_chars("█░-")
			.tick_chars("⢀ ⡀ ⠄ ⢂ ⡂ ⠅ ⢃ ⡃ ⠍ ⢋ ⡋ ⠍⠁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⢈⠩⡀⢙⠄⡙⢂⠩⡂⢘⠅⡘⢃⠨⡃⢐⠍⡐⢋⠠⡋⢀⠍⡁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⠈⠩ ⢙ ⡙ ⠩ ⢘ ⡘ ⠨ ⢐ ⡐ ⠠ ⢀ ⡀"),
	);

	// Extract all entries in parallel
	let entries = archive.entries().values().collect::<Vec<_>>();
	let chunk_size = chunk_size.unwrap_or(if entries.len() < jobs { 8 } else { entries.len() / jobs });

	thread::scope(|s| -> anyhow::Result<()> {
		let mut handles = Vec::new();

		for chunk in entries.chunks(chunk_size) {
			let pbar = pbar.clone();
			let target_folder = target_folder.clone();

			let handle = s.spawn(move || -> anyhow::Result<()> {
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

			handles.push(handle);
		}

		// wait for all threads to complete successfully
		let mut pending = Vec::with_capacity(handles.len());

		loop {
			if handles.is_empty() {
				break;
			}

			for handle in handles.drain(..) {
				if handle.is_finished() {
					handle.join().unwrap()?;
				} else {
					pending.push(handle);
				}
			}

			mem::swap(&mut pending, &mut handles);
		}

		Ok(())
	})?;

	// Finished extracting
	pbar.finish();
	println!("Extracted {} files in {}s", archive.entries().len(), time.elapsed().as_secs_f64());

	Ok(())
}

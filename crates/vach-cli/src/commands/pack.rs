use std::{
	collections::HashSet,
	fs::File,
	io::{self, Read, Write},
	path::PathBuf,
};

use indicatif::{ProgressBar, ProgressStyle};
use tempfile::NamedTempFile;
use vach::{crypto_utils, prelude::*};
use walkdir;

use super::CommandTrait;
use crate::cli;

struct FileAutoDropper(PathBuf, Option<File>);

impl FileAutoDropper {
	fn new(path: PathBuf) -> Option<Leaf<FileAutoDropper>> {
		path.exists().then(|| {
			let id = path.to_string_lossy().to_string();
			let handle = FileAutoDropper(path, None);

			Leaf::new(handle, id)
		})
	}
}

impl Read for FileAutoDropper {
	fn read(
		&mut self,
		buf: &mut [u8],
	) -> io::Result<usize> {
		// open file if None
		let file = match self.1.as_mut() {
			Some(file) => file,
			None => {
				let file = File::open(&self.0)?;
				self.1.insert(file)
			},
		};

		let result = file.read(buf);
		if let Ok(0) = result {
			// Once the file is done reading, we drop the file handle
			self.1.take();
		};

		result
	}
}

/// This command verifies the validity and integrity of an archive
pub struct Subcommand;

impl CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.6"
	}

	fn evaluate(
		&self,
		args: cli::CommandLine,
	) -> anyhow::Result<()> {
		// 1: Assemble Input Settings
		let cli::Command::Pack {
			output,
			inputs,
			directories,
			recursive_directories,
			exclude,
			compress_mode,
			compression_algorithm,
			sign,
			flags,
			jobs,
			encrypt,
			keypair,
			private_key,
		} = args.command
		else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let flags = flags.map(Flags::from_bits).unwrap_or_default();

		let compress_mode = compress_mode
			.map(|c| match c {
				cli::CompressModeSetting::Always => CompressMode::Always,
				cli::CompressModeSetting::Never => CompressMode::Never,
				cli::CompressModeSetting::Auto => CompressMode::Detect,
			})
			.unwrap_or_default();

		let compression_algo = compression_algorithm
			.map(|a| match a {
				cli::CompressionAlgorithmSetting::LZ4 => CompressionAlgorithm::LZ4,
				cli::CompressionAlgorithmSetting::Snappy => CompressionAlgorithm::Snappy,
				cli::CompressionAlgorithmSetting::Brotli => CompressionAlgorithm::Brotli(9),
			})
			.unwrap_or_default();

		// get signing_key
		let mut signing_key = match private_key {
			Some(path) => {
				let file = File::open(path)?;
				Some(crypto_utils::read_secret_key(file)?)
			},
			None => match keypair {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_keypair(file)?)
				},
				None => None,
			},
		};

		// If encrypt is true, and no keypair was found: Generate and write a new keypair to a file
		if (encrypt || sign) && signing_key.is_none() {
			let generated = crypto_utils::gen_keypair();

			let mut file = File::create("keypair.kp")?;
			file.write_all(&generated.to_keypair_bytes())?;
			println!("Generated a new keypair @ keypair.kp");

			signing_key = Some(generated);
		}

		// combine leaf input-template
		let template = Leaf::<&'static [u8]>::default().compress(compress_mode).compression_algo(compression_algo).encrypt(encrypt).sign(sign);

		// 2: Assemble input files
		let mut leaves = vec![];

		// Extract entries to be excluded
		let excludes = match exclude {
			Some(val) => val
				.iter()
				.filter_map(|path| match path.canonicalize() {
					Ok(path) => Some(path),
					Err(err) => {
						eprintln!("Failed to canonicalize: {}. Skipping due to error: {}", path.to_string_lossy(), err);
						None
					},
				})
				.collect::<HashSet<PathBuf>>(),
			None => HashSet::new(),
		};

		// Used to filter invalid inputs and excluded inputs
		let path_filter = |path: &PathBuf| match path.canonicalize() {
			Ok(canonical) => !excludes.iter().any(|p| canonical.starts_with(p)) && canonical.is_file(),
			Err(err) => {
				eprintln!("Failed to canonicalize: {}. Skipping due to error: {}", path.to_string_lossy(), err);
				false
			},
		};

		if let Some(f) = inputs {
			let iter = f.into_iter().filter(path_filter).filter_map(FileAutoDropper::new).map(|l| l.template(&template));

			leaves.extend(iter);
		};

		// Extract directory inputs
		if let Some(val) = directories {
			let iter = val.into_iter().flat_map(|dir| {
				walkdir::WalkDir::new(dir)
					.max_depth(1)
					.into_iter()
					.map(|v| v.unwrap().into_path())
					.filter(path_filter)
					.filter_map(FileAutoDropper::new)
					.map(|l| l.template(&template))
			});

			leaves.extend(iter);
		};

		// Extract recursive directory inputs
		if let Some(val) = recursive_directories {
			let iter = val
				.into_iter()
				.flat_map(|dir| walkdir::WalkDir::new(dir).into_iter())
				.map(|v| v.unwrap().into_path())
				.filter(|f| path_filter(f))
				.filter_map(FileAutoDropper::new)
				.map(|l| l.template(&template));

			leaves.extend(iter);
		}

		// 3: Final Assembly

		// create temporary file
		let mut temporary_file = NamedTempFile::new().unwrap();

		// assemble configuration for builder
		let config = BuilderConfig { flags, signing_key, num_threads: jobs };

		// setup progress bar and callback to update it
		let progress = ProgressBar::new(leaves.len() as _);
		progress.set_style(
			ProgressStyle::default_bar()
				.template(super::PROGRESS_BAR_STYLE)?
				.progress_chars("█░-")
				.tick_chars("⢀ ⡀ ⠄ ⢂ ⡂ ⠅ ⢃ ⡃ ⠍ ⢋ ⡋ ⠍⠁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⢈⠩⡀⢙⠄⡙⢂⠩⡂⢘⠅⡘⢃⠨⡃⢐⠍⡐⢋⠠⡋⢀⠍⡁⢋⠁⡋⠁⠍⠉⠋⠉⠋⠉⠉⠙⠉⠙⠉⠩⠈⢙⠈⡙⠈⠩ ⢙ ⡙ ⠩ ⢘ ⡘ ⠨ ⢐ ⡐ ⠠ ⢀ ⡀"),
		);

		// increments progress-bar by one for each entry
		let mut callback = |entry: &RegistryEntry, _: &[u8]| {
			progress.inc(1);
			let message = entry.id.as_ref();
			progress.set_message(message.to_string());
		};

		// 4: Write
		let bytes_written = dump(&mut temporary_file, &mut leaves, Some(config), Some(&mut callback))?;
		temporary_file.persist(&output)?;

		progress.println(format!("Generated a new archive @ {}; Bytes written: {}", output.display(), bytes_written));
		progress.finish();

		Ok(())
	}
}

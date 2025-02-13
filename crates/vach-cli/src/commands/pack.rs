use std::{
	fs::File,
	io::{self, Read, Write},
	sync::Arc,
};
use std::path::PathBuf;
use std::collections::HashSet;

use tempfile::NamedTempFile;
use vach::prelude::*;
use vach::crypto_utils;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir;

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.0.5";

struct FileAutoDropper(PathBuf, Option<File>);

impl FileAutoDropper {
	fn new<'a>(path: PathBuf) -> Option<Leaf<'a>> {
		path.exists().then(|| {
			let id = Arc::from(path.to_string_lossy());
			let handle = Box::new(FileAutoDropper(path, None));

			Leaf {
				id,
				handle,
				..Default::default()
			}
		})
	}
}

impl Read for FileAutoDropper {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		// 1: Assemble Input Settings

		// get output path
		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an output path using the -o or --output key"),
		};

		// get flags
		let flags = match args.value_of(key_names::FLAGS) {
			Some(magic) => Flags::from_bits(magic.parse::<u32>()?),
			None => Flags::default(),
		};

		// get content_version
		let version: u8 = match args.value_of(key_names::VERSION) {
			Some(version) => version.parse()?,
			None => 0,
		};

		// get compress mode
		let mut compress_mode = CompressMode::default();
		if let Some(value) = args.value_of(key_names::COMPRESS_MODE) {
			compress_mode = match value.to_lowercase().as_str() {
				"always" => CompressMode::Always,
				"detect" => CompressMode::Detect,
				"never" => CompressMode::Never,
				invalid_value => {
					anyhow::bail!("{} is an invalid value for COMPRESS_MODE", invalid_value)
				},
			}
		};

		// get compression algorithm
		let mut compression_algo = CompressionAlgorithm::default();
		if let Some(value) = args.value_of(key_names::COMPRESS_ALGO) {
			compression_algo = match value.to_lowercase().as_str() {
				"lz4" => CompressionAlgorithm::LZ4,
				"brotli" => CompressionAlgorithm::Brotli(8),
				"snappy" => CompressionAlgorithm::Snappy,
				invalid_value => {
					anyhow::bail!("{} is an invalid value for COMPRESS_ALGO", invalid_value)
				},
			}
		};

		// get crypto settings
		let encrypt = args.is_present(key_names::ENCRYPT);
		let hash = args.is_present(key_names::HASH);

		// get signing_key
		let mut signing_key = match args.value_of(key_names::SECRET_KEY) {
			Some(path) => {
				let file = File::open(path)?;
				Some(crypto_utils::read_secret_key(file)?)
			},
			None => match args.value_of(key_names::SECRET_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_secret_key(file)?)
				},
				None => None,
			},
		};

		// If encrypt is true, and no keypair was found: Generate and write a new keypair to a file
		if (encrypt || hash) && signing_key.is_none() {
			let generated = crypto_utils::gen_keypair();

			let mut file = File::create("keypair.kp")?;
			file.write_all(&generated.to_keypair_bytes())?;
			println!("Generated a new keypair @ keypair.kp");

			signing_key = Some(generated);
		}

		// get jobs
		let num_threads = args
			.value_of(key_names::JOBS)
			.map(|v| v.parse::<usize>().ok())
			.flatten()
			.unwrap_or(num_cpus::get());

		// combine leaf input-template
		let template = Leaf::default()
			.compress(compress_mode)
			.compression_algo(compression_algo)
			.encrypt(encrypt)
			.sign(hash)
			.version(version);

		// 2: Assemble input files
		let mut leaves = vec![];

		// Extract entries to be excluded
		let excludes = match args.values_of(key_names::EXCLUDE) {
			Some(val) => val
				.filter_map(|f| {
					let path = PathBuf::from(f);

					match path.canonicalize() {
						Ok(path) => Some(path),
						Err(err) => {
							eprintln!(
								"Failed to evaluate: {}. Skipping due to error: {}",
								path.to_string_lossy(),
								err
							);
							None
						},
					}
				})
				.filter(|v| v.is_file())
				.collect::<HashSet<PathBuf>>(),
			None => HashSet::new(),
		};

		// Used to filter invalid inputs and excluded inputs
		let path_filter = |path: &PathBuf| match path.canonicalize() {
			Ok(canonical) => !excludes.contains(&canonical) && canonical.is_file(),
			Err(err) => {
				eprintln!(
					"Failed to canonicalize: {}. Skipping due to error: {}",
					path.to_string_lossy(),
					err
				);
				false
			},
		};

		if let Some(val) = args.values_of(key_names::INPUT) {
			let iter = val
				.map(PathBuf::from)
				.filter(|f| path_filter(f))
				.filter_map(FileAutoDropper::new)
				.map(|l| l.template(&template));

			leaves.extend(iter);
		};

		// Extract directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT) {
			let iter = val
				.map(|dir| {
					walkdir::WalkDir::new(dir)
						.max_depth(1)
						.into_iter()
						.map(|v| v.unwrap().into_path())
						.filter(|f| path_filter(f))
						.filter_map(FileAutoDropper::new)
						.map(|l| l.template(&template))
				})
				.flatten();

			leaves.extend(iter);
		};

		// Extract recursive directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT_REC) {
			let iter = val
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
		let config = BuilderConfig {
			flags,
			signing_key,
			num_threads: num_threads.try_into().expect("Number of threads cannot be zero"),
		};

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
		let bytes_written = dump(&mut temporary_file, &mut leaves, &config, Some(&mut callback))?;
		temporary_file.persist(output_path)?;

		progress.println(format!(
			"Generated a new archive @ {}; Bytes written: {}",
			output_path, bytes_written
		));

		progress.finish();

		Ok(())
	}
}

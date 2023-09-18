use std::fs::OpenOptions;
use std::{
	fs::File,
	io::{Write, Read, self},
};
use std::path::PathBuf;
use std::collections::HashSet;

use vach::prelude::*;
use vach::crypto_utils;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir;

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.0.5";

struct FileWrapper(PathBuf, Option<File>);

impl Read for FileWrapper {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		// If no file is defined open it
		let file = match self.1.as_mut() {
			Some(file) => file,
			None => {
				self.1 = Some(File::open(&self.0)?);
				self.1.as_mut().unwrap()
			},
		};
		let result = file.read(buf);

		// Intercepts a file once it's finished reading to drop it, thus avoiding OS filesystem limitations easily
		// Meaning we can safely drop the `fs::File` stored in this file wrapper
		if let Ok(0) = result {
			self.1.take();
		};

		result
	}
}

/// This command verifies the validity and integrity of an archive
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		// The archives magic
		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		// Flags that go into the header section of the archive
		let flags = match args.value_of(key_names::FLAGS) {
			Some(magic) => Flags::from_bits(magic.parse::<u32>()?),
			None => Flags::default(),
		};

		// Extract the compress mode
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

		// Extract the compress mode
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

		// Extract entries to be excluded
		let excludes = match args.values_of(key_names::EXCLUDE) {
			Some(val) => val
				.filter_map(|f| {
					let path = PathBuf::from(f);

					match path.canonicalize() {
						Ok(path) => Some(path),
						Err(err) => {
							log::warn!(
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

		// Extract the inputs
		let mut inputs: Vec<FileWrapper> = vec![];

		// Used to filter invalid inputs and excluded inputs
		let path_filter = |path: &PathBuf| match path.canonicalize() {
			Ok(canonical) => !excludes.contains(&canonical) && canonical.is_file(),
			Err(err) => {
				log::warn!(
					"Failed to evaluate: {}. Skipping due to error: {}",
					path.to_string_lossy(),
					err
				);
				false
			},
		};

		if let Some(val) = args.values_of(key_names::INPUT) {
			val.map(PathBuf::from)
				.filter(|f| path_filter(f))
				.for_each(|p| inputs.push(FileWrapper(p, None)));
		};

		// Extract directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT) {
			val.for_each(|dir| {
				walkdir::WalkDir::new(dir)
					.max_depth(1)
					.into_iter()
					.map(|v| v.unwrap().into_path())
					.filter(|f| path_filter(f))
					.for_each(|p| inputs.push(FileWrapper(p, None)))
			});
		};

		// Extract recursive directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT_REC) {
			val.flat_map(|dir| walkdir::WalkDir::new(dir).into_iter())
				.map(|v| v.unwrap().into_path())
				.filter(|f| path_filter(f))
				.for_each(|p| inputs.push(FileWrapper(p, None)));
		}

		// Read valueless flags
		let encrypt = args.is_present(key_names::ENCRYPT);
		let hash = args.is_present(key_names::HASH);
		let truncate = args.is_present(key_names::TRUNCATE);

		// Extract the version information to be set
		let version = match args.value_of(key_names::VERSION) {
			Some(version) => version.parse::<u8>()?,
			None => 0,
		};

		// Attempting to extract a secret key
		let secret_key = match args.value_of(key_names::KEYPAIR) {
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

		// Generate a keypair from the secret key
		let mut kp = secret_key.map(|sk| SigningKey::from(sk));

		// If encrypt is true, and no keypair was found: Generate and write a new keypair to a file
		if (encrypt || hash) && kp.is_none() {
			let generated = crypto_utils::gen_keypair();

			let mut file = File::create("keypair.kp")?;
			file.write_all(&generated.to_bytes())?;
			log::info!("Generated a new keypair @ keypair.kp");

			kp = Some(generated);
		}

		let pbar = ProgressBar::new(inputs.len() as u64 + 5 + if truncate { 3 } else { 0 });
		pbar.set_style(
			ProgressStyle::default_bar()
				.template(super::PROGRESS_BAR_STYLE)
				.progress_chars("█░-")
				.tick_strings(&[
					"⢀ ", "⡀ ", "⠄ ", "⢂ ", "⡂ ", "⠅ ", "⢃ ", "⡃ ", "⠍ ", "⢋ ", "⡋ ", "⠍⠁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉",
					"⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⢈⠩", "⡀⢙", "⠄⡙", "⢂⠩", "⡂⢘", "⠅⡘", "⢃⠨", "⡃⢐", "⠍⡐", "⢋⠠",
					"⡋⢀", "⠍⡁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⠈⠩", " ⢙", " ⡙", " ⠩",
					" ⢘", " ⡘", " ⠨", " ⢐", " ⡐", " ⠠", " ⢀", " ⡀",
				]),
		);

		// Since it wraps it's internal state in an arc, we can safely clone and send across threads
		let callback = |leaf: &Leaf, _: &RegistryEntry| {
			pbar.inc(1);
			pbar.set_message(leaf.id.to_string())
		};

		// Build a builder-config using the above extracted data
		let builder_config = BuilderConfig {
			flags,
			magic,
			keypair: kp,
			progress_callback: Some(&callback),
		};

		// Construct the builder
		let mut builder = Builder::new().template(
			Leaf::default()
				.compress(compress_mode)
				.compression_algo(compression_algo)
				.encrypt(encrypt)
				.sign(hash)
				.version(version),
		);

		// Prepare output file
		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an output path using the -o or --output key"),
		};

		let output_file = match OpenOptions::new().write(true).create_new(true).open(output_path) {
			Ok(file) => file,
			Err(err) => anyhow::bail!("Unable to generate archive @ {}: [IO::Error] {}", output_path, err),
		};

		// Process the files
		for wrapper in &mut inputs {
			if !wrapper.0.exists() {
				pbar.println(format!("Skipping {}, does not exist!", wrapper.0.to_string_lossy()));

				pbar.inc(1);

				continue;
			}

			let id = wrapper
				.0
				.to_string_lossy()
				.trim_start_matches("./")
				.trim_start_matches(".\\")
				.to_string();
			log::info!("Preparing {} for packaging", id);
			builder.add(wrapper, &id)?;
		}

		// Inform of success in input queue
		pbar.inc(2);

		builder.dump(output_file, &builder_config)?;
		pbar.println(format!("Generated a new archive @ {}", output_path));
		drop(builder);

		// Truncate original files
		if truncate {
			for wrapper in inputs {
				std::fs::remove_file(&wrapper.0)?;
				pbar.finish();
				pbar.println(format!("Truncated original file @ {}", wrapper.0.to_string_lossy()));
			}

			pbar.inc(3);
		};

		pbar.inc(3);

		Ok(())
	}
}

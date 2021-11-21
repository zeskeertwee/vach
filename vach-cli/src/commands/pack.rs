use std::{fs::File, io::Write};
use std::path::PathBuf;
use std::convert::TryInto;
use std::collections::HashSet;

use anyhow::{Result, bail};
use vach::{self, prelude::*};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir;

use super::CommandTrait;
use crate::keys::key_names;

/// This command verifies the validity and integrity of an archive
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> Result<()> {
		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => path,
			None => bail!("Please provide an output path using the -o or --output key"),
		};

		let output_file = File::create(&output_path)?;

		// The archives magic
		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		// Flags that go into the header section of the archive
		let flags = match args.value_of(key_names::FLAGS) {
			Some(magic) => Flags::from_bits(magic.parse::<u16>()?),
			None => Flags::default(),
		};

		// Extract the compress mode
		let mut compress_mode = CompressMode::default();
		if let Some(value) = args.value_of(key_names::COMPRESS_MODE) {
			compress_mode = match value.to_lowercase().as_str() {
				"always" => CompressMode::Always,
				"detect" => CompressMode::Detect,
				"never" => CompressMode::Never,
				invalid_value => bail!("{} is an invalid value for COMPRESS_MODE", invalid_value),
			}
		};

		// Extract entries to be excluded
		let excludes = match args.values_of(key_names::EXCLUDE) {
			Some(val) => val
				.map(PathBuf::from)
				.filter(|v| v.is_file())
				.collect::<HashSet<PathBuf>>(),
			None => HashSet::new(),
		};

		// Extract the inputs
		let mut inputs: Vec<PathBuf> = vec![];

		if let Some(val) = args.values_of(key_names::INPUT) {
			val.map(PathBuf::from)
				.filter(|v| v.is_file() || excludes.contains(v))
				.for_each(|p| inputs.push(p));
		};

		// Extract directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT) {
			val.for_each(|dir| {
				walkdir::WalkDir::new(dir)
					.max_depth(1)
					.into_iter()
					.map(|v| v.unwrap().into_path())
					.filter(|f| !excludes.contains(f) && f.is_file())
					.for_each(|p| inputs.push(p))
			});
		};

		// Extract recursive directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT_REC) {
			val.map(|dir| walkdir::WalkDir::new(dir).into_iter())
				.flatten()
				.map(|v| v.unwrap().into_path())
				.filter(|f| !excludes.contains(f) && f.is_file())
				.for_each(|p| inputs.push(p));
		}

		// Extract valueless flags
		let encrypt = args.is_present(key_names::ENCRYPT);
		let hash = args.is_present(key_names::HASH);

		// Extract the version information to be set
		let version = match args.value_of(key_names::VERSION) {
			Some(version) => version.parse::<u8>()?,
			None => 0,
		};

		// Attempting to extract a secret key
		let secret_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = File::open(path)?;
				Some(vach::utils::read_keypair(file)?.secret)
			}
			None => match args.value_of(key_names::SECRET_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(vach::utils::read_secret_key(file)?)
				}
				None => None,
			},
		};

		// Generate a keypair from the secret key
		let mut kp = match secret_key {
			Some(sk) => {
				let pk = PublicKey::from(&sk);
				Some(Keypair {
					secret: sk,
					public: pk,
				})
			}
			None => None,
		};

		// If encrypt is true, and no keypair was found: Generate and write a new keypair to a file
		if (encrypt || hash) && kp.is_none() {
			let generated = vach::utils::gen_keypair();

			let mut file = File::create("keypair.kp")?;
			file.write_all(&generated.to_bytes())?;
			println!("Generated a new keypair @ keypair.kp");

			kp = Some(generated);
		}

		let pbar = ProgressBar::new(inputs.len() as u64 + 5);
		pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

		// Build a builder-config using the above extracted data
		let builder_config = BuilderConfig {
			flags,
			magic,
			keypair: kp,
		};

		// Construct the builder
		let mut builder = Builder::new().template(
			Leaf::default()
				.compress(compress_mode)
				.encrypt(encrypt)
				.sign(hash)
				.version(version),
		);

		// Process the files
		for entry in inputs {
			if !entry.exists() {
				pbar.println(format!(
					"Skipping {}, does not exist!",
					entry.to_string_lossy()
				));
				pbar.inc(1);
				continue;
			}

			let id = match entry.to_str() {
				Some(name) => name.to_string(),
				None => "".to_string(),
			};

			pbar.println(format!("Packaging {}", id));

			match File::open(&entry) {
				Ok(file) => {
					if let Err(e) = builder.add(file, &id) {
						pbar.println(format!(
							"Couldn't add file: {}. {}",
							entry.to_string_lossy(),
							e
						))
					}
				}
				Err(e) => pbar.println(format!(
					"Couldn't open file {}: {}",
					entry.to_string_lossy(),
					e
				)),
			}

			pbar.inc(1);
		}

		// Inform of success in input queue
		pbar.inc(2);

		// Dumping processed data
		pbar.println(format!("Generated a new archive & {}", output_path));
		builder.dump(output_file, &builder_config)?;
		pbar.inc(3);

		// SUCCESS
		pbar.finish_and_clear();

		Ok(())
	}

	fn version(&self) -> &'static str {
		"0.0.1"
	}
}

// OLD implementation
/*
pub fn handle_package_command(
	config: &mut Config, files: Vec<PathBuf>, save_path: PathBuf, compress_mode: CompressMode,
	encrypt: bool,
) -> Result<()> {
	// fail early
	let mut save_file = File::create(&save_path)?;
*/

// 	let mut builder_config = BuilderConfig::default();

// 	// .take() is needed here (and thus a &mut reference is needed) because SecretKey doesn't implement Clone
// 	let (public_key, secret_key) = (config.public_key.take(), config.secret_key.take());
// 	match (public_key, secret_key) {
// 		(Some(pkey), Some(skey)) => {
// 			builder_config.keypair = Some(Keypair {
// 				public: pkey,
// 				secret: skey,
// 			});
// 		}
// 		_ => (),
// 	}

// 	let pbar = ProgressBar::new(files.len() as u64 + 1);
// 	pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

// 	let mut builder =
// 		Builder::new().template(Leaf::default().compress(compress_mode).encrypt(encrypt));

// 	for entry in files {
// 		if !entry.exists() {
// 			pbar.println(format!(
// 				"Skipping {}, does not exist!",
// 				entry.to_string_lossy()
// 			));
// 			pbar.inc(1);
// 			continue;
// 		}

// 		if entry.is_file() {
// 			let id = match entry.file_name() {
// 				Some(name) => name.to_string_lossy().to_string(),
// 				None => "".to_string(),
// 			};
// 			pbar.println(format!("Packaging {}", id));

// 			match File::open(&entry) {
// 				Ok(file) => match builder.add(file, &id) {
// 					Ok(_) => (),
// 					Err(e) => pbar.println(format!(
// 						"Couldn't add file {}: {}",
// 						entry.to_string_lossy(),
// 						e
// 					)),
// 				},
// 				Err(e) => pbar.println(format!(
// 					"Couldn't add file {}: {}",
// 					entry.to_string_lossy(),
// 					e
// 				)),
// 			}
// 		} else if entry.is_dir() {
// 			pbar.println(format!("Packaging {} (directory)", entry.to_string_lossy()));
// 			match builder.add_dir(&entry.to_string_lossy(), None) {
// 				Ok(_) => (),
// 				Err(e) => pbar.println(format!(
// 					"Couldn't add folder {}: {}",
// 					entry.to_string_lossy(),
// 					e
// 				)),
// 			}
// 		}

// 		pbar.inc(1);
// 	}

// 	pbar.println(format!("Writing to {}", save_path.to_string_lossy()));
// 	builder.dump(&mut save_file, &builder_config)?;
// 	pbar.inc(1);
// 	pbar.finish_and_clear();

// 	Ok(())
// }

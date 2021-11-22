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

enum InputSource {
	PathBuf(PathBuf),
	VachResource(Resource, String),
}

impl From<PathBuf> for InputSource {
	fn from(pb: PathBuf) -> InputSource {
		InputSource::PathBuf(pb)
	}
}

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
		let mut inputs: Vec<InputSource> = vec![];

		if let Some(val) = args.values_of(key_names::INPUT) {
			val.map(PathBuf::from)
				.filter(|v| v.is_file() || excludes.contains(v))
				.for_each(|p| inputs.push(InputSource::PathBuf(p)));
		};

		// Extract directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT) {
			val.for_each(|dir| {
				walkdir::WalkDir::new(dir)
					.max_depth(1)
					.into_iter()
					.map(|v| v.unwrap().into_path())
					.filter(|f| !excludes.contains(f) && f.is_file())
					.for_each(|p| inputs.push(InputSource::PathBuf(p)))
			});
		};

		// Extract recursive directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT_REC) {
			val.map(|dir| walkdir::WalkDir::new(dir).into_iter())
				.flatten()
				.map(|v| v.unwrap().into_path())
				.filter(|f| !excludes.contains(f) && f.is_file())
				.for_each(|p| inputs.push(InputSource::PathBuf(p)));
		}

		// Extract inputs from the archive
		let mut archive = None;
		let mut archive_path = "";
		if let Some(path) = args.value_of(key_names::SOURCE) {
			// Storing the path of the archive for reporting purposes
			archive_path = path;
			dbg!(archive_path);

			let archive_file = File::open(PathBuf::from(path))?;
			archive = Some(Archive::from_handle(archive_file)?);
		};

		if let Some(arch) = &mut archive {
			let arch_pointer = arch as *mut Archive<File>;

			for (id, _) in arch.entries().iter() {
				// This safe archive.fetch does not interact with &archive.entries mutably, therefore can not cause "pulling the rug from beneath your feet" problems
				unsafe {
					inputs.push(InputSource::VachResource(
						(*arch_pointer).fetch(id)?,
						id.clone(),
					))
				}
			}
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

		let pbar = ProgressBar::new(inputs.len() as u64 + 5 + if truncate { 3 } else { 0 });
		pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

		// Build a builder-config using the above extracted data
		let builder_config = BuilderConfig {
			flags,
			magic,
			keypair: kp,
			..Default::default()
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
		for entry in &inputs {
			match entry {
				InputSource::VachResource(res, id) => {
					builder.add(res.data.as_slice(), id)?;
					pbar.println(format!("Packaging entry from archive: {} @ {}", id, archive_path));
				}
				InputSource::PathBuf(path) => {
					if !path.exists() {
						pbar.println(format!(
							"Skipping {}, does not exist!",
							path.to_string_lossy()
						));

						pbar.inc(1);

						continue;
					}

					let id = match path.to_str() {
						Some(name) => name.trim_start_matches("./").to_string(),
						None => "".to_string(),
					};

					pbar.println(format!("Packaging {}", id));

					match File::open(&path) {
						Ok(file) => {
							if let Err(e) = builder.add(file, &id) {
								pbar.println(format!(
									"Couldn't add file: {}. {}",
									path.to_string_lossy(),
									e
								))
							}
						}
						Err(e) => pbar.println(format!(
							"Couldn't open file {}: {}",
							path.to_string_lossy(),
							e
						)),
					}
				}
			}

			pbar.inc(1);
		}

		// Inform of success in input queue
		pbar.inc(2);

		// Dumping processed data
		pbar.println(format!("Generated a new archive @ {}", output_path));
		builder.dump(output_file, &builder_config)?;

		// Truncate original files
		if truncate {
			for entry in &inputs {
				if let InputSource::PathBuf(buf) = entry {
					std::fs::remove_file(&buf)?;

					pbar.println(format!(
						"Truncated original file @ {}",
						buf.to_string_lossy()
					));
				}
			}

			pbar.inc(3);
		};

		pbar.inc(3);

		// SUCCESS
		pbar.finish_and_clear();

		Ok(())
	}

	fn version(&self) -> &'static str {
		"0.0.1"
	}
}

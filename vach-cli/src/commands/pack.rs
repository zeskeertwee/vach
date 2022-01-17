use std::fs::OpenOptions;
use std::{fs::File, io::Write};
use std::path::PathBuf;
use std::convert::TryInto;
use std::collections::HashSet;

use vach::prelude::*;
use vach::utils;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir;

use super::CommandTrait;
use crate::keys::key_names;

enum InputSource<'a> {
	PathBuf(PathBuf),
	VachResource(Resource, &'a str),
}

impl<'a> From<PathBuf> for InputSource<'a> {
	fn from(pb: PathBuf) -> InputSource<'a> {
		InputSource::PathBuf(pb)
	}
}

pub const VERSION: &str = "0.0.5";
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
				}
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
							println!(
								"Failed to evaluate: {}. Skipping due to error: {}",
								path.to_string_lossy(),
								err
							);
							None
						}
					}
				})
				.filter(|v| v.is_file())
				.collect::<HashSet<PathBuf>>(),
			None => HashSet::new(),
		};

		// Extract the inputs
		let mut inputs: Vec<InputSource> = vec![];

		// Used to filter invalid inputs and excluded inputs
		let path_filter = |path: &PathBuf| match path.canonicalize() {
			Ok(canonical) => !excludes.contains(&canonical) && canonical.is_file(),
			Err(err) => {
				println!(
					"Failed to evaluate: {}. Skipping due to error: {}",
					path.to_string_lossy(),
					err
				);
				false
			}
		};

		if let Some(val) = args.values_of(key_names::INPUT) {
			val.map(PathBuf::from)
				.filter(|f| path_filter(f))
				.for_each(|p| inputs.push(InputSource::PathBuf(p)));
		};

		// Extract directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT) {
			val.for_each(|dir| {
				walkdir::WalkDir::new(dir)
					.max_depth(1)
					.into_iter()
					.map(|v| v.unwrap().into_path())
					.filter(|f| path_filter(f))
					.for_each(|p| inputs.push(InputSource::PathBuf(p)))
			});
		};

		// Extract recursive directory inputs
		if let Some(val) = args.values_of(key_names::DIR_INPUT_REC) {
			val.map(|dir| walkdir::WalkDir::new(dir).into_iter())
				.flatten()
				.map(|v| v.unwrap().into_path())
				.filter(|f| path_filter(f))
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
				unsafe { inputs.push(InputSource::VachResource((*arch_pointer).fetch(id)?, id)) }
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
				Some(utils::read_keypair(file)?.secret)
			}
			None => match args.value_of(key_names::SECRET_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(utils::read_secret_key(file)?)
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
			let generated = utils::gen_keypair();

			let mut file = File::create("keypair.kp")?;
			file.write_all(&generated.to_bytes())?;
			println!("Generated a new keypair @ keypair.kp");

			kp = Some(generated);
		}

		let pbar = ProgressBar::new(inputs.len() as u64 + 5 + if truncate { 3 } else { 0 });
		pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

		// Since it wraps it's internal state in an arc, we can safely clone and send across threads
		let callback = |msg: &str, _: &RegistryEntry| {
			pbar.inc(1);
			pbar.set_message(msg.to_string())
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
				.encrypt(encrypt)
				.sign(hash)
				.version(version),
		);

		// Prepare output file
		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an output path using the -o or --output key"),
		};

		let output_file;

		match OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(output_path)
		{
			Ok(file) => output_file = file,
			#[rustfmt::skip]
			Err(err) => anyhow::bail!( "Unable to generate archive @ {}: [IO::Error] {}", output_path, err ),
		};

		// Process the files
		for entry in &inputs {
			match entry {
				InputSource::VachResource(res, id) => {
					builder.add(res.data.as_slice(), id)?;

					let message =
						format!("Preparing entry from archive: {} @ {}", id, archive_path);
					pbar.println(message);
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

					let id = path
						.to_string_lossy()
						.trim_start_matches("./")
						.trim_start_matches(".\\")
						.to_string();
					pbar.println(format!("Preparing {} for packaging", id));

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
		}

		// Inform of success in input queue
		pbar.inc(2);

		builder.dump(output_file, &builder_config)?;
		pbar.println(format!("Generated a new archive @ {}", output_path));
		drop(builder);

		// Truncate original files
		if truncate {
			for entry in inputs {
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
}

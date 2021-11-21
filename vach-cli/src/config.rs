use std::path::PathBuf;
use clap::{App, Arg, ArgMatches, SubCommand};
use vach::crypto::{Keypair, PublicKey, SecretKey};
use anyhow::{Result, bail};
use lazy_static::lazy_static;
use vach::builder::CompressMode;
use log::info;
use crate::utils::read_file_from_value_name;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

mod key_names {
	// Paths to keypairs, public keys and secret keys to be used
    pub(crate) const PK_PATH: &str = "PUBLIC_KEY_PATH";
    pub(crate) const SK_PATH: &str = "SECRET_KEY_PATH";
    pub(crate) const KP_PATH: &str = "KEYPAIR_PATH";

    pub(crate) const KEY_FILE_OR_FOLDER_PATHS: &str = "FILE_OR_FOLDER_PATHS";

    pub(crate) const KEY_ARCHIVE_PATH: &str = "ARCHIVE_PATH";

    pub(crate) const KEY_KEYPAIR_FOLDER: &str = "KEYPAIR_FOLDER";

    pub(crate) const KEY_OPEN_SAVE_FOLDER: &str = "OPEN_FOLDER";

    pub(crate) const KEY_COMPRESS_MODE: &str = "COMPRESS_MODE";

    pub(crate) const KEY_ARCHIVE_SAVE_PATH: &str = "ARCHIVE_SAVE_PATH";

    pub(crate) const KEY_ENCRYPT: &str = "ENCRYPT";
}

trait SubcommandMatcher: Fn(&ArgMatches) -> Mode + Sync {}
impl<T> SubcommandMatcher for T where T: Fn(&ArgMatches) -> Mode + Sync {}

lazy_static! {
	static ref SUBCOMMANDS: [(&'static str, Box<dyn SubcommandMatcher>); 3] = [
		("package", Box::new(Mode::parse_package)),
		("open", Box::new(Mode::parse_open)),
		("generatekeys", Box::new(Mode::parse_generate_keys)),
	];
}

pub struct Config {
	pub public_key: Option<PublicKey>,
	pub secret_key: Option<SecretKey>,
	pub mode: Mode,
}

#[derive(Clone)]
pub enum Mode {
	Package {
		files: Vec<PathBuf>,
		save_path: PathBuf,
		compress_mode: CompressMode,
		encrypt: bool,
	},
	// this command lists the contents of an archive when save_path is None,
	// and extracts the contents to save_path when it contains a path
	Open {
		archive: PathBuf,           // guaranteed to be pointing to a valid file
		save_path: Option<PathBuf>, // guaranteed to be pointing to a valid folder
	},
	GenKeypair {
		save_folder: PathBuf, // guaranteed to be pointing to a valid folder
	},
	Error {
		msg: String,
	},
	None,
}

impl Config {
	pub fn from_args() -> Result<Self> {
		let version = format!("v{}, vach v{}", VERSION, vach::VERSION);

		let matches = App::new("vach-cli")
			.version(version.as_str())
			.author(AUTHORS)
			.about("A command-line interface for packing and packing with .vach files along with other vach archive related functionality")
			.arg(Arg::with_name(key_names::PK_PATH)
				.short("P")
				.long("public_key")
				.value_name("PUBLIC_KEY_PATH")
				.help("Sets the path to the public key to be used")
				.required(false)
				.takes_value(true))
			.arg(Arg::with_name(key_names::SK_PATH)
				.short("S")
				.long("secret_key")
				.value_name("SECRET_KEY_PATH")
				.help("Sets the path to the secret key to be used")
				.required(false)
				.takes_value(true)
			)
			.arg(Arg::with_name(key_names::KP_PATH)
				.short("K")
				.long("keypair")
				.help("Sets the path to the keypair to be used (if this and the secret_key or public_key are explicitly set, the one specified here will be used)")
				.required(false)
				.takes_value(true))
			.subcommand(SubCommand::with_name("package")
				.about("Package files into a vach archive")
				.version(version.as_str())
				.author(AUTHORS)
				.arg(Arg::with_name(key_names::KEY_COMPRESS_MODE)
					.short("C")
					.long("compress_mode")
					.value_name("COMPRESS_MODE")
					.help("Sets the compression mode to be used. Can be 'Always', 'Detect' or 'Never'. If none is set, it defaults to 'Detect'")
					.required(false)
					.multiple(false)
					.takes_value(true))
				.arg(Arg::with_name(key_names::KEY_ENCRYPT)
					.long("encrypt")
					.short("E")
					.value_name("BOOL")
					.help("Sets if encryption is enabled for the archive. Defaults to false")
					.required(false)
					.multiple(false)
					.takes_value(false))
				.arg(Arg::with_name(key_names::KEY_ARCHIVE_SAVE_PATH)
					.value_name("SAVE_PATH")
					.help("Where to save the generated archive")
					.required(true)
					.takes_value(true)
					.multiple(false))
				.arg(Arg::with_name(key_names::KEY_FILE_OR_FOLDER_PATHS)
					.value_name("FILE_OR_FOLDER_PATHS")
					.help("The files to package, or when passing a folder, all files in the folder are added, however, folders in the folder are ignored")
					.required(true)
					.multiple(true)
					.takes_value(true))
				)
			.subcommand(SubCommand::with_name("open")
				.about("Open an archive, and list or extract all files in it")
				.version(version.as_str())
				.author(AUTHORS)
				.arg(Arg::with_name(key_names::KEY_ARCHIVE_PATH)
					.value_name("ARCHIVE_PATH")
					.help("The path to the archive")
					.required(true)
					.takes_value(true))
				.arg(Arg::with_name(key_names::KEY_OPEN_SAVE_FOLDER)
					.value_name("SAVE_FOLDER")
					.help("If set, where to save the extracted files. Leave this empty to only list the contents of the archive")
					.required(false)
					.multiple(false)))
			.subcommand(SubCommand::with_name("generatekeys")
				.about("Generate a keypair (public & secret key)")
				.version(version.as_str())
				.author(AUTHORS)
				.arg(Arg::with_name(key_names::KEY_KEYPAIR_FOLDER)
					.value_name("SAVE_FOLDER")
					.help("The folder in which to store the public, secret and keypair files")
					.required(true)
					.takes_value(true)))
			.get_matches();

		let mut config = Config {
			public_key: None,
			secret_key: None,
			mode: Mode::None,
		};

		match read_file_from_value_name(&matches, key_names::KP_PATH) {
			Ok((data, path)) => match Keypair::from_bytes(&data) {
				Ok(keypair) => {
					config.public_key = Some(keypair.public);
					config.secret_key = Some(keypair.secret);
					info!("Using keypair in {}", path);
				}
				Err(e) => bail!("The keypair in {} is invalid: {}", path, e),
			},
			Err(_) => (),
		}

		// the only way this can not be None is if a keypair was specified, thus skip this if it's Some
		if config.public_key.is_none() {
			match read_file_from_value_name(&matches, key_names::PK_PATH) {
				Ok((data, path)) => match PublicKey::from_bytes(&data) {
					Ok(key) => {
						config.public_key = Some(key);
						info!("Using public key in {}", path);
					}
					Err(e) => bail!("The public key in {} is invalid: {}", path, e),
				},
				Err(_) => (),
			}

			match read_file_from_value_name(&matches, key_names::SK_PATH) {
				Ok((data, path)) => match SecretKey::from_bytes(&data) {
					Ok(key) => {
						config.secret_key = Some(key);
						info!("Using secret key in {}", path);
					}
					Err(e) => bail!("The secret key in {} is invalid: {}", path, e),
				},
				Err(_) => (),
			}
		}

		let (subcommand, matches) = matches.subcommand();

		for (cmd_name, parse_func) in SUBCOMMANDS.iter() {
			if *cmd_name == subcommand {
				// unwrapping is ok, because the subcommand exists
				config.mode = (parse_func)(&matches.unwrap())
			}
		}

		return Ok(config);
	}
}

impl Mode {
	fn parse_package(matches: &ArgMatches) -> Self {
		let mut compress_mode = CompressMode::Detect;
		if let Some(value) = matches.value_of(key_names::KEY_COMPRESS_MODE) {
			match value.to_lowercase().as_str() {
				"always" => compress_mode = CompressMode::Always,
				"detect" => compress_mode = CompressMode::Detect,
				"never" => compress_mode = CompressMode::Never,
				_ => {
					return Mode::Error {
						msg: format!("{} is an invalid value for COMPRESS_MODE", value),
					}
				}
			}
		}

		// unwrapping is ok, because the value is required, and we won't get here without it being set
		let paths = matches
			.values_of(key_names::KEY_FILE_OR_FOLDER_PATHS)
			.unwrap()
			.map(|v| PathBuf::from(v))
			.collect();

		let save_path: PathBuf = matches
			.value_of(key_names::KEY_ARCHIVE_SAVE_PATH)
			.unwrap()
			.into();

		let encrypt = matches.is_present(key_names::KEY_ENCRYPT);

		Self::Package {
			files: paths,
			compress_mode,
			save_path,
			encrypt,
		}
	}

	fn parse_open(matches: &ArgMatches) -> Self {
		// unwrapping is ok, because the value is required, and we won't get here without it being set
		let archive_path: PathBuf = matches.value_of(key_names::KEY_ARCHIVE_PATH).unwrap().into();

		if archive_path.is_dir() || !archive_path.exists() {
			return Self::Error {
				msg: format!(
					"{} is a folder or does not exist, expecting a file!",
					archive_path.to_string_lossy()
				),
			};
		}

		let mut save_path = None;

		if let Some(path) = matches.value_of(key_names::KEY_OPEN_SAVE_FOLDER) {
			let path: PathBuf = path.into();

			if path.is_file() || !path.exists() {
				return Self::Error {
					msg: format!(
						"{} is a file or does not exist, expecting a folder!",
						path.to_string_lossy()
					),
				};
			}

			save_path = Some(path);
		}

		Self::Open {
			archive: archive_path,
			save_path,
		}
	}

	fn parse_generate_keys(matches: &ArgMatches) -> Self {
		// unwrapping is ok, because the value is required, and we won't get here without it being set
		let save_folder: PathBuf = matches.value_of(key_names::KEY_KEYPAIR_FOLDER).unwrap().into();

		if save_folder.is_file() || !save_folder.exists() {
			return Self::Error {
				msg: format!(
					"{} is a file or does not exist, expecting a folder!",
					save_folder.to_string_lossy()
				),
			};
		}

		Self::GenKeypair { save_folder }
	}
}

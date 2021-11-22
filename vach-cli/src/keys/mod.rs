use clap::Arg;
use std::collections::HashMap;

pub mod key_names {
	pub(crate) const OUTPUT: &str = "OUTPUT";
	pub(crate) const INPUT: &str = "INPUT";
	pub(crate) const SOURCE: &str = "SOURCE";

	pub(crate) const DIR_INPUT: &str = "DIR_INPUT";
	pub(crate) const DIR_INPUT_REC: &str = "DIR_INPUT_REC";

	pub(crate) const EXCLUDE: &str = "EXCLUDE";
	pub(crate) const TRUNCATE: &str = "TRUNCATE";

	pub(crate) const FLAGS: &str = "FLAGS";
	pub(crate) const VERSION: &str = "VERSION";
	pub(crate) const MAGIC: &str = "MAGIC";
	pub(crate) const COMPRESS_MODE: &str = "COMPRESS_MODE";
	pub(crate) const HASH: &str = "HASH";
	pub(crate) const ENCRYPT: &str = "ENCRYPT";
	pub(crate) const SPLIT_KEY: &str = "SPLIT_KEY";

	pub(crate) const SECRET_KEY: &str = "SECRET_KEY";
	pub(crate) const PUBLIC_KEY: &str = "PUBLIC_KEY";
	pub(crate) const KEYPAIR: &str = "KEYPAIR";

	pub(crate) const QUIET: &str = "QUIET";
}

pub fn build_keys<'a>() -> HashMap<&'static str, Arg<'a, 'a>> {
	/* please only use this function once during the lifecycle of the program */
	let mut map = HashMap::new();

	/* The various keys usable in the CLI */
	// A general output target
	map.insert(
		key_names::OUTPUT,
		Arg::with_name(key_names::OUTPUT)
			.short("o")
			.long("output")
			.value_name(key_names::OUTPUT)
			.help("A general output target, for example a file to write to")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	// A general input source
	map.insert(
		key_names::INPUT,
		Arg::with_name(key_names::INPUT)
			.long("input")
			.short("i")
			.value_name(key_names::INPUT)
			.help("A general list of input sources, like paths to files")
			.required(false)
			.takes_value(true)
			.multiple(true),
	);

	// add all files in a directory into the input queue
	map.insert(
		key_names::DIR_INPUT,
		Arg::with_name(key_names::DIR_INPUT)
			.long("directory")
			.short("d")
			.value_name(key_names::DIR_INPUT)
			.help("Add all files in a directory into the input queue")
			.required(false)
			.takes_value(true)
			.multiple(true),
	);

	// same as above, only that it adds files from the directory recursively
	map.insert(
		key_names::DIR_INPUT_REC,
		Arg::with_name(key_names::DIR_INPUT_REC)
			.long("directory-r")
			.short("r")
			.value_name(key_names::DIR_INPUT_REC)
			.help("Recursively add all files in a directory into the input queue")
			.required(false)
			.takes_value(true)
			.multiple(true),
	);

	// exclude the given files from the write queue
	map.insert(
		key_names::EXCLUDE,
		Arg::with_name(key_names::EXCLUDE)
			.long("exclude")
			.short("x")
			.value_name(key_names::EXCLUDE)
			.help("Exclude the given paths from the input queue")
			.required(false)
			.takes_value(true)
			.multiple(true),
	);

	// Deletes the original files after they have been processed successfully
	map.insert(
		key_names::TRUNCATE,
		Arg::with_name(key_names::TRUNCATE)
			.short("t")
			.long("truncate")
			.value_name(key_names::TRUNCATE)
			.help("Exclude the given paths from the input queue")
			.required(false)
			.takes_value(false),
	);

	// treats the entries in a .vach file like regular files, but with metadata from the archive
	map.insert(
		key_names::SOURCE,
		Arg::with_name(key_names::SOURCE)
			.long("source")
			.short("z")
			.value_name(key_names::SOURCE)
			.help("Treats the entries in a .vach file like regular files and adds them to the input queue")
			.required(false)
			.takes_value(false)
			.number_of_values(1),
	);

	// treats the entries in a .vach file like regular files, but with metadata from the archive
	map.insert(
		key_names::MAGIC,
		Arg::with_name(key_names::MAGIC)
			.long("magic")
			.short("m")
			.value_name(key_names::MAGIC)
			.help("The magic used to generate the archive")
			.required(false)
			.takes_value(true)
			.number_of_values(1)
			.validator(|magic| {
				if magic.len() != vach::MAGIC_LENGTH {
					return Err(format!(
						"Please provide a magic of the right length: {}. Magic: {} has length: {}",
						vach::MAGIC_LENGTH,
						&magic,
						magic.len()
					));
				};

				Ok(())
			}),
	);

	// The compress mode of the adjacent leafs
	map.insert(
		key_names::COMPRESS_MODE,
		Arg::with_name(key_names::COMPRESS_MODE)
			.long("compress-mode")
			.short("c")
			.value_name(key_names::COMPRESS_MODE)
			.help("The compress mode of the adjacent leafs, Can be 'Always', 'Detect' or 'Never'. If none is set, it defaults to 'Detect'")
			.required(false)
			.takes_value(true)
			.number_of_values(1)
			.validator(|c_mode| {
				if c_mode != "always" && c_mode != "never" && c_mode != "detect" {
					return Err(format!("Please provide a valid Compress Mode, either \"always\", \"detect\" or \"never\". Not: {}", c_mode));
				};

				Ok(())
			}),
	);

	// To sign the entries and include the signatures in the target, an sk or kp must be provided
	map.insert(
		key_names::HASH,
		Arg::with_name(key_names::HASH)
			.short("h")
			.long("hash")
			.value_name(key_names::HASH)
			.help("To sign the entries and include the signatures in the target, an sk or kp must be provided")
			.required(false)
			.takes_value(false),
	);

	// Encrypt the data, an sk or kp must be provided
	map.insert(
		key_names::ENCRYPT,
		Arg::with_name(key_names::ENCRYPT)
			.short("e")
			.long("encrypt")
			.value_name(key_names::ENCRYPT)
			.help("Encrypt the data, an sk or kp must be provided")
			.required(false)
			.takes_value(false),
	);

	// Used in conjunction with the keypair subcommand to split the keypair upon generation into it's two parts
	map.insert(
		key_names::SPLIT_KEY,
		Arg::with_name(key_names::SPLIT_KEY)
			.short("s")
			.long("split")
			.value_name(key_names::SPLIT_KEY)
			.help("Used in conjunction with the keypair subcommand to split the keypair upon generation into it's two parts")
			.required(false)
			.takes_value(false),
	);

	// The secret key to be used in signing of signatures
	map.insert(
		key_names::SECRET_KEY,
		Arg::with_name(key_names::SECRET_KEY)
			.short("s")
			.long("secret-key")
			.value_name(key_names::SECRET_KEY)
			.help("The secret key to be used in signing of signatures")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	// The public key to be used in decryption and validation of signatures
	map.insert(
		key_names::PUBLIC_KEY,
		Arg::with_name(key_names::PUBLIC_KEY)
			.short("p")
			.long("public-key")
			.value_name(key_names::PUBLIC_KEY)
			.help("The public key to be used in decryption and validation of signatures")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	// A keypair is just a pair of the above two, but when set will be chosen over the above
	map.insert(
		key_names::KEYPAIR,
		Arg::with_name(key_names::KEYPAIR)
			.long("keypair")
			.short("k")
			.value_name(key_names::KEYPAIR)
			.help("A keypair is just a pair of the above two, but when set will be chosen over the above")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	// Tells the CLI to not log any messages to the console
	map.insert(
		key_names::QUIET,
		Arg::with_name(key_names::QUIET)
			.short("q")
			.long("quiet")
			.value_name(key_names::QUIET)
			.help("Tells the CLI to not log any messages to the console")
			.required(false)
			.takes_value(false),
	);

	// The flags that go into the .vach file header section
	map.insert(
		key_names::FLAGS,
		Arg::with_name("f")
			.long("flags")
			.short("f")
			.value_name(key_names::FLAGS)
			.help("The flags that go into the .vach file header section")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	// the version of the leafs being read or to be written
	map.insert(
		key_names::VERSION,
		Arg::with_name(key_names::VERSION)
			.long("version")
			.short("v")
			.value_name(key_names::VERSION)
			.help("the version of the leafs being read or to be written")
			.required(false)
			.takes_value(true)
			.number_of_values(1),
	);

	assert_eq!(map.len(), 18);

	map
}

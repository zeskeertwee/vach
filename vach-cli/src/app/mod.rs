use std::collections::HashMap;
use clap::{App, Arg};

use crate::keys::key_names;
use crate::commands;

const VERSION: &str = "VACH VERSION 20 LTS";
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

pub fn build_app<'a>(key_map: HashMap<&'static str, Arg<'a>>) -> App<'a> {
	App::new("vach-cli")
		.author(self::AUTHORS)
		.about("A command-line interface for unpacking and packing .vach (version 20) files")
		.version(self::VERSION)
		.subcommand(
			App::new("keypair")
				.author(AUTHORS)
				.version(commands::keypair::VERSION)
				.about("Generate a keypair (public & secret key)")
				.arg(key_map.get(key_names::OUTPUT).unwrap())
				.arg(key_map.get(key_names::SPLIT_KEY).unwrap()),
		)
		.subcommand(
			App::new("split")
				.author(AUTHORS)
				.version(commands::split::VERSION)
				.about("Splits a keypair into it's respective secret and public keys")
				.arg(key_map.get(key_names::INPUT).unwrap()),
		)
		.subcommand(
			App::new("verify")
				.author(AUTHORS)
				.version(commands::verify::VERSION)
				.about("Verifies the validity of a .vach file")
				.arg(key_map.get(key_names::MAGIC).unwrap())
				.arg(key_map.get(key_names::INPUT).unwrap()),
		)
		.subcommand(
			App::new("list")
				.author(AUTHORS)
				.version(commands::list::VERSION)
				.about("Lists all the entries in a .vach archive and their metadata")
				.arg(key_map.get(key_names::INPUT).unwrap())
				.arg(key_map.get(key_names::MAGIC).unwrap()),
		)
		.subcommand(
			App::new("unpack")
				.author(AUTHORS)
				.version(commands::unpack::VERSION)
				.about("Unpacks a .vach archive")
				.arg(key_map.get(key_names::OUTPUT).unwrap())
				.arg(key_map.get(key_names::INPUT).unwrap())
				.arg(key_map.get(key_names::KEYPAIR).unwrap())
				.arg(key_map.get(key_names::MAGIC).unwrap())
				.arg(key_map.get(key_names::PUBLIC_KEY).unwrap())
				.arg(key_map.get(key_names::TRUNCATE).unwrap()),
		)
		.subcommand(
			App::new("pack")
				.author(AUTHORS)
				.version(commands::pack::VERSION)
				.about("Packages all input files into a .vach archive")
				// Output file
				.arg(key_map.get(key_names::OUTPUT).unwrap())
				// Data sources
				.arg(key_map.get(key_names::INPUT).unwrap())
				.arg(key_map.get(key_names::DIR_INPUT).unwrap())
				.arg(key_map.get(key_names::DIR_INPUT_REC).unwrap())
				.arg(key_map.get(key_names::SOURCE).unwrap())
				.arg(key_map.get(key_names::EXCLUDE).unwrap())
				// Crypto shit
				.arg(key_map.get(key_names::KEYPAIR).unwrap())
				.arg(key_map.get(key_names::SECRET_KEY).unwrap())
				// Modifiers
				.arg(key_map.get(key_names::FLAGS).unwrap())
				.arg(key_map.get(key_names::COMPRESS_MODE).unwrap())
				.arg(key_map.get(key_names::MAGIC).unwrap())
				.arg(key_map.get(key_names::ENCRYPT).unwrap())
				.arg(key_map.get(key_names::HASH).unwrap())
				.arg(key_map.get(key_names::VERSION).unwrap())
				.arg(key_map.get(key_names::TRUNCATE).unwrap()),
		)
}

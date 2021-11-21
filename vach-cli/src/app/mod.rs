use std::collections::HashMap;
use clap::{App, Arg, SubCommand};

use crate::keys::key_names;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

pub fn build_app<'a>(key_map: HashMap<&'static str, Arg<'a, 'a>>) -> App<'a, 'a> {
	App::new("vach-cli")
	.author(AUTHORS)
	.about("A command-line interface for unpacking and packing .vach files")
	.subcommand(
		SubCommand::with_name("keypair")
		.author(AUTHORS)
		.about("Generate a keypair (public & secret key)")
		.arg(key_map.get(key_names::OUTPUT).unwrap())
		.arg(key_map.get(key_names::SPLIT_KEY).unwrap())
	)
	.subcommand(
		SubCommand::with_name("split")
		.author(AUTHORS)
		.about("Splits a keypair into it's respective secret and public keys")
		.arg(key_map.get(key_names::INPUT).unwrap())
	)
	.subcommand(
		SubCommand::with_name("verify")
		.author(AUTHORS)
		.about("Verifies the validity of a .vach file")
		.arg(key_map.get(key_names::MAGIC).unwrap())
		.arg(key_map.get(key_names::INPUT).unwrap())
	)
	.subcommand(
		SubCommand::with_name("list")
		.author(AUTHORS)
		.about("Lists all the entries in a .vach archive and their metadata")
		.arg(key_map.get(key_names::INPUT).unwrap())
		.arg(key_map.get(key_names::MAGIC).unwrap())
	)
	.subcommand(
		SubCommand::with_name("unpack")
		.author(AUTHORS)
		.about("Unpacks a .vach archive")
		.arg(key_map.get(key_names::OUTPUT).unwrap())
		.arg(key_map.get(key_names::INPUT).unwrap())
		.arg(key_map.get(key_names::KEYPAIR).unwrap())
		.arg(key_map.get(key_names::MAGIC).unwrap())
		.arg(key_map.get(key_names::PUBLIC_KEY).unwrap())
	)
	.subcommand(
		SubCommand::with_name("pack")
		.author(AUTHORS)
		.about("Packages all input files into a .vach archive")
		.arg(key_map.get(key_names::INPUT).unwrap())
		.arg(key_map.get(key_names::OUTPUT).unwrap())
		.arg(key_map.get(key_names::FLAGS).unwrap())
		.arg(key_map.get(key_names::KEYPAIR).unwrap())
		.arg(key_map.get(key_names::SECRET_KEY).unwrap())
		.arg(key_map.get(key_names::COMPRESS_MODE).unwrap())
		.arg(key_map.get(key_names::MAGIC).unwrap())
		.arg(key_map.get(key_names::DIR_INPUT).unwrap())
		.arg(key_map.get(key_names::DIR_INPUT_REC).unwrap())
		.arg(key_map.get(key_names::ENCRYPT).unwrap())
		.arg(key_map.get(key_names::HASH).unwrap())
		.arg(key_map.get(key_names::VERSION).unwrap())
		.arg(key_map.get(key_names::EXCLUDE).unwrap())
	)
}

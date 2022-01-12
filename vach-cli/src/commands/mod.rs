use std::collections::HashMap;

use clap::ArgMatches;
use anyhow::Result;

// A common progress bar style for all commands
const PROGRESS_BAR_STYLE: &str = "{wide_bar} {pos:>7}/{len:7} ETA {eta_precise}";

// Trait that must be implemented by all subcommands
pub trait CommandTrait: Sync {
	fn evaluate(&self, args: &ArgMatches) -> Result<()>;
}

// All sub-commands are defined in the below modules
pub mod keypair;
pub mod list;
pub mod pack;
pub mod split;
pub mod unpack;
pub mod verify;

pub fn build_commands() -> HashMap<&'static str, Box<dyn CommandTrait>> {
	let mut map: HashMap<&'static str, Box<dyn CommandTrait>> = HashMap::new();

	map.insert("keypair", Box::new(keypair::Evaluator));
	map.insert("split", Box::new(split::Evaluator));
	map.insert("verify", Box::new(verify::Evaluator));
	map.insert("list", Box::new(list::Evaluator));
	map.insert("unpack", Box::new(unpack::Evaluator));
	map.insert("pack", Box::new(pack::Evaluator));

	map
}

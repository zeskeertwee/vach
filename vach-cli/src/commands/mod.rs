use clap::ArgMatches;
use anyhow::Result;
use lazy_static::lazy_static;

// A common progress bar style for all commands
const PROGRESS_BAR_STYLE: &str = "{wide_bar} {pos:>7}/{len:7} ETA {eta_precise}";

// Trait that must be implemented by all subcommands
pub trait CommandTrait: Sync {
	 fn evaluate(&self, args: &ArgMatches) -> Result<()>;
	 fn version(&self) -> &'static str;
}

// All sub-commands are defined in the below modules
pub mod keypair;
pub mod unpack;
pub mod pack;
pub mod split;
pub mod list;
pub mod verify;

lazy_static! {
	pub static ref KEYPAIR_COMMAND: Box<dyn CommandTrait> = Box::new(keypair::Evaluator);
	pub static ref SPLIT_COMMAND: Box<dyn CommandTrait> = Box::new(split::Evaluator);
	pub static ref VERIFY_COMMAND: Box<dyn CommandTrait> = Box::new(verify::Evaluator);
	pub static ref LIST_COMMAND: Box<dyn CommandTrait> = Box::new(list::Evaluator);
	pub static ref UNPACK_COMMAND: Box<dyn CommandTrait> = Box::new(unpack::Evaluator);
	pub static ref PACK_COMMAND: Box<dyn CommandTrait> = Box::new(pack::Evaluator);
}

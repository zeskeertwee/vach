// A common progress bar style for all commands
const PROGRESS_BAR_STYLE: &str = "[{elapsed_precise}] {spinner} {bar:50.cyan/blue} {pos:>7}/{len:7} {msg}";

// Trait that must be implemented by all subcommands
pub trait CommandTrait: Sync {
	fn version() -> &'static str;
	fn evaluate(
		&self,
		cli: crate::cli::CommandLine,
	) -> anyhow::Result<()>;
}

// All sub-commands are defined in the below modules
pub mod keypair;
pub mod list;
pub mod pack;
pub mod pipe;
pub mod unpack;
pub mod verify;

use crate::commands::CommandTrait;
use clap::Parser;

// Fundamental modules
mod cli;
mod commands;
mod utils;

fn main() {
	let cli = cli::CommandLine::parse();

	match cli.command {
		cli::Command::Unpack { .. } => commands::unpack::Subcommand.evaluate(cli),
		cli::Command::Pipe { .. } => commands::pipe::Subcommand.evaluate(cli),
		cli::Command::List { .. } => commands::list::Subcommand.evaluate(cli),
		cli::Command::Verify { .. } => commands::verify::Subcommand.evaluate(cli),
		cli::Command::GenKeypair { .. } => commands::keypair::Subcommand.evaluate(cli),
		cli::Command::Pack { .. } => commands::pack::Subcommand.evaluate(cli),
	}
	.unwrap();
}

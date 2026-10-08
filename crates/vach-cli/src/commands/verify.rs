use std::fs::File;
use vach::archive::*;

use super::CommandTrait;
use crate::cli;

pub struct Subcommand;

impl CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.2"
	}

	fn evaluate(
		&self,
		cli: cli::CommandLine,
	) -> anyhow::Result<()> {
		let cli::Command::Verify { input } = cli.command else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let input_file = File::open(input)?;
		if let Err(err) = Archive::new(input_file) {
			match err {
				InternalError::MalformedArchiveSource(m) => anyhow::bail!("Invalid Magic Sequence: {:?}", m),
				InternalError::IncompatibleArchiveVersionError(v) => {
					anyhow::bail!("Incompatible Archive Version: {}, expected: {}", v, vach::VERSION)
				},
				InternalError::MissingFeatureError(f) => anyhow::bail!("CLI wasn't compiled with the feature: {}", f),
				e => anyhow::bail!("Unable to verify the archive source, error: {}", e),
			}
		};

		Ok(())
	}
}

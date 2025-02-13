use std::fs::File;
use vach::archive::*;

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.0.1";

/// This command verifies the validity and integrity of an archive
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		let input_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an input path using the -i or --input key"),
		};

		let input_file = File::open(input_path)?;
		if let Err(err) = Archive::new(input_file) {
			match err {
				InternalError::MalformedArchiveSource(m) => anyhow::bail!("Invalid Magic Sequence: {:?}", m),
				InternalError::IncompatibleArchiveVersionError(v) => {
					anyhow::bail!("Incompatible Archive Version: {}, expected: {}", v, vach::VERSION)
				},
				InternalError::MissingFeatureError(f) => anyhow::bail!("CLI wasn't compiled with the feature: {}", f),
				e => anyhow::bail!("Unable to verify the archive source, error: {}", e.to_string()),
			}
		};

		Ok(())
	}
}

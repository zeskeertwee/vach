use std::{
	fs::File,
	io::{self, BufReader, Write},
};
use vach::{crypto_utils, prelude::*};

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
		let cli::Command::Pipe { input, resource, keypair, public_key } = cli.command else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		// Attempting to extract a public key from a -p or -k input
		let verifying_key = match keypair {
			Some(path) => {
				let file = File::open(&path)?;

				Some(crypto_utils::read_keypair(file)?.verifying_key())
			},
			None => match public_key {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_verifying_key(file)?)
				},
				None => None,
			},
		};

		let input_file = match File::open(&input) {
			Ok(it) => BufReader::new(it),
			Err(err) => anyhow::bail!("IOError: {} @ {}", err, input.display()),
		};

		// load archive
		let archive = match verifying_key.as_ref() {
			Some(vk) => Archive::with_key(input_file, vk),
			None => Archive::new(input_file),
		};

		// Parse then extract archive
		let mut archive = match archive {
			Ok(archive) => archive,
			Err(err) => match err {
				InternalError::NoKeypairError => anyhow::bail!("Please provide a public key or a keypair for use in decryption or signature verification"),
				InternalError::MalformedArchiveSource(_) => anyhow::bail!("Unable to validate the archive: {}", err),
				err => anyhow::bail!("Encountered an error: {}", err),
			},
		};

		let mut handle = io::stdout().lock();
		let resource = archive.fetch_mut(resource)?;
		handle.write_all(&resource.data)?;

		drop(handle);

		Ok(())
	}
}

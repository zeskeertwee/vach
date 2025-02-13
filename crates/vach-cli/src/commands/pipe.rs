use std::{
	fs::File,
	io::{self, BufReader, Write},
};
use vach::{crypto_utils, prelude::*};

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.1.0";

pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		let input_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an input path using the -i or --input key"),
		};

		let resource = match args.value_of(key_names::RESOURCE) {
			Some(resource) => resource,
			None => anyhow::bail!("Please provide a resource to extract using the -r or --resource key"),
		};

		// Attempting to extract a public key from a -p or -k input
		let verifying_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = match File::open(path) {
					Ok(it) => it,
					Err(err) => anyhow::bail!("IOError: {} @ {}", err, path),
				};

				Some(crypto_utils::read_keypair(file)?.verifying_key())
			},
			None => match args.value_of(key_names::PUBLIC_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_verifying_key(file)?)
				},
				None => None,
			},
		};

		let input_file = match File::open(input_path) {
			Ok(it) => BufReader::new(it),
			Err(err) => anyhow::bail!("IOError: {} @ {}", err, input_path),
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
				InternalError::NoKeypairError => anyhow::bail!(
					"Please provide a public key or a keypair for use in decryption or signature verification"
				),
				InternalError::MalformedArchiveSource(_) => anyhow::bail!("Unable to validate the archive: {}", err),
				err => anyhow::bail!("Encountered an error: {}", err.to_string()),
			},
		};

		let stdout = io::stdout();
		{
			let mut handle = stdout.lock();
			let resource = archive.fetch_mut(resource)?;
			handle.write_all(&resource.data)?;
		}

		Ok(())
	}
}

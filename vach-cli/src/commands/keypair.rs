use anyhow::Result;
use vach::utils::gen_keypair;
use log::info;

use crate::utils;
use crate::keys::key_names;

use super::CommandTrait;

// Default keypair write destination
const KEYPAIR_FILE_NAME: &str = "keypair.kp";

/// This command is used to generate keypair
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> Result<()> {
		let mut output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => path.to_string(),
			None => {
				KEYPAIR_FILE_NAME.to_string()
			}
		};

		let to_split = args.is_present(key_names::SPLIT_KEY);
		let kp = gen_keypair();

		if to_split {
			output_path = output_path.trim_end_matches(".kp").to_string();

			let mut sk_path = output_path.clone();
			sk_path.push_str(".sk");

			let mut pk_path = output_path;
			pk_path.push_str(".pk");

			utils::create_and_write_to_file(&sk_path, &kp.secret.to_bytes())?;
			info!("Secret Key successfully generated and saved in: {}", sk_path);

			utils::create_and_write_to_file(&pk_path, &kp.public.to_bytes())?;
			info!("Public Key successfully generated and saved in: {}", pk_path);
		} else {
			utils::create_and_write_to_file(&output_path, &kp.to_bytes())?;
			info!("KeyPair successfully generated and saved in: {}", output_path);
		}

		Ok(())
	}

	fn version(&self) -> &'static str {
		"0.0.1"
	}
}

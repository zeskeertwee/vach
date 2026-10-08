use crate::{cli, utils};
use vach::crypto_utils::gen_keypair;

/// This command is used to generate keypair
pub struct Subcommand;

impl super::CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.2"
	}

	fn evaluate(
		&self,
		args: cli::CommandLine,
	) -> anyhow::Result<()> {
		let cli::Command::GenKeypair { output, split_key } = args.command else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let kp = gen_keypair();
		if split_key {
			let stem = output.trim_end_matches(".kp");

			let sk_path = format!("{}.sk", stem);
			let pk_path = format!("{}.pk", stem);

			utils::create_and_write_to_file(&sk_path, &kp.to_bytes())?;
			println!("Secret Key successfully generated and saved in: {}", sk_path);

			utils::create_and_write_to_file(&pk_path, &kp.verifying_key().to_bytes())?;
			println!("Public Key successfully generated and saved in: {}", pk_path);
		} else {
			utils::create_and_write_to_file(&output, &kp.to_keypair_bytes())?;
			println!("KeyPair successfully generated and saved in: {}", output);
		}

		Ok(())
	}
}

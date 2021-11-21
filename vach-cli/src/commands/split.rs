use std::fs::File;

use anyhow::{Result, bail};

use log::info;
use vach::utils::read_keypair;
use super::CommandTrait;
use crate::{keys::key_names, utils};

/// This command splits an existing valid keypair into it's public and secret key parts
pub struct Evaluator;

impl CommandTrait for Evaluator {
    fn evaluate(&self, args: &clap::ArgMatches) -> Result<()> {
        let mut input_path = match args.value_of(key_names::INPUT) {
            Some(path) => path.to_string(),
            None => bail!("Please provide a some input to a keypair files using the -i or --input key!"),
        };

        // Open and parse the keypair file
        let file = File::open(&input_path)?;
        let kp = read_keypair(file)?;

        // Format key paths
        input_path = input_path.trim_end_matches(".kp").to_string();

        let mut sk_path = input_path.clone();
        sk_path.push_str(".sk");

        let mut pk_path = input_path.clone();
        pk_path.push_str(".pk");

        // Write key parts
        utils::create_and_write_to_file(&pk_path, &kp.public.to_bytes())?;
        utils::create_and_write_to_file(&sk_path, &kp.secret.to_bytes())?;

        info!("Successfully split keypair: {} -> into {} and {}", input_path, pk_path, sk_path);

        Ok(())
    }

    fn version(&self) -> &'static str {
        "0.0.1"
    }
}

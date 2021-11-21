use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;
use anyhow::{Result, bail};
use clap::ArgMatches;

pub fn read_file_from_value_name(
	matches: &ArgMatches, value_name: &str,
) -> Result<(Vec<u8>, String)> {
	// Fetch the path from the ArgMatches dictionary
	let path = match matches.value_of(value_name) {
		Some(x) => x,
		None => bail!("no value specified for {}", value_name),
	};

	let mut file = File::open(path)?;
	let mut buf = Vec::new();

	file.read_to_end(&mut buf)?;

	Ok((buf, path.to_string()))
}

pub fn create_and_write_to_file(path: &str, data: &[u8]) -> Result<()> {
	let path = PathBuf::from_str(path)?;

	// Check if the file exists
	if path.exists() {
		bail!("The file {} already exists!", path.to_string_lossy());
	}

	let mut file = File::create(path)?;
	file.write_all(data)?;

	Ok(())
}

use std::path::PathBuf;
use anyhow::{Result, bail};
use vach::utils::gen_keypair;
use std::fs::File;
use std::io::Write;
use log::info;

const KEYPAIR_FILE_NAME: &str = "key.pair";
const PUBLIC_KEY_FILE_NAME: &str = "key.pub";
const SECRET_KEY_FILE_NAME: &str = "key.prv";

pub fn handle_keypair_command(save_folder: PathBuf) -> Result<()> {
	let keypair = gen_keypair();
	let pair_path = append_to_path(&save_folder, KEYPAIR_FILE_NAME);
	let public_path = append_to_path(&save_folder, PUBLIC_KEY_FILE_NAME);
	let secret_path = append_to_path(&save_folder, SECRET_KEY_FILE_NAME);

	create_and_write_to_file(&pair_path, &keypair.to_bytes())?;
	create_and_write_to_file(&public_path, &keypair.public.to_bytes())?;
	create_and_write_to_file(&secret_path, &keypair.secret.to_bytes())?;

	info!(
		"Keypair successfully generated and saved in {}",
		save_folder.to_string_lossy()
	);

	Ok(())
}

fn append_to_path(original: &PathBuf, append: &str) -> PathBuf {
	let mut copy = original.clone();
	copy.push(append);
	copy
}

fn create_and_write_to_file(path: &PathBuf, data: &[u8]) -> Result<()> {
	if path.exists() {
		bail!("The file {} already exists!", path.to_string_lossy());
	}

	let mut file = File::create(path)?;
	file.write_all(data)?;
	Ok(())
}

use std::fs::File;
use std::path::PathBuf;
use crate::config::Config;
use anyhow::Result;
use vach::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

pub fn handle_package_command(
	config: &mut Config, files: Vec<PathBuf>, save_path: PathBuf, compress_mode: CompressMode,
	encrypt: bool,
) -> Result<()> {
	// fail early
	let mut save_file = File::create(&save_path)?;

	let mut builder_config = BuilderConfig::default();
	// .take() is needed here (and thus a &mut reference is needed) because SecretKey doesn't implement Clone
	let (public_key, secret_key) = (config.public_key.take(), config.secret_key.take());
	match (public_key, secret_key) {
		(Some(pkey), Some(skey)) => {
			builder_config.keypair = Some(Keypair {
				public: pkey,
				secret: skey,
			});
		}
		_ => (),
	}

	let pbar = ProgressBar::new(files.len() as u64 + 1);
	pbar.set_style(ProgressStyle::default_bar().template(super::PROGRESS_BAR_STYLE));

	let mut builder =
		Builder::new().template(Leaf::default().compress(compress_mode).encrypt(encrypt));

	for entry in files {
		if !entry.exists() {
			pbar.println(format!(
				"Skipping {}, does not exist!",
				entry.to_string_lossy()
			));
			pbar.inc(1);
			continue;
		}

		if entry.is_file() {
			let id = match entry.file_name() {
				Some(name) => name.to_string_lossy().to_string(),
				None => "".to_string(),
			};
			pbar.println(format!("Packaging {}", id));

			match File::open(&entry) {
				Ok(file) => match builder.add(file, &id) {
					Ok(_) => (),
					Err(e) => pbar.println(format!(
						"Couldn't add file {}: {}",
						entry.to_string_lossy(),
						e
					)),
				},
				Err(e) => pbar.println(format!(
					"Couldn't add file {}: {}",
					entry.to_string_lossy(),
					e
				)),
			}
		} else if entry.is_dir() {
			pbar.println(format!("Packaging {} (directory)", entry.to_string_lossy()));
			match builder.add_dir(&entry.to_string_lossy(), None) {
				Ok(_) => (),
				Err(e) => pbar.println(format!(
					"Couldn't add folder {}: {}",
					entry.to_string_lossy(),
					e
				)),
			}
		}

		pbar.inc(1);
	}

	pbar.println(format!("Writing to {}", save_path.to_string_lossy()));
	builder.dump(&mut save_file, &builder_config)?;
	pbar.inc(1);
	pbar.finish_and_clear();

	Ok(())
}

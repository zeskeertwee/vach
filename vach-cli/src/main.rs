mod commands;
mod config;

use config::Mode;
use log::{error, Level};
use std::env;

fn main() {
	if let Err(_) = env::var("RUST_LOG") {
		// log level not explicitly set by the user
		env::set_var("RUST_LOG", "info");
	}
	pretty_env_logger::init();

	let mut config = match config::Config::from_args() {
		Ok(x) => x,
		Err(e) => {
			error!("An error occurred while parsing the command: {}", e);
			return;
		}
	};
	let config_mode = config.mode.clone();

	let res = match config_mode {
		Mode::None => {
			error!("No action specified!");
			return;
		}
		Mode::Error { msg } => {
			error!("An error occurred while parsing the command: {}", msg);
			return;
		}
		Mode::GenKeypair { save_folder } => commands::handle_keypair_command(save_folder),
		Mode::Open { archive, save_path } => {
			commands::handle_open_command(&config, archive, save_path)
		}
		Mode::Package {
			files,
			save_path,
			compress_mode,
			encrypt,
		} => commands::handle_package_command(&mut config, files, save_path, compress_mode, encrypt),
	};

	match res {
		Ok(_) => (),
		Err(e) => error!("An error occurred while executing the command: {}", e),
	}
}
